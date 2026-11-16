// Package testenv provides a throw-away process environment for tests that
// would otherwise load key material or credentials from the machine they run
// on.
//
// Several parts of SOPS discover key material implicitly:
//
//   - github.com/getsops/sops/v3/age reads SSH identities from
//     os.UserHomeDir()/.ssh and age keys from os.UserConfigDir()/sops/age,
//   - the PGP code path shells out to gpg, which reads GNUPGHOME and may talk
//     to a running gpg-agent,
//   - the AWS, Google Cloud and Vault integrations fall back to the ambient
//     credential chains of the host.
//
// A test that exercises any of those paths therefore behaves differently on a
// laptop with SSH keys than on a clean CI runner. That drift hides real
// regressions: a broken key-loading path can look green locally only because
// the host happens to supply a matching key.
//
// A Sandbox points every one of those sources at an empty temporary directory
// and unsets the environment variables that can leak outside of it. Tests must
// then supply the key material they need explicitly, which is also what makes
// the outcome independent of the host.
package testenv

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Sandbox is an isolated directory tree to point the process environment at.
// Obtain one with New; the zero value is not usable.
type Sandbox struct {
	// Root is the sandbox root; every other directory lives inside it.
	Root string
	// Home is the sandbox home directory, used for os.UserHomeDir() and for
	// the conventional ~/.ssh and ~/.gnupg lookups.
	Home string
	// ConfigDir is the sandbox user configuration directory, used for
	// os.UserConfigDir() (and for XDG_CONFIG_HOME).
	ConfigDir string
	// GnuPGHome is the sandbox GnuPG home directory.
	GnuPGHome string
}

// ambientVars lists environment variables that can point key loading or
// credential discovery outside the sandbox. Apply unsets all of them before
// pointing the remaining ones at the sandbox.
//
// The SOPS_* names mirror constants in the packages under test. They are
// repeated here as literals on purpose: internal/testenv must not depend on the
// packages it isolates, and a typo in a variable name would silently weaken the
// isolation, so each name is spelled out and grouped by the code that reads it.
var ambientVars = []string{
	// age identities and SSH keys (age/keysource.go).
	"SOPS_AGE_KEY",
	"SOPS_AGE_KEY_FILE",
	"SOPS_AGE_KEY_CMD",
	"SOPS_AGE_RECIPIENT",
	"SOPS_AGE_SSH_PRIVATE_KEY_FILE",
	"SOPS_AGE_SSH_PRIVATE_KEY_CMD",
	// GnuPG binary override and agent discovery (pgp/keysource.go, age).
	"SOPS_GPG_EXEC",
	"GPG_AGENT_INFO",
	"SSH_AUTH_SOCK",
	"XDG_RUNTIME_DIR",
	// AWS credential chain (kms/keysource.go).
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_PROFILE",
	"AWS_DEFAULT_PROFILE",
	"AWS_SHARED_CREDENTIALS_FILE",
	"AWS_CONFIG_FILE",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"AWS_ROLE_ARN",
	// Google Cloud credential chain (gcpkms/keysource.go).
	"GOOGLE_CREDENTIALS",
	"GOOGLE_OAUTH_ACCESS_TOKEN",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"CLOUDSDK_CONFIG",
	// HashiCorp Vault (hcvault/keysource.go).
	"VAULT_TOKEN",
	"VAULT_ADDR",
	"VAULT_CACERT",
	"VAULT_CAPATH",
	"VAULT_CLIENT_CERT",
	"VAULT_CLIENT_KEY",
	"VAULT_CLIENT_CERT_FILE",
	"VAULT_CLIENT_KEY_FILE",
	"VAULT_NAMESPACE",
	"VAULT_SKIP_VERIFY",
	"VAULT_TLS_SERVER_NAME",
	"SOPS_HC_VAULT_ALLOWLIST",
	// Azure Key Vault integration tests.
	"AZURE_TENANT_ID",
	"AZURE_CLIENT_ID",
	"AZURE_CLIENT_SECRET",
	"AZURE_SUBSCRIPTION_ID",
	// HuaweiCloud KMS.
	"HUAWEICLOUD_SDK_AK",
	"HUAWEICLOUD_SDK_SK",
}

// New creates a sandbox in a fresh temporary directory. The caller is
// responsible for calling Cleanup.
func New() (*Sandbox, error) {
	root, err := os.MkdirTemp("", "sops-testenv-")
	if err != nil {
		return nil, fmt.Errorf("testenv: cannot create sandbox root: %w", err)
	}
	s := &Sandbox{
		Root:      root,
		Home:      filepath.Join(root, "home"),
		ConfigDir: filepath.Join(root, "config"),
		GnuPGHome: filepath.Join(root, "gnupg"),
	}
	for _, dir := range []string{s.Home, s.ConfigDir, s.GnuPGHome} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			_ = os.RemoveAll(root)
			return nil, fmt.Errorf("testenv: cannot create %s: %w", dir, err)
		}
		// os.MkdirTemp creates 0700 directories on Unix, but be explicit:
		// some tests (and GnuPGHome.Validate) care about the mode.
		if err := os.Chmod(dir, 0o700); err != nil {
			_ = os.RemoveAll(root)
			return nil, fmt.Errorf("testenv: cannot restrict %s: %w", dir, err)
		}
	}
	return s, nil
}

// Cleanup removes the sandbox directory tree.
func (s *Sandbox) Cleanup() error {
	if s == nil || s.Root == "" {
		return nil
	}
	return os.RemoveAll(s.Root)
}

// Apply points the process environment at the sandbox and removes ambient key
// material and credentials. It is intended to be called once, from a package's
// TestMain, before any test runs. Individual tests may still override the
// environment (for example with t.Setenv) to supply the key material they
// exercise.
//
// Apply sets GPG_AGENT_INFO to the empty string rather than unsetting it: the
// gopgagent package treats a set-but-empty value as "there is no agent", while
// an unset value makes it look for the socket in the invoking user's home
// directory, which is exactly the host dependency this package removes.
func (s *Sandbox) Apply() error {
	if s == nil {
		return nil
	}
	for _, name := range ambientVars {
		if err := os.Unsetenv(name); err != nil {
			return fmt.Errorf("testenv: cannot unset %s: %w", name, err)
		}
	}

	vars := map[string]string{
		"HOME":            s.Home,
		"XDG_CONFIG_HOME": s.ConfigDir,
		"GNUPGHOME":       s.GnuPGHome,
		"GPG_AGENT_INFO":  "",
	}
	if runtime.GOOS == "windows" {
		// os.UserHomeDir reads USERPROFILE on Windows; HOME is ignored.
		vars["USERPROFILE"] = s.Home
		// os.UserConfigDir reads %AppData% on Windows.
		vars["APPDATA"] = s.ConfigDir
		vars["LOCALAPPDATA"] = s.ConfigDir
	}
	for name, value := range vars {
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("testenv: cannot set %s: %w", name, err)
		}
	}
	return nil
}

// RunMain creates a sandbox, applies it and runs the package's tests inside it.
// It is meant to be used as the whole body of a TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(testenv.RunMain(m)) }
//
// The sandbox is removed before RunMain returns.
func RunMain(m *testing.M) int {
	s, err := New()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() {
		if err := s.Cleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "testenv: cannot clean up sandbox: %v\n", err)
		}
	}()
	if err := s.Apply(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return m.Run()
}
