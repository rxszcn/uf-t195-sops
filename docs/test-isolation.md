# Encryption chain test isolation

The release gate for this repository rests on SOPS's encryption and MAC
verification. Until now that gate had two weaknesses:

- the only machine check was the unit test suite, and
- the suite's result depended on the machine running it.

A developer whose `$HOME` contains `~/.ssh` keys saw `go test ./...` green; the
same commit on a clean runner was red. The failures pointed at the machine, not
at the code, so real regressions in key loading could survive until the
integration stage.

This document records what was changed and why.

## Root causes found

Running the suite on a Windows developer machine with `~/.ssh` keys, and in a
clean Linux container, produced three distinct classes of failure.

### Key material leaks in from the host

`age.loadAgeSSHIdentities` reads `os.UserHomeDir()/.ssh/id_ed25519` and
`id_rsa`, so `loadIdentities` picked up the developer's SSH keys. The
`no identities` and `parsing error` tests then saw an identity where they
expected none, and the passphrase tests reached the host's live gpg-agent
socket through `gopgagent.NewConn`.

This is the failure the task described: the host supplied key material the tests
did not ask for, which masked the real behaviour.

### Paths assumed to be POSIX

`config.TestLoadConfigFileWithAmbiguousPath` used the fixture `/foo/config`.
`parseCreationRuleForFile` makes the config directory absolute with
`filepath.Abs` (which is `D:\foo` on Windows) and then strips that prefix from
the file path, so the prefix never matched and the test failed.

`pgp/keysource.go` passed absolute paths to gpg. On Windows, GnuPG resolves
`--homedir C:\...` relative to the working directory and reports "directory
does not exist".

### Platform and credential differences

- `GnuPGHome.Validate` required mode `0700`, but Go reports `0777` for every
  directory on Windows and `os.Chmod` cannot change it. Every `GnuPGHome` test
  failed there.
- `pgp.TestPGP` used its own fingerprint but relied on `make test` having
  imported that key into the host keyring, so it failed with "No public key"
  wherever the import had not happened.
- `gcpkms.newKMSClient` falls back to the ambient Google credential chain, so
  `GOOGLE_APPLICATION_CREDENTIALS` and friends decided whether the credential
  tests passed.
- `kms` and `hcvault` called `logger.Fatalf` in `TestMain` when Docker was
  absent, which killed the test binary instead of skipping the tests that need
  a backend.

## What changed

### An explicit test environment (`internal/testenv`)

`internal/testenv` creates a throw-away directory tree and points every place
SOPS discovers key material or credentials at it:

- `HOME` / `USERPROFILE` (SSH keys, `~/.gnupg`, `~/.vault-token`),
- `XDG_CONFIG_HOME` / `APPDATA` / `LOCALAPPDATA` (age `keys.txt`),
- `GNUPGHOME`,

and it unsets `SOPS_AGE_*`, `SOPS_GPG_EXEC`, and the AWS, Google Cloud, Vault,
Azure and HuaweiCloud credential variables.

It also sets `GPG_AGENT_INFO` to the empty string rather than unsetting it. The
`gopgagent` package treats a set-but-empty value as "no agent", while an unset
value makes it look for the socket in the invoking user's home directory, which
is the exact host dependency being removed.

`testenv.RunMain(m)` is the whole body of a `TestMain`:

```go
func TestMain(m *testing.M) { os.Exit(testenv.RunMain(m)) }
```

It is installed in `age`, `pgp`, `gcpkms` and the root `sops_test` package.
Those are the packages that decrypt, load keys, or exercise a credential chain.

### Tests supply their own key material

- `age`: `overwriteUserConfigDir` now also sets `USERPROFILE` on Windows
  (`os.UserHomeDir` reads it there and ignores `HOME`). Previously the tests
  wrote `id_25519` into the developer's real `~/.ssh`, which is both a leak and
  a source of cross-test pollution.
- `pgp/TestPGP` now drives the round trip from `testdata/ring/pubring.gpg` and
  `secring.gpg` instead of the host keyring.
- `encryption_gate_test.go` declares its own age key pair and injects the
  identity with `ParsedIdentities.ApplyToMasterKey`; its happy path never calls
  `loadIdentities`.

### Real code fixes, not only test changes

Two defects were found where the tests were right and the code was wrong:

- `GnuPGHome.Validate` skips the `0700` check on Windows, where the permission
  bits do not exist and the check made every GnuPG home unusable.
- `gpgExec` runs gpg with the home directory as its working directory and passes
  `--homedir .` on Windows, where GnuPG does not accept a Windows absolute path.

Both are platform bugs that only surfaced because the tests now run on Windows
as well as Linux.

Two further test expectations were made platform-aware rather than changed in
behaviour: the "missing gpg binary" error text differs between Go's Unix and
Windows exec implementations, and the "wrong permissions" case cannot exist on
Windows, so it skips there with a stated reason.

### External backends skip explicitly

`kms` and `hcvault` now record why the backend is unavailable in
`testDockerUnavailable`, and each test that needs it calls
`skipWithoutDocker(t)`, which prints:

```
skipping: AWS KMS test backend unavailable: cannot reach the Docker daemon: ...
```

The remaining tests in those packages still run. The Docker probe uses a 5
second context instead of `pool.Retry`'s default minute, so a missing daemon
costs seconds, not a minute per package.

### The gate itself

`encryption_gate_test.go` adds four checks on the encryption chain that do not
depend on the host:

- **key wrap round trip**: the age recipient wraps the data key, and an
  explicitly injected identity unwraps it.
- **encrypt/decrypt MAC**: `Encrypt` returns a MAC over the plaintext, the CLI
  path stores it encrypted under the data key, and `Decrypt` recomputes exactly
  that MAC. The test also asserts AES-GCM ciphertext and that a value with the
  unencrypted suffix stays in the clear.
- **tamper detection**: editing a MAC'd value after encryption changes the
  computed MAC, and flipping a byte of ciphertext makes decryption fail.
- **no ambient keys**: a master key with no injected identity must fail with
  `failed to load age identities`. If the host leaks SSH keys or age keys into
  the process, key loading succeeds and the error changes to
  `incorrect identity for recipient block`, so the assertion fails.

The last one is the isolation self-check. It was verified two ways: it passes
with `SOPS_AGE_KEY` set in the environment, because `TestMain` clears it, and it
fails when `testenv.Apply` is neutered, so the check has teeth.

## Pipeline

`.github/workflows/cli.yml` gains a `crypto` job with a two-element matrix:

- `clean` runs `make crypto-test`, which unsets key material and credentials.
- `poisoned` runs `make crypto-test-poisoned`, which sets `SOPS_AGE_*` and bogus
  Google Cloud, Vault and AWS credentials.

Both run the crypto packages with `-race` and the Makefile's `GO_TEST_FLAGS`.
Both must pass. The `check` job now depends on `crypto`, so branch protection
can keep requiring only `check`.

The existing `build` job still runs `make test` (the full suite) unchanged, so
no existing coverage was removed. `build` covers `linux`, `darwin` and
`windows`, so the Windows path fixes in `pgp` are exercised.

## Verification performed

On Windows 11 (Go 1.27.4) and in `golang:1.27` Linux containers:

- full suite `go test ./...`: 21 packages, all green, both with the developer's
  `~/.ssh` present (the poisoned host) and with an empty `HOME` (the clean
  host);
- `make crypto-test` and `make crypto-test-poisoned` on Linux with `-race`:
  all crypto packages green;
- `kms` and `hcvault` with Docker up: the backend tests actually run and pass,
  so the skip path was not bought by weakening coverage;
- the `TestEncryptionGate_NoAmbientKeys` self-check fails when the sandbox is
  removed, confirming the gate detects host leakage;
- a deliberate mutation that drops a value from the decrypt-side MAC makes
  `TestEncryptionGate_EncryptDecryptMAC` fail, confirming the MAC gate detects
  encryption-semantic regressions.

## Trade-offs and decisions

- **`TestMain` per package rather than per test.** The environment has to be in
  place before the first test loads a key. Per-test `t.Setenv` already covered
  the variables a test sets, but not implicit lookups such as
  `os.UserHomeDir` inside `loadIdentities`.
- **Isolation in a shared internal package.** Nine packages need the same list
  of ambient variables, and a list duplicated nine times drifts. The cost is
  that `internal/testenv` repeats the `SOPS_*` constants as literals instead of
  importing the packages under test: importing them would invert the
  dependency, and a typo in a name would silently weaken the isolation. The
  names are grouped by the code that reads them.
- **`GPG_AGENT_INFO=""` rather than `unset`.** Unsetting made `gopgagent` fall
  back to the home-directory socket. Empty is the documented "no agent" value.
- **Skip, do not fail, on a missing external backend.** A missing Docker daemon
  is not a regression in the encryption chain, and failing the package hid the
  tests that do not need it. The skip message names the backend and the reason,
  and the `crypto` gate runs on GitHub's `ubuntu-latest` runners, which have
  Docker, so the backend tests are not skipped there.
- **Two environments, not one.** A clean environment proves the tests do not
  need host keys; a poisoned one proves they do not trust host keys. Either
  alone leaves a hole.
- **The `crypto` job runs only on `ubuntu-latest`.** That is the runner that has
  Docker for the backend tests, and `-race` needs cgo. Cross-platform coverage
  stays in the `build` job, which still runs the full suite on Linux, macOS and
  Windows.

## Not changed

`make test` still imports `pgp/sops_functional_tests_key.asc` into the host
keyring and still unsets the `SOPS_AGE_*` variables. That is kept because the
functional (Rust) tests and other unmodified packages depend on it, and the
existing tests must keep passing. The new `crypto` gate runs the same packages
with the process environment isolated regardless, so the gate does not depend on
that import.
