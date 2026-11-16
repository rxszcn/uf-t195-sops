package sops_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/internal/testenv"
	"github.com/getsops/sops/v3/stores/yaml"
)

// The age key pair below is test-only material, kept local to this file so the
// gate states exactly which key material it depends on. gateRecipient matches
// gateIdentity.
const (
	gateRecipient = "age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun"
	gateIdentity  = "AGE-SECRET-KEY-1G0Q5K9TV4REQ3ZSQRMTMG8NSWQGYT0T7TZ33RAZEE0GZYVZN0APSU24RK7"
)

// plainConfig is the plaintext tree the gate encrypts. The "value_plain" entry
// ends in the configured UnencryptedSuffix, so it stays readable while still
// being covered by the MAC.
const plainConfig = `secret: my-value
numbers:
    one: 1
list:
    - first
    - second
value_plain: visible
`

// gateMetadata is the metadata shared by the gate tests.
func gateMetadata() sops.Metadata {
	return sops.Metadata{
		UnencryptedSuffix: "_plain",
		Version:           "3.10.0",
	}
}

// newGateTree loads plainConfig into a tree whose key group holds one age
// master key. The recipient is set on the key, but no identity is injected yet:
// wrapping and unwrapping the data key is done explicitly by the tests.
func newGateTree(t *testing.T) sops.Tree {
	t.Helper()

	store := yaml.NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile([]byte(plainConfig))
	require.NoError(t, err)

	masterKey, err := age.MasterKeyFromRecipient(gateRecipient)
	require.NoError(t, err)

	tree := sops.Tree{
		Branches: branches,
		Metadata: gateMetadata(),
	}
	tree.Metadata.KeyGroups = []sops.KeyGroup{{masterKey}}
	return tree
}

// findValue returns the value stored under key in the tree's first branch.
func findValue(t *testing.T, tree sops.Tree, key string) interface{} {
	t.Helper()
	for _, item := range tree.Branches[0] {
		if item.Key == key {
			return item.Value
		}
	}
	t.Fatalf("key %q not found in tree", key)
	return nil
}

// setValue replaces the value stored under key in the tree's first branch.
func setValue(t *testing.T, tree *sops.Tree, key string, value interface{}) {
	t.Helper()
	for i, item := range tree.Branches[0] {
		if item.Key == key {
			tree.Branches[0][i].Value = value
			return
		}
	}
	t.Fatalf("key %q not found in tree", key)
}

// encryptAndStoreMAC encrypts tree with dataKey and stores the encrypted MAC in
// the metadata the same way the CLI does, returning the plaintext MAC.
func encryptAndStoreMAC(t *testing.T, tree *sops.Tree, dataKey []byte, cipher sops.Cipher) string {
	t.Helper()
	plainMAC, err := tree.Encrypt(dataKey, cipher)
	require.NoError(t, err)
	require.NotEmpty(t, plainMAC)

	tree.Metadata.LastModified = time.Unix(1700000000, 0).UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(
		plainMAC, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	require.NoError(t, err)
	return plainMAC
}

// TestEncryptionGate_KeyWrapRoundTrip covers the key-loading path without any
// ambient key material: the data key is wrapped with the age recipient and
// unwrapped by an identity that the test injects explicitly.
func TestEncryptionGate_KeyWrapRoundTrip(t *testing.T) {
	tree := newGateTree(t)
	dataKey := bytes.Repeat([]byte{0x2a}, 32)

	masterKey := tree.Metadata.KeyGroups[0][0]
	require.NoError(t, masterKey.Encrypt(dataKey))
	wrapped := masterKey.EncryptedDataKey()
	require.NotEmpty(t, wrapped)

	unwrapKey := &age.MasterKey{EncryptedKey: string(wrapped)}
	var ids age.ParsedIdentities
	require.NoError(t, ids.Import(gateIdentity))
	ids.ApplyToMasterKey(unwrapKey)

	got, err := unwrapKey.Decrypt()
	require.NoError(t, err)
	assert.Equal(t, dataKey, got, "the data key must unwrap with the supplied identity")
}

// TestEncryptionGate_EncryptDecryptMAC is a self-contained check of the parts of
// the encryption chain that guard a release: values are encrypted with the data
// key, the MAC covers the plaintext, and a decrypt recomputes exactly that MAC.
func TestEncryptionGate_EncryptDecryptMAC(t *testing.T) {
	cipher := aes.NewCipher()
	tree := newGateTree(t)
	dataKey := bytes.Repeat([]byte{0x2a}, 32)

	plainMAC := encryptAndStoreMAC(t, &tree, dataKey, cipher)

	// Values are encrypted by the SOPS cipher (AES-256-GCM); the age master key
	// only wraps the data key. Every value except the "_plain" one must be
	// ciphertext now.
	secret, ok := findValue(t, tree, "secret").(string)
	require.True(t, ok)
	assert.Contains(t, secret, "ENC[AES256_GCM,data:", "secret must be AES-GCM ciphertext")
	assert.Equal(t, "visible", findValue(t, tree, "value_plain"),
		"a value with the unencrypted suffix must be left in the clear")

	// Decrypt recomputes the MAC over the decrypted tree; it must match both
	// the MAC Encrypt returned and the MAC stored (encrypted) in the metadata.
	computedMAC, err := tree.Decrypt(dataKey, aes.NewCipher())
	require.NoError(t, err)
	assert.Equal(t, plainMAC, computedMAC,
		"MAC computed on decrypt must match the MAC computed on encrypt")

	storedMAC, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey,
		tree.Metadata.LastModified.Format(time.RFC3339))
	require.NoError(t, err)
	assert.Equal(t, plainMAC, storedMAC,
		"the MAC stored in the metadata must decrypt to the plaintext MAC")
}

// TestEncryptionGate_TamperDetection checks that the MAC gate actually bites:
// modifying a MAC'd value after encryption makes the recomputed MAC differ from
// the stored one, which the CLI reports as "MAC mismatch" and refuses to
// decrypt. Modifying ciphertext is caught earlier, by the AEAD itself.
func TestEncryptionGate_TamperDetection(t *testing.T) {
	t.Run("modified plaintext value", func(t *testing.T) {
		cipher := aes.NewCipher()
		tree := newGateTree(t)
		dataKey := bytes.Repeat([]byte{0x2a}, 32)

		plainMAC := encryptAndStoreMAC(t, &tree, dataKey, cipher)

		// The unencrypted value is readable but still part of the MAC, so
		// editing it must be detected.
		setValue(t, &tree, "value_plain", "tampered")

		computedMAC, err := tree.Decrypt(dataKey, aes.NewCipher())
		require.NoError(t, err)
		assert.NotEqual(t, plainMAC, computedMAC,
			"editing a MAC'd value must change the computed MAC")
	})

	t.Run("modified ciphertext", func(t *testing.T) {
		cipher := aes.NewCipher()
		tree := newGateTree(t)
		dataKey := bytes.Repeat([]byte{0x2a}, 32)

		encryptAndStoreMAC(t, &tree, dataKey, cipher)

		secret := findValue(t, tree, "secret").(string)
		body := []byte(secret)
		marker := bytes.Index(body, []byte("data:"))
		require.Greater(t, marker, -1)
		// Flip one byte of the base64 payload; AES-GCM authenticates it, so
		// the value must no longer decrypt.
		body[marker+len("data:")] ^= 0x01
		setValue(t, &tree, "secret", string(body))

		_, err := tree.Decrypt(dataKey, aes.NewCipher())
		assert.Error(t, err, "a modified ciphertext must not decrypt")
	})
}

// TestEncryptionGate_NoAmbientKeys pins the isolation itself. A master key with
// no injected identities has to fail with "failed to load age identities"; if
// the test process can see SSH keys or age keys from the host, the key loading
// succeeds (and then fails later with "incorrect identity for recipient block",
// because those keys do not match gateRecipient). Asserting on the specific
// error therefore fails whenever ambient key material leaks into the suite.
func TestEncryptionGate_NoAmbientKeys(t *testing.T) {
	wrapped := &age.MasterKey{Recipient: gateRecipient}
	require.NoError(t, wrapped.Encrypt(bytes.Repeat([]byte{0x2a}, 32)))

	key := &age.MasterKey{
		Recipient:    gateRecipient,
		EncryptedKey: string(wrapped.EncryptedDataKey()),
	}
	got, err := key.Decrypt()
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorContains(t, err, "failed to load age identities",
		"the test process must not find age identities on the host")
}

// TestMain isolates the root package's tests from host key material, so that
// TestEncryptionGate_NoAmbientKeys and the other tree tests behave the same on
// a developer machine and on a clean CI runner.
func TestMain(m *testing.M) {
	os.Exit(testenv.RunMain(m))
}
