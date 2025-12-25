// Package fpe implements Format-Preserving Encryption (FPE) using the FF1 algorithm.
// This file defines the FPE interface for Tink integration.
// For Tink integration, see the tinkfpe package.

package fpe

// FPE is a Tink-compatible interface for Format-Preserving Encryption operations.
// This follows Tink's primitive pattern, similar to tink.DeterministicAEAD.
// FPE is deterministic: same plaintext + tweak + key = same ciphertext.
type FPE interface {
	// Tokenize encrypts plaintext using format-preserving encryption.
	// Returns the tokenized (encrypted) value that preserves the format of the input.
	// This is deterministic: same input always produces same output.
	Tokenize(plaintext string) (string, error)

	// Detokenize decrypts tokenized value using format-preserving encryption.
	// The originalPlaintext parameter is used for alphabet detection to ensure consistency.
	// This is the inverse of Tokenize.
	Detokenize(tokenized string, originalPlaintext string) (string, error)
}
