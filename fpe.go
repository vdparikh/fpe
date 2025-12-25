// Package fpe implements Format-Preserving Encryption (FPE) using the FF1 algorithm.
// FF1 is a NIST-standardized format-preserving encryption algorithm (NIST SP 800-38G).
//
// This package provides a clean, provider-agnostic implementation of FF1 that can
// be used with any key management system. It preserves the format of input data
// (e.g., SSN format XXX-XX-XXXX, credit card numbers, email addresses) while
// encrypting the actual data characters.
//
// The package includes both standalone FF1 implementation and Tink-compatible
// primitives (see tink.go). While Tink doesn't natively support FPE, this package
// provides a Tink-compatible interface that follows Tink's design patterns and
// integrates seamlessly with Tink's key management system.
//
// Example usage:
//
//	key := []byte("your-encryption-key-32-bytes-long!")
//	tweak := []byte("tenant-1234|customer.ssn")
//
//	fpe, err := fpe.NewFF1(key, tweak)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Tokenize (encrypt) while preserving format
//	tokenized, err := fpe.Tokenize("123-45-6789")
//	if err != nil {
//		log.Fatal(err)
//	}
//	// tokenized might be "987-65-4321" (same format, different data)
//
//	// Detokenize (decrypt) to recover original
//	plaintext, err := fpe.Detokenize(tokenized, "123-45-6789", "")
//	if err != nil {
//		log.Fatal(err)
//	}
//	// plaintext will be "123-45-6789"
package fpe

import (
	"fmt"

	"github.com/vdparikh/fpe/subtle"
)

// FF1 implements Format-Preserving Encryption using the FF1 algorithm.
// FF1 is based on a Feistel network and preserves the format of input data.
// This is a high-level wrapper around the subtle.FF1 implementation.
type FF1 struct {
	ff1 *subtle.FF1
}

// NewFF1 creates a new FF1 FPE instance with the given key and tweak.
// The key should be at least 16 bytes (AES-128) or 32 bytes (AES-256).
// The tweak is a public, non-secret value that ensures different ciphertexts
// for the same plaintext when the tweak changes.
//
// This function creates a high-level wrapper around the subtle.FF1 implementation.
// For Tink integration, use tinkfpe.New() instead.
func NewFF1(key, tweak []byte) (*FF1, error) {
	ff1, err := subtle.NewFF1(key, tweak)
	if err != nil {
		return nil, err
	}
	return &FF1{ff1: ff1}, nil
}

// Tokenize encrypts plaintext using format-preserving encryption.
// It preserves format characters (hyphens, dots, colons, @ signs, etc.) and
// only encrypts the alphanumeric data characters.
//
// Returns the tokenized (encrypted) value that maintains the same format as the input.
func (f *FF1) Tokenize(plaintext string) (string, error) {
	// Step 1: Separate format characters (hyphens, dots, etc.) from data characters
	formatMask, dataChars := SeparateFormatAndData(plaintext)

	// Step 2: Determine the alphabet for data characters only
	alphabet := DetermineAlphabet(dataChars)
	if len(alphabet) == 0 {
		return "", fmt.Errorf("no valid alphabet found for plaintext")
	}

	// Step 3: Convert data characters to numeric representation
	dataNumeric := StringToNumeric(dataChars, alphabet)

	// Step 4: Use FF1 algorithm for format-preserving encryption
	tokenizedNumeric, err := f.ff1.Encrypt(dataNumeric, alphabet)
	if err != nil {
		return "", fmt.Errorf("failed to tokenize: %w", err)
	}

	// Step 5: Convert back to string and reconstruct with format
	tokenizedData := NumericToString(tokenizedNumeric, alphabet, len(dataChars))
	tokenized := ReconstructWithFormat(tokenizedData, formatMask, plaintext)

	return tokenized, nil
}

// Detokenize decrypts tokenized value using format-preserving encryption.
// The alphabet parameter should match what was used during tokenization.
// If empty, it will be determined from the tokenized data (may not match original).
//
// For best results, pass the alphabet determined from the original plaintext.
func (f *FF1) Detokenize(tokenized string, originalPlaintext string, alphabet string) (string, error) {
	// Step 1: Separate format characters from data characters
	formatMask, dataChars := SeparateFormatAndData(tokenized)

	// Step 2: Determine alphabet (prefer from original plaintext if provided)
	if alphabet == "" {
		if originalPlaintext != "" {
			_, originalDataChars := SeparateFormatAndData(originalPlaintext)
			alphabet = DetermineAlphabet(originalDataChars)
		} else {
			alphabet = DetermineAlphabet(dataChars)
		}
	}
	if len(alphabet) == 0 {
		return "", fmt.Errorf("no valid alphabet found")
	}

	// Step 3: Convert tokenized data to numeric representation
	tokenizedNumeric := StringToNumeric(dataChars, alphabet)

	// Step 4: Use FF1 algorithm for format-preserving decryption
	plaintextNumeric, err := f.ff1.Decrypt(tokenizedNumeric, alphabet)
	if err != nil {
		return "", fmt.Errorf("failed to detokenize: %w", err)
	}

	// Step 5: Convert back to string and reconstruct with format
	plaintextData := NumericToString(plaintextNumeric, alphabet, len(dataChars))
	plaintext := ReconstructWithFormat(plaintextData, formatMask, tokenized)

	return plaintext, nil
}
