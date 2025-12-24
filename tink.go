// Package fpe implements Format-Preserving Encryption (FPE) using the FF1 algorithm.
// This file provides Tink-compatible primitives for FPE operations.

package fpe

import (
	"fmt"
)

// FPE is a Tink-compatible interface for Format-Preserving Encryption operations.
// This follows Tink's primitive pattern, similar to tink.AEAD.
type FPE interface {
	// Tokenize encrypts plaintext using format-preserving encryption.
	// Returns the tokenized (encrypted) value that preserves the format of the input.
	Tokenize(plaintext string) (string, error)

	// Detokenize decrypts tokenized value using format-preserving encryption.
	// The originalPlaintext parameter is used for alphabet detection to ensure consistency.
	Detokenize(tokenized string, originalPlaintext string) (string, error)
}

// TinkFPE implements the FPE interface using Tink's key management patterns.
// This allows FPE to work seamlessly with Tink's KMS clients and key management.
type TinkFPE struct {
	ff1 *FF1
}

// NewTinkFPE creates a new Tink-compatible FPE primitive from a Tink key.
// The key should be obtained from a Tink KMS client or key manager.
func NewTinkFPE(key []byte, tweak []byte) (FPE, error) {
	ff1, err := NewFF1(key, tweak)
	if err != nil {
		return nil, fmt.Errorf("failed to create FF1 instance: %w", err)
	}

	return &TinkFPE{
		ff1: ff1,
	}, nil
}

// Tokenize encrypts plaintext using format-preserving encryption.
func (t *TinkFPE) Tokenize(plaintext string) (string, error) {
	return t.ff1.Tokenize(plaintext)
}

// Detokenize decrypts tokenized value using format-preserving encryption.
func (t *TinkFPE) Detokenize(tokenized string, originalPlaintext string) (string, error) {
	return t.ff1.Detokenize(tokenized, originalPlaintext, "")
}

// Verify that TinkFPE implements the FPE interface
var _ FPE = (*TinkFPE)(nil)

// KMSClientFPE is a Tink KMS client that provides FPE primitives.
// This follows the same pattern as tink.KMSClient but for FPE operations.
type KMSClientFPE interface {
	// GetFPE returns an FPE primitive for the given key URI.
	// The URI format is provider-specific (e.g., "omnikey-turing://<key-id>").
	GetFPE(uri string, tweak []byte) (FPE, error)
}

// Verify that KMSClientFPE follows Tink patterns
// Note: This is a custom interface, not part of Tink's core, but follows Tink's design patterns.
