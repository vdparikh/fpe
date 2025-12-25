// Package tinkfpe provides Tink integration for Format-Preserving Encryption.
// This file contains the factory function for creating FPE primitives from Tink keyset handles.
package tinkfpe

import (
	"fmt"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/vdparikh/fpe"
	"github.com/vdparikh/fpe/subtle"
)

// New creates a new FPE primitive from a Tink keyset handle.
// This is the main entry point for users following Tink's pattern.
//
// Example:
//
//	handle, err := keyset.NewHandle(fpeKeyTemplate)
//	if err != nil {
//	    return err
//	}
//	primitive, err := tinkfpe.New(handle, []byte("tweak"))
//	if err != nil {
//	    return err
//	}
//	tokenized, err := primitive.Tokenize("123-45-6789")
func New(handle *keyset.Handle, tweak []byte) (fpe.FPE, error) {
	if handle == nil {
		return nil, fmt.Errorf("keyset handle cannot be nil")
	}

	// Extract the primary key from the keyset using Tink's Primitives API
	primitives, err := handle.Primitives()
	if err != nil {
		return nil, fmt.Errorf("failed to get primitives from handle: %w", err)
	}

	// Get the primary entry (which contains the key)
	primary := primitives.Primary
	if primary == nil {
		return nil, fmt.Errorf("no primary key found in keyset")
	}

	// Extract key material using the key ID from the primary entry
	keyID := primary.KeyID
	if keyID == 0 {
		return nil, fmt.Errorf("invalid key ID in primary entry")
	}

	// Extract the keyset using insecurecleartextkeyset (for unencrypted keysets)
	// This works for keysets created with insecurecleartextkeyset
	ks := insecurecleartextkeyset.KeysetMaterial(handle)

	// Find the key with matching ID
	var keyBytes []byte
	for _, key := range ks.Key {
		if key.KeyId == keyID {
			keyData := key.KeyData
			if keyData == nil {
				continue
			}

			// Handle encrypted keys via KMS
			// Note: For encrypted keys, the KMS URI is typically in the keyset key structure,
			// not in KeyData. Full KMS support would require additional keyset parsing.
			keyMaterialType := keyData.GetKeyMaterialType()
			if keyMaterialType == 1 { // ENCRYPTED = 1
				return nil, fmt.Errorf("encrypted keys via KMS are not yet fully supported - use symmetric keys")
			}

			// For symmetric keys, return the value directly
			// SYMMETRIC = 2
			if keyMaterialType == 2 {
				keyBytes = keyData.Value
				break
			}
		}
	}

	if keyBytes == nil {
		return nil, fmt.Errorf("key with ID %d not found or unsupported key type", keyID)
	}

	// Create FF1 instance from subtle package with the extracted key
	ff1, err := subtle.NewFF1(keyBytes, tweak)
	if err != nil {
		return nil, fmt.Errorf("failed to create FF1 instance: %w", err)
	}

	// Wrap in FPE interface
	return &fpeImpl{ff1: ff1}, nil
}

// fpeImpl implements the fpe.FPE interface using the subtle.FF1 implementation.
type fpeImpl struct {
	ff1 *subtle.FF1
}

// Tokenize encrypts plaintext using format-preserving encryption.
func (f *fpeImpl) Tokenize(plaintext string) (string, error) {
	// Use the format handling from the parent package
	formatMask, dataChars := fpe.SeparateFormatAndData(plaintext)
	alphabet := fpe.DetermineAlphabet(dataChars)
	if len(alphabet) == 0 {
		return "", fmt.Errorf("no valid alphabet found for plaintext")
	}

	// Convert to numeric and encrypt
	dataNumeric := fpe.StringToNumeric(dataChars, alphabet)
	tokenizedNumeric, err := f.ff1.Encrypt(dataNumeric, alphabet)
	if err != nil {
		return "", fmt.Errorf("failed to tokenize: %w", err)
	}

	// Convert back to string and reconstruct with format
	tokenizedData := fpe.NumericToString(tokenizedNumeric, alphabet, len(dataChars))
	tokenized := fpe.ReconstructWithFormat(tokenizedData, formatMask, plaintext)

	return tokenized, nil
}

// Detokenize decrypts tokenized value using format-preserving encryption.
func (f *fpeImpl) Detokenize(tokenized string, originalPlaintext string) (string, error) {
	formatMask, dataChars := fpe.SeparateFormatAndData(tokenized)

	// Determine alphabet (prefer from original plaintext if provided)
	var alphabet string
	if originalPlaintext != "" {
		_, originalDataChars := fpe.SeparateFormatAndData(originalPlaintext)
		alphabet = fpe.DetermineAlphabet(originalDataChars)
	} else {
		alphabet = fpe.DetermineAlphabet(dataChars)
	}
	if len(alphabet) == 0 {
		return "", fmt.Errorf("no valid alphabet found")
	}

	// Convert to numeric and decrypt
	tokenizedNumeric := fpe.StringToNumeric(dataChars, alphabet)
	plaintextNumeric, err := f.ff1.Decrypt(tokenizedNumeric, alphabet)
	if err != nil {
		return "", fmt.Errorf("failed to detokenize: %w", err)
	}

	// Convert back to string and reconstruct with format
	plaintextData := fpe.NumericToString(plaintextNumeric, alphabet, len(dataChars))
	plaintext := fpe.ReconstructWithFormat(plaintextData, formatMask, tokenized)

	return plaintext, nil
}

// Verify that fpeImpl implements fpe.FPE
var _ fpe.FPE = (*fpeImpl)(nil)
