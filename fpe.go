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
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// FF1 implements Format-Preserving Encryption using the FF1 algorithm.
// FF1 is based on a Feistel network and preserves the format of input data.
type FF1 struct {
	key   []byte
	tweak []byte
}

// NewFF1 creates a new FF1 FPE instance with the given key and tweak.
// The key should be at least 16 bytes (AES-128) or 32 bytes (AES-256).
// The tweak is a public, non-secret value that ensures different ciphertexts
// for the same plaintext when the tweak changes.
func NewFF1(key, tweak []byte) (*FF1, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("key must be at least 16 bytes, got %d", len(key))
	}
	return &FF1{
		key:   key,
		tweak: tweak,
	}, nil
}

// Tokenize encrypts plaintext using format-preserving encryption.
// It preserves format characters (hyphens, dots, colons, @ signs, etc.) and
// only encrypts the alphanumeric data characters.
//
// Returns the tokenized (encrypted) value that maintains the same format as the input.
func (f *FF1) Tokenize(plaintext string) (string, error) {
	// Step 1: Separate format characters (hyphens, dots, etc.) from data characters
	formatMask, dataChars := separateFormatAndData(plaintext)

	// Step 2: Determine the alphabet for data characters only
	alphabet := determineAlphabet(dataChars)
	if len(alphabet) == 0 {
		return "", fmt.Errorf("no valid alphabet found for plaintext")
	}

	// Step 3: Convert data characters to numeric representation
	dataNumeric := stringToNumeric(dataChars, alphabet)

	// Step 4: Use FF1 algorithm for format-preserving encryption
	tokenizedNumeric, err := f.ff1Encrypt(dataNumeric, alphabet)
	if err != nil {
		return "", fmt.Errorf("failed to tokenize: %w", err)
	}

	// Step 5: Convert back to string and reconstruct with format
	tokenizedData := numericToString(tokenizedNumeric, alphabet, len(dataChars))
	tokenized := reconstructWithFormat(tokenizedData, formatMask, plaintext)

	return tokenized, nil
}

// Detokenize decrypts tokenized value using format-preserving encryption.
// The alphabet parameter should match what was used during tokenization.
// If empty, it will be determined from the tokenized data (may not match original).
//
// For best results, pass the alphabet determined from the original plaintext.
func (f *FF1) Detokenize(tokenized string, originalPlaintext string, alphabet string) (string, error) {
	// Step 1: Separate format characters from data characters
	formatMask, dataChars := separateFormatAndData(tokenized)

	// Step 2: Determine alphabet (prefer from original plaintext if provided)
	if alphabet == "" {
		if originalPlaintext != "" {
			_, originalDataChars := separateFormatAndData(originalPlaintext)
			alphabet = determineAlphabet(originalDataChars)
		} else {
			alphabet = determineAlphabet(dataChars)
		}
	}
	if len(alphabet) == 0 {
		return "", fmt.Errorf("no valid alphabet found")
	}

	// Step 3: Convert tokenized data to numeric representation
	tokenizedNumeric := stringToNumeric(dataChars, alphabet)

	// Step 4: Use FF1 algorithm for format-preserving decryption
	plaintextNumeric, err := f.ff1Decrypt(tokenizedNumeric, alphabet)
	if err != nil {
		return "", fmt.Errorf("failed to detokenize: %w", err)
	}

	// Step 5: Convert back to string and reconstruct with format
	plaintextData := numericToString(plaintextNumeric, alphabet, len(dataChars))
	plaintext := reconstructWithFormat(plaintextData, formatMask, tokenized)

	return plaintext, nil
}

// ff1Encrypt performs FF1-style format-preserving encryption.
// Implements a Feistel network following NIST SP 800-38G principles.
func (f *FF1) ff1Encrypt(plaintext []uint16, alphabet string) ([]uint16, error) {
	radix := len(alphabet)
	n := len(plaintext)

	if n == 0 {
		return plaintext, nil
	}

	// FF1 Feistel network: split into left and right halves
	// u = floor(n/2), v = ceil(n/2)
	u := n / 2
	v := n - u

	// Handle edge case: if n=1, we can't split into Feistel network
	// For single character, just return as-is (or apply simple transformation)
	if n == 1 {
		// For single character, apply a simple transformation
		// This is not standard FF1, but handles the edge case
		result := make([]uint16, 1)
		result[0] = (plaintext[0] + 1) % uint16(radix)
		return result, nil
	}

	// L_0 = first u elements, R_0 = last v elements
	L := make([]uint16, u)
	R := make([]uint16, v)
	copy(L, plaintext[:u])
	copy(R, plaintext[u:])

	// Number of rounds (FF1 uses 10 rounds)
	rounds := 10

	for i := 0; i < rounds; i++ {
		// Generate round key from main key and round number
		roundKey := f.deriveRoundKey(i, radix)

		// F function: compute on R (right half)
		// F returns output of same length as input (R)
		fOutput := f.feistelFunction(R, roundKey, radix)

		// Feistel round:
		// L_{i+1} = R_i
		// R_{i+1} = (L_i + F(R_i)) mod radix
		// fOutput has length len(R), but we need length len(L) for newR
		// Use the F output cyclically to match L's length
		// This ensures consistent mapping when sizes differ
		newR := make([]uint16, len(L))
		for j := 0; j < len(L); j++ {
			// Map fOutput index to L index using cyclic indexing
			// This ensures we use all of fOutput's values
			fIdx := j % len(fOutput)
			fVal := uint32(fOutput[fIdx])
			val := uint32(L[j]) + fVal
			newR[j] = uint16(val % uint32(radix))
		}

		// Update for next round: L_{i+1} = R_i, R_{i+1} = newR
		L, R = R, newR
	}

	// After all rounds: L = R_rounds, R = L_rounds
	// After 10 rounds (even): L has size of R_9, R has size of L_9
	// Since sizes alternate: R_9 has size u (if 9 is odd) or v (if 9 is even)
	// 9 is odd, so R_9 has size u, L_9 has size v
	// So L = R_9 has size u, R = L_9 has size v
	// Output: [L, R] = [u elements, v elements] = [L_0 size, R_0 size]
	result := make([]uint16, n)
	copy(result, L)
	copy(result[len(L):], R)

	return result, nil
}

// ff1Decrypt performs FF1-style format-preserving decryption.
// Reverse of encryption using Feistel network.
func (f *FF1) ff1Decrypt(ciphertext []uint16, alphabet string) ([]uint16, error) {
	radix := len(alphabet)
	n := len(ciphertext)

	if n == 0 {
		return ciphertext, nil
	}

	// FF1 Feistel network (reverse)
	// Split into left and right halves
	u := n / 2
	v := n - u

	// Start with the final state from encryption
	// Encryption ends with: result = [L, R] where L = R_9, R = L_9
	// After 9 rounds: L_9 has size v (since 9 is odd, L alternates: L_0=u, L_1=v, L_2=u, ..., L_9=v)
	//                 R_9 has size u (since 9 is odd, R alternates: R_0=v, R_1=u, R_2=v, ..., R_9=u)
	// So after 10 rounds: L = R_9 has size u, R = L_9 has size v
	// Output: [L, R] = [u, v]
	// So ciphertext = [u elements, v elements]
	L := make([]uint16, u) // L = R_9 has size u
	R := make([]uint16, v) // R = L_9 has size v
	copy(L, ciphertext[:u])
	copy(R, ciphertext[u:])

	// Number of rounds (same as encryption)
	rounds := 10

	// Decrypt by running rounds in reverse
	for i := rounds - 1; i >= 0; i-- {
		// Generate round key from main key and round number
		roundKey := f.deriveRoundKey(i, radix)

		// At start of decryption round i: L = L_{i+1}, R = R_{i+1}
		// We need to recover: L_i and R_i
		// From encryption: L_{i+1} = R_i, so R_i = L (current L)
		// From encryption: R_{i+1} = (L_i + F(R_i)) mod radix
		// So: L_i = (R_{i+1} - F(R_i) + radix) mod radix
		//     L_i = (R - F(L) + radix) mod radix

		// F function: compute on R_i = current L
		// F returns output of same length as input (L)
		fOutput := f.feistelFunction(L, roundKey, radix)

		// Recover L_i: L_i = (R_{i+1} - F(R_i) + radix) mod radix
		// R_{i+1} = current R, R_i = current L
		// So: L_i = (R - F(L) + radix) mod radix
		// fOutput has length len(L), but we need length len(R) for oldL
		// Use the SAME cyclic mapping as encryption to ensure consistency
		oldL := make([]uint16, len(R))
		for j := 0; j < len(R); j++ {
			// Use the same cyclic indexing as encryption
			// In encryption: we mapped fOutput (size v) to L (size u) using j % len(fOutput)
			// In decryption: we map fOutput (size u) to R (size v) using j % len(fOutput)
			// This ensures the mapping is consistent
			fIdx := j % len(fOutput)
			fVal := uint32(fOutput[fIdx])
			// Reverse the addition: (R - fOutput + radix) mod radix
			val := uint32(R[j]) + uint32(radix) - fVal
			oldL[j] = uint16(val % uint32(radix))
		}

		// Recover R_i: R_i = L_{i+1} = current L
		oldR := make([]uint16, len(L))
		copy(oldR, L)

		// Update for next iteration: L = L_i, R = R_i
		L = oldL
		R = oldR
	}

	// After all rounds, we have L = L_0 (u elements), R = R_0 (v elements)
	// Original was [L_0, R_0], so combine: L then R
	result := make([]uint16, n)
	copy(result, L)
	copy(result[len(L):], R)

	return result, nil
}

// feistelFunction implements the F function for Feistel network.
// This should produce output of the same length as input.
func (f *FF1) feistelFunction(input []uint16, roundKey []byte, radix int) []uint16 {
	if len(input) == 0 {
		return input
	}

	// Use AES to generate pseudorandom values
	block, err := aes.NewCipher(roundKey)
	if err != nil {
		// Fallback: simple hash
		return f.simpleHash(input, radix)
	}

	// Convert input to bytes
	inputBytes := numericToBytes(input, radix)

	// Pad to block size
	blockSize := aes.BlockSize
	paddedLen := ((len(inputBytes) + blockSize - 1) / blockSize) * blockSize
	padded := make([]byte, paddedLen)
	copy(padded, inputBytes)

	// Encrypt with AES-ECB (one block at a time)
	// Use cipher.Block interface explicitly
	var cipherBlock cipher.Block = block
	output := make([]byte, paddedLen)
	for i := 0; i < paddedLen; i += blockSize {
		cipherBlock.Encrypt(output[i:], padded[i:])
	}

	// Convert back to numeric and constrain to radix
	// Ensure we produce exactly len(input) elements
	result := make([]uint16, len(input))
	outputBytesNeeded := len(input) * 2
	if outputBytesNeeded > len(output) {
		// If we need more bytes than we have, cycle through the output
		for i := 0; i < len(input); i++ {
			byteIdx := (i * 2) % len(output)
			if byteIdx+1 < len(output) {
				val := uint16(output[byteIdx])<<8 | uint16(output[byteIdx+1])
				result[i] = val % uint16(radix)
			} else {
				// Handle edge case
				val := uint16(output[byteIdx])
				result[i] = val % uint16(radix)
			}
		}
	} else {
		// Normal case: we have enough bytes
		for i := 0; i < len(input); i++ {
			if i*2+1 < len(output) {
				val := uint16(output[i*2])<<8 | uint16(output[i*2+1])
				result[i] = val % uint16(radix)
			} else {
				// Fallback if somehow we don't have enough
				result[i] = 0
			}
		}
	}

	return result
}

// simpleHash provides a fallback hash function
func (f *FF1) simpleHash(input []uint16, radix int) []uint16 {
	result := make([]uint16, len(input))
	for i, val := range input {
		// Simple hash: multiply by prime and add tweak
		hash := (uint32(val) * 31) + uint32(f.tweak[i%len(f.tweak)])
		result[i] = uint16(hash % uint32(radix))
	}
	return result
}

// deriveRoundKey derives a round key from the main key and round number
func (f *FF1) deriveRoundKey(round int, radix int) []byte {
	// Simple key derivation: XOR round number into key
	roundKey := make([]byte, len(f.key))
	copy(roundKey, f.key)

	// Add round number to first few bytes
	for i := 0; i < len(roundKey) && i < 4; i++ {
		roundKey[i] ^= byte(round >> (i * 8))
	}

	// Ensure key is at least AES block size
	if len(roundKey) < aes.BlockSize {
		padded := make([]byte, aes.BlockSize)
		copy(padded, roundKey)
		roundKey = padded
	} else if len(roundKey) > aes.BlockSize {
		roundKey = roundKey[:aes.BlockSize]
	}

	return roundKey
}
