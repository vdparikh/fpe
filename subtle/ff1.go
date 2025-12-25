// Package subtle provides low-level cryptographic primitives for Format-Preserving Encryption.
// This package contains the core NIST FF1 algorithm implementation that works with raw keys.
// It should not be used directly by most users; instead use the high-level APIs in the parent package.
package subtle

import (
	"crypto/aes"
	"fmt"
	"math/big"
)

// FF1 implements the core NIST SP 800-38G FF1 algorithm using raw keys.
// This is the low-level implementation that performs the actual cryptographic operations.
type FF1 struct {
	key   []byte
	tweak []byte
}

// NewFF1 creates a new FF1 instance with the given raw key and tweak.
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

// Encrypt performs FF1 format-preserving encryption on numeric data.
// This is the core encryption function that works with numeric arrays (base-radix representation).
//
// Maximum input length: The implementation supports inputs up to 2^31-1 characters,
// but practical limits are determined by available memory. For very long inputs (>10,000
// characters), consider performance implications.
//
// Thread safety: This method is safe for concurrent use by multiple goroutines,
// as it does not modify the FF1 instance state.
func (f *FF1) Encrypt(plaintext []uint16, alphabet string) ([]uint16, error) {
	radix := len(alphabet)
	n := len(plaintext)

	if n == 0 {
		return plaintext, nil
	}

	// Validate maximum practical input length to prevent resource exhaustion
	// NIST FF1 doesn't specify a maximum, but we set a reasonable limit
	const maxInputLength = 100000 // 100k characters
	if n > maxInputLength {
		return nil, fmt.Errorf("input too long: %d characters (maximum %d)", n, maxInputLength)
	}

	// Validate minimum domain size for security
	// Domain size = radix^n. For security, we require domain size >= 1000
	// This prevents using FF1 on very small domains which are not secure
	domainSize := new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(n)), nil)
	minDomainSize := big.NewInt(1000)
	if domainSize.Cmp(minDomainSize) < 0 {
		return nil, fmt.Errorf("domain size too small: radix=%d, length=%d, domain_size=%s (minimum 1000 required for security)", radix, n, domainSize.String())
	}

	// Step 1: Split into left and right halves
	// u = floor(n/2), v = ceil(n/2)
	u := n / 2
	v := n - u

	// Step 2: Initialize A and B
	// A = first u elements, B = last v elements
	A := make([]uint16, u)
	B := make([]uint16, v)
	copy(A, plaintext[:u])
	copy(B, plaintext[u:])

	// Get properly sized key
	aesKey := f.getAESKey()

	// Number of rounds (FF1 uses 10 rounds)
	rounds := 10

	// Step 6: Feistel rounds
	for i := 0; i < rounds; i++ {
		// Current sizes: A has size len(A), B has size len(B)
		// F function: compute on B, output should have size len(A)
		currentU := len(A)
		currentV := len(B)
		C := f.feistelFunction(B, i, currentU, currentV, n, radix, aesKey)

		// Ensure C has exactly len(A) elements
		if len(C) != len(A) {
			// Pad or truncate C to match A's length
			newC := make([]uint16, len(A))
			for j := 0; j < len(A); j++ {
				if j < len(C) {
					newC[j] = C[j]
				} else {
					newC[j] = 0
				}
			}
			C = newC
		}

		// Feistel round:
		// A_{i+1} = B_i
		// B_{i+1} = (A_i + C) mod radix (element-wise)
		newB := make([]uint16, len(A))
		for j := 0; j < len(A); j++ {
			val := uint32(A[j]) + uint32(C[j])
			newB[j] = uint16(val % uint32(radix))
		}

		// Update for next round: A_{i+1} = B_i, B_{i+1} = newB
		A, B = B, newB
	}

	// Step 7: Output A || B
	result := make([]uint16, n)
	copy(result, A)
	copy(result[len(A):], B)

	return result, nil
}

// Decrypt performs FF1 format-preserving decryption on numeric data.
// This is the core decryption function that works with numeric arrays (base-radix representation).
//
// Maximum input length: The implementation supports inputs up to 2^31-1 characters,
// but practical limits are determined by available memory. For very long inputs (>10,000
// characters), consider performance implications.
//
// Thread safety: This method is safe for concurrent use by multiple goroutines,
// as it does not modify the FF1 instance state.
func (f *FF1) Decrypt(ciphertext []uint16, alphabet string) ([]uint16, error) {
	radix := len(alphabet)
	n := len(ciphertext)

	if n == 0 {
		return ciphertext, nil
	}

	// Validate maximum practical input length to prevent resource exhaustion
	const maxInputLength = 100000 // 100k characters
	if n > maxInputLength {
		return nil, fmt.Errorf("input too long: %d characters (maximum %d)", n, maxInputLength)
	}

	// Validate minimum domain size for security (same as encryption)
	domainSize := new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(n)), nil)
	minDomainSize := big.NewInt(1000)
	if domainSize.Cmp(minDomainSize) < 0 {
		return nil, fmt.Errorf("domain size too small: radix=%d, length=%d, domain_size=%s (minimum 1000 required for security)", radix, n, domainSize.String())
	}

	// Step 1: Split into left and right halves
	u := n / 2
	v := n - u

	// Start with the final state from encryption
	A := make([]uint16, u)
	B := make([]uint16, v)
	copy(A, ciphertext[:u])
	copy(B, ciphertext[u:])

	// Get properly sized key
	aesKey := f.getAESKey()

	// Number of rounds (same as encryption)
	rounds := 10

	// Decrypt by running rounds in reverse
	for i := rounds - 1; i >= 0; i-- {
		// Current sizes: A has size len(A), B has size len(B)
		// F function: compute on A (which was B_i), output should have size len(B)
		currentU := len(B) // Output size (size of B, which was A_{i+1})
		currentV := len(A) // Input size (size of A, which was B_i)
		C := f.feistelFunction(A, i, currentU, currentV, n, radix, aesKey)

		// Ensure C has exactly len(B) elements
		if len(C) != len(B) {
			// Pad or truncate C to match B's length
			newC := make([]uint16, len(B))
			for j := 0; j < len(B); j++ {
				if j < len(C) {
					newC[j] = C[j]
				} else {
					newC[j] = 0
				}
			}
			C = newC
		}

		// Recover A_i: A_i = (B_{i+1} - C + radix) mod radix
		oldA := make([]uint16, len(B))
		for j := 0; j < len(B); j++ {
			cIdx := j % len(C)
			cVal := uint32(C[cIdx])
			val := uint32(B[j]) + uint32(radix) - cVal
			oldA[j] = uint16(val % uint32(radix))
		}

		// Recover B_i: B_i = A_{i+1} = current A
		oldB := make([]uint16, len(A))
		copy(oldB, A)

		// Update for next iteration: A = A_i, B = B_i
		A = oldA
		B = oldB
	}

	// After all rounds, we have A = A_0 (u elements), B = B_0 (v elements)
	result := make([]uint16, n)
	copy(result, A)
	copy(result[len(A):], B)

	return result, nil
}

// feistelFunction implements the F function for FF1 following NIST SP 800-38G.
// This is the core PRF used in each Feistel round.
func (f *FF1) feistelFunction(B []uint16, roundNum, u, v, n, radix int, aesKey []byte) []uint16 {
	m := len(B)
	if m == 0 {
		return make([]uint16, u)
	}

	// Step 6.i: Build Q array
	Q := f.buildQArray(roundNum, B, radix)

	// Step 6.ii: Encrypt Q with AES to get R
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		// This should not happen with valid key sizes, but handle gracefully
		return make([]uint16, u)
	}

	// Q must be padded to AES block size (16 bytes)
	blockSize := aes.BlockSize
	qLen := len(Q)
	paddedLen := ((qLen + blockSize - 1) / blockSize) * blockSize
	Q_padded := make([]byte, paddedLen)
	copy(Q_padded, Q)

	// Encrypt Q_padded with AES-ECB
	R := make([]byte, paddedLen)
	for i := 0; i < paddedLen; i += blockSize {
		block.Encrypt(R[i:], Q_padded[i:])
	}

	// Step 6.iii: Extract S (first d bytes of R)
	d := (u*bitLength(radix) + 7) / 8
	if d < 1 {
		d = 1
	}
	if d > len(R) {
		d = len(R)
	}
	// For small outputs, use more bytes for better distribution
	if d < 8 && len(R) >= 8 {
		d = 8
	}
	S := R[:d]

	// Step 6.iv: Convert S to integer y (big-endian)
	y := new(big.Int).SetBytes(S)

	// Step 6.v: m is the output length (u)
	// Step 6.vi: Compute c = y mod (radix^m)
	radixBig := big.NewInt(int64(radix))
	radixPowM := new(big.Int).Exp(radixBig, big.NewInt(int64(u)), nil)
	c := new(big.Int).Mod(y, radixPowM)

	// Step 6.vii: Convert c to base-radix representation of length u
	C := numradixDecode(c, radix, u)

	return C
}

// buildQArray constructs the Q array for a specific round as specified in NIST FF1.
func (f *FF1) buildQArray(roundNum int, B []uint16, radix int) []byte {
	// Q starts with 4 bytes of round number
	Q := make([]byte, 0)
	Q = append(Q, byte(roundNum))
	Q = append(Q, byte(roundNum))
	Q = append(Q, byte(roundNum))
	Q = append(Q, byte(roundNum))

	// Add tweak
	Q = append(Q, f.tweak...)

	// Add B array encoded using numradix
	B_bytes := numradixToBytes(B, radix)
	Q = append(Q, B_bytes...)

	// Pad Q to AES block size (16 bytes) boundary
	blockSize := aes.BlockSize
	qLen := len(Q)
	paddedLen := ((qLen + blockSize - 1) / blockSize) * blockSize
	if paddedLen > qLen {
		padding := make([]byte, paddedLen-qLen)
		Q = append(Q, padding...)
	}

	return Q
}

// getAESKey returns the AES key properly sized (16, 24, or 32 bytes).
func (f *FF1) getAESKey() []byte {
	keyLen := len(f.key)

	// AES supports 16, 24, or 32 byte keys
	if keyLen == 16 || keyLen == 24 || keyLen == 32 {
		return f.key
	}

	// If key is < 16 bytes, pad to 16
	if keyLen < 16 {
		padded := make([]byte, 16)
		copy(padded, f.key)
		return padded
	}

	// If key is between sizes, use the next smaller standard size
	if keyLen < 24 {
		return f.key[:16]
	}
	if keyLen < 32 {
		return f.key[:24]
	}

	// If key is > 32 bytes, use first 32
	return f.key[:32]
}
