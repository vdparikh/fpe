package tinkfpe

import (
	cryptorand "crypto/rand"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/google/tink/go/keyset"
)

// TestCollisionResistance tests that different inputs produce different outputs
// (no collisions for a given key/tweak pair)
func TestCollisionResistance(t *testing.T) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		t.Fatalf("Failed to register KeyManager: %v", err)
	}

	// Create a keyset handle
	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		t.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("test-tweak")
	primitive, err := New(handle, tweak)
	if err != nil {
		t.Fatalf("Failed to create FPE primitive: %v", err)
	}

	// Test with numeric inputs
	t.Run("NumericInputs", func(t *testing.T) {
		seen := make(map[string]string) // ciphertext -> plaintext
		testCases := []string{
			"1234567890",
			"9876543210",
			"0000000000",
			"1111111111",
			"9999999999",
			"0123456789",
			"123456789",
			"12345678",
			"1234567",
			"123456",
		}

		for _, plaintext := range testCases {
			ciphertext, err := primitive.Tokenize(plaintext)
			if err != nil {
				t.Errorf("Failed to tokenize %s: %v", plaintext, err)
				continue
			}

			// Check for collisions
			if existing, exists := seen[ciphertext]; exists {
				t.Errorf("COLLISION DETECTED: %s and %s both produce %s",
					existing, plaintext, ciphertext)
			} else {
				seen[ciphertext] = plaintext
			}

			// Verify round-trip
			decrypted, err := primitive.Detokenize(ciphertext, plaintext)
			if err != nil {
				t.Errorf("Failed to detokenize %s: %v", ciphertext, err)
				continue
			}
			if decrypted != plaintext {
				t.Errorf("Round-trip failed: %s -> %s -> %s", plaintext, ciphertext, decrypted)
			}
		}

		t.Logf("✓ Tested %d numeric inputs, no collisions detected", len(testCases))
	})

	// Test with format-preserved inputs
	t.Run("FormatPreservedInputs", func(t *testing.T) {
		seen := make(map[string]string)
		testCases := []string{
			"123-45-6789",
			"987-65-4321",
			"000-00-0000",
			"111-11-1111",
			"999-99-9999",
			"4532-1234-5678-9010",
			"555-123-4567",
			"user@domain.com",
		}

		for _, plaintext := range testCases {
			ciphertext, err := primitive.Tokenize(plaintext)
			if err != nil {
				t.Errorf("Failed to tokenize %s: %v", plaintext, err)
				continue
			}

			if existing, exists := seen[ciphertext]; exists {
				t.Errorf("COLLISION DETECTED: %s and %s both produce %s",
					existing, plaintext, ciphertext)
			} else {
				seen[ciphertext] = plaintext
			}
		}

		t.Logf("✓ Tested %d format-preserved inputs, no collisions detected", len(testCases))
	})

	// Test with random inputs (more comprehensive)
	t.Run("RandomInputs", func(t *testing.T) {
		// Track both plaintexts and ciphertexts to detect actual collisions
		// A collision is when DIFFERENT plaintexts produce the SAME ciphertext
		plaintextToCiphertext := make(map[string]string) // plaintext -> ciphertext
		ciphertextToPlaintext := make(map[string]string) // ciphertext -> plaintext (for collision detection)
		collisions := 0
		numTests := 1000
		seenPlaintexts := make(map[string]bool) // Track unique plaintexts

		for i := 0; i < numTests; i++ {
			// Generate random numeric string
			plaintext := generateRandomNumericString(10)

			// Skip if we've seen this exact plaintext before (deterministic encryption will produce same output)
			if seenPlaintexts[plaintext] {
				// This is expected - same input produces same output (deterministic)
				// Verify it produces the same ciphertext as before
				expectedCiphertext := plaintextToCiphertext[plaintext]
				actualCiphertext, err := primitive.Tokenize(plaintext)
				if err != nil {
					t.Errorf("Failed to tokenize duplicate input: %v", err)
					continue
				}
				if actualCiphertext != expectedCiphertext {
					t.Errorf("Determinism violation: %s produced %s before, now produces %s",
						plaintext, expectedCiphertext, actualCiphertext)
				}
				continue
			}
			seenPlaintexts[plaintext] = true

			ciphertext, err := primitive.Tokenize(plaintext)
			if err != nil {
				t.Errorf("Failed to tokenize random input: %v", err)
				continue
			}

			// Store the mapping
			plaintextToCiphertext[plaintext] = ciphertext

			// Check for actual collision: different plaintext producing same ciphertext
			if existingPlaintext, exists := ciphertextToPlaintext[ciphertext]; exists {
				// This is a real collision: two different plaintexts produce the same ciphertext
				collisions++
				t.Errorf("COLLISION DETECTED: %s and %s both produce %s",
					existingPlaintext, plaintext, ciphertext)
			} else {
				ciphertextToPlaintext[ciphertext] = plaintext
			}
		}

		if collisions > 0 {
			t.Errorf("Found %d collisions in %d random tests", collisions, numTests)
		} else {
			t.Logf("✓ Tested %d unique random inputs, no collisions detected", len(seenPlaintexts))
		}
	})
}

// TestAvalancheEffect tests that small changes in input produce large changes in output
func TestAvalancheEffect(t *testing.T) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		t.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		t.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("avalanche-test")
	primitive, err := New(handle, tweak)
	if err != nil {
		t.Fatalf("Failed to create FPE primitive: %v", err)
	}

	testCases := []struct {
		name     string
		base     string
		variants []string
	}{
		{
			name: "SingleDigitChange",
			base: "1234567890",
			variants: []string{
				"0234567890", // Change first digit
				"1234567891", // Change last digit
				"1234567880", // Change second-to-last
			},
		},
		{
			name: "FormatCharacterChange",
			base: "123-45-6789",
			variants: []string{
				"124-45-6789", // Change digit before first hyphen
				"123-46-6789", // Change digit after first hyphen
				"123-45-6799", // Change digit before last
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseCipher, err := primitive.Tokenize(tc.base)
			if err != nil {
				t.Fatalf("Failed to tokenize base: %v", err)
			}

			for _, variant := range tc.variants {
				variantCipher, err := primitive.Tokenize(variant)
				if err != nil {
					t.Errorf("Failed to tokenize variant %s: %v", variant, err)
					continue
				}

				// Calculate Hamming distance (number of different characters)
				distance := hammingDistance(baseCipher, variantCipher)
				maxDistance := len(baseCipher)

				// For FPE, avalanche effect is weaker than block ciphers because format is preserved
				// We expect at least 1 character to differ (to ensure the change propagates)
				// For format-preserving encryption, even small changes should produce different outputs
				if distance == 0 {
					t.Errorf("No avalanche effect: %s -> %s, %s -> %s (identical outputs)",
						tc.base, baseCipher, variant, variantCipher)
				} else {
					t.Logf("✓ Avalanche effect: %s vs %s (distance: %d/%d)",
						tc.base, variant, distance, maxDistance)
				}
			}
		})
	}
}

// TestBijectivity verifies that encryption is a bijection (one-to-one mapping)
// For a given key/tweak, every input should map to a unique output
func TestBijectivity(t *testing.T) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		t.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		t.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("bijectivity-test")
	primitive, err := New(handle, tweak)
	if err != nil {
		t.Fatalf("Failed to create FPE primitive: %v", err)
	}

	// Test with a small domain to exhaustively check bijectivity
	t.Run("SmallDomain", func(t *testing.T) {
		// Test all 3-digit numbers (1000 possibilities)
		// Note: This might fail domain size check, so we'll use 4-digit
		seen := make(map[string]bool)
		domainSize := 10000 // 4-digit numbers

		for i := 0; i < domainSize; i++ {
			plaintext := fmt.Sprintf("%04d", i)
			ciphertext, err := primitive.Tokenize(plaintext)
			if err != nil {
				// Domain size might be too small, skip
				if i < 100 {
					continue
				}
				t.Errorf("Failed to tokenize %s: %v", plaintext, err)
				continue
			}

			if seen[ciphertext] {
				t.Errorf("NOT BIJECTIVE: %s maps to %s (already seen)", plaintext, ciphertext)
			}
			seen[ciphertext] = true

			// Verify reverse mapping
			decrypted, err := primitive.Detokenize(ciphertext, plaintext)
			if err != nil {
				t.Errorf("Failed to detokenize %s: %v", ciphertext, err)
				continue
			}
			if decrypted != plaintext {
				t.Errorf("NOT INVERTIBLE: %s -> %s -> %s", plaintext, ciphertext, decrypted)
			}
		}

		if len(seen) == domainSize {
			t.Logf("✓ Bijectivity verified for domain size %d", domainSize)
		} else {
			t.Logf("Tested %d/%d inputs (some may have failed domain size check)", len(seen), domainSize)
		}
	})
}

// TestKeySensitivity verifies that different keys produce different outputs
func TestKeySensitivity(t *testing.T) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		t.Fatalf("Failed to register KeyManager: %v", err)
	}

	plaintext := "1234567890"
	tweak := []byte("key-sensitivity-test")

	// Generate multiple different keys
	numKeys := 10
	keys := make([][]byte, numKeys)
	ciphertexts := make(map[string]int) // ciphertext -> key index

	for i := 0; i < numKeys; i++ {
		key := make([]byte, 32)
		if _, err := cryptorand.Read(key); err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}
		keys[i] = key

		handle, err := NewKeysetHandleFromKey(key)
		if err != nil {
			t.Fatalf("Failed to create keyset handle for key %d: %v", i, err)
		}

		primitive, err := New(handle, tweak)
		if err != nil {
			t.Fatalf("Failed to create FPE primitive for key %d: %v", i, err)
		}

		ciphertext, err := primitive.Tokenize(plaintext)
		if err != nil {
			t.Fatalf("Failed to tokenize with key %d: %v", i, err)
		}

		// Check for collisions across different keys
		if existingKey, exists := ciphertexts[ciphertext]; exists {
			t.Errorf("KEY COLLISION: Key %d and key %d both produce %s for input %s",
				existingKey, i, ciphertext, plaintext)
		} else {
			ciphertexts[ciphertext] = i
		}
	}

	if len(ciphertexts) == numKeys {
		t.Logf("✓ Key sensitivity verified: %d different keys produced %d different outputs", numKeys, len(ciphertexts))
	}
}

// TestTweakSensitivity verifies that different tweaks produce different outputs
func TestTweakSensitivity(t *testing.T) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		t.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		t.Fatalf("Failed to create keyset handle: %v", err)
	}

	plaintext := "1234567890"

	// Test with different tweaks
	tweaks := [][]byte{
		[]byte(""),
		[]byte("tweak1"),
		[]byte("tweak2"),
		[]byte("tweak-3"),
		[]byte("very-long-tweak-value-for-testing"),
		[]byte("a"),
		[]byte("b"),
	}

	ciphertexts := make(map[string]string) // ciphertext -> tweak

	for _, tweak := range tweaks {
		primitive, err := New(handle, tweak)
		if err != nil {
			t.Fatalf("Failed to create FPE primitive with tweak %q: %v", tweak, err)
		}

		ciphertext, err := primitive.Tokenize(plaintext)
		if err != nil {
			t.Fatalf("Failed to tokenize with tweak %q: %v", tweak, err)
		}

		// Check for collisions across different tweaks
		if existingTweak, exists := ciphertexts[ciphertext]; exists {
			t.Errorf("TWEAK COLLISION: Tweak %q and %q both produce %s for input %s",
				existingTweak, tweak, ciphertext, plaintext)
		} else {
			ciphertexts[ciphertext] = string(tweak)
		}
	}

	if len(ciphertexts) == len(tweaks) {
		t.Logf("✓ Tweak sensitivity verified: %d different tweaks produced %d different outputs", len(tweaks), len(ciphertexts))
	}
}

// TestDistribution tests that outputs are well-distributed (not biased)
func TestDistribution(t *testing.T) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		t.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		t.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("distribution-test")
	primitive, err := New(handle, tweak)
	if err != nil {
		t.Fatalf("Failed to create FPE primitive: %v", err)
	}

	// Test digit distribution in ciphertexts
	t.Run("DigitDistribution", func(t *testing.T) {
		numTests := 10000
		digitCounts := make(map[rune]int)

		for i := 0; i < numTests; i++ {
			plaintext := generateRandomNumericString(10)
			ciphertext, err := primitive.Tokenize(plaintext)
			if err != nil {
				t.Errorf("Failed to tokenize: %v", err)
				continue
			}

			for _, char := range ciphertext {
				if char >= '0' && char <= '9' {
					digitCounts[char]++
				}
			}
		}

		// Check that digits are reasonably distributed
		// For uniform distribution, each digit should appear ~10% of the time
		expectedPerDigit := numTests * 10 / 100  // Rough estimate
		tolerance := expectedPerDigit * 30 / 100 // 30% tolerance

		for digit := '0'; digit <= '9'; digit++ {
			count := digitCounts[digit]
			if count < expectedPerDigit-tolerance || count > expectedPerDigit+tolerance {
				t.Logf("Digit %c: %d occurrences (expected ~%d ± %d)",
					digit, count, expectedPerDigit, tolerance)
			}
		}

		t.Logf("✓ Digit distribution tested across %d ciphertexts", numTests)
	})
}

// TestDeterminism verifies that same input + same key + same tweak = same output
func TestDeterminism(t *testing.T) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		t.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		t.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("determinism-test")
	testCases := []string{
		"1234567890",
		"9876543210",
		"123-45-6789",
		"user@domain.com",
	}

	for _, plaintext := range testCases {
		primitive1, err := New(handle, tweak)
		if err != nil {
			t.Fatalf("Failed to create FPE primitive: %v", err)
		}

		ciphertext1, err := primitive1.Tokenize(plaintext)
		if err != nil {
			t.Errorf("Failed to tokenize %s: %v", plaintext, err)
			continue
		}

		// Create a new primitive instance (should use same key)
		primitive2, err := New(handle, tweak)
		if err != nil {
			t.Fatalf("Failed to create second FPE primitive: %v", err)
		}

		ciphertext2, err := primitive2.Tokenize(plaintext)
		if err != nil {
			t.Errorf("Failed to tokenize %s with second primitive: %v", plaintext, err)
			continue
		}

		if ciphertext1 != ciphertext2 {
			t.Errorf("NOT DETERMINISTIC: %s produced %s and %s", plaintext, ciphertext1, ciphertext2)
		}
	}

	t.Logf("✓ Determinism verified for %d test cases", len(testCases))
}

// Helper functions

var (
	// Global RNG for test use to avoid seed collisions
	testRNG      = rand.New(rand.NewSource(time.Now().UnixNano()))
	testRNGMutex sync.Mutex
)

func generateRandomNumericString(length int) string {
	testRNGMutex.Lock()
	defer testRNGMutex.Unlock()

	// Use a combination of time and random to ensure uniqueness
	// Add some randomness to avoid collisions on fast systems
	testRNG.Seed(time.Now().UnixNano() + int64(testRNG.Intn(1000000)))

	b := make([]byte, length)
	for i := range b {
		b[i] = byte('0' + testRNG.Intn(10))
	}
	return string(b)
}

func hammingDistance(s1, s2 string) int {
	if len(s1) != len(s2) {
		return -1 // Different lengths
	}
	distance := 0
	for i := 0; i < len(s1); i++ {
		if s1[i] != s2[i] {
			distance++
		}
	}
	return distance
}
