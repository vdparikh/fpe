package tinkfpe

import (
	cryptorand "crypto/rand"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/proto/tink_go_proto"
)

// BenchmarkTokenize benchmarks the Tokenize operation for various input sizes
func BenchmarkTokenize(b *testing.B) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		b.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		b.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("benchmark-tweak")
	primitive, err := New(handle, tweak)
	if err != nil {
		b.Fatalf("Failed to create FPE primitive: %v", err)
	}

	benchmarks := []struct {
		name      string
		plaintext string
	}{
		{"Short_4digits", "1234"},
		{"Medium_10digits", "1234567890"},
		{"Long_16digits", "1234567890123456"},
		{"SSN_Format", "123-45-6789"},
		{"CreditCard_Format", "4532-1234-5678-9010"},
		{"Phone_Format", "555-123-4567"},
		{"Email_Format", "user@domain.com"},
		{"Alphanumeric_10", "ABC123XYZ9"},
		{"Alphanumeric_20", "ABC123XYZ9DEF456UVW8"},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := primitive.Tokenize(bm.plaintext)
				if err != nil {
					b.Fatalf("Tokenize failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkDetokenize benchmarks the Detokenize operation
func BenchmarkDetokenize(b *testing.B) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		b.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		b.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("benchmark-tweak")
	primitive, err := New(handle, tweak)
	if err != nil {
		b.Fatalf("Failed to create FPE primitive: %v", err)
	}

	// Pre-tokenize the test data
	testCases := []struct {
		name      string
		plaintext string
		tokenized string
	}{
		{"Short_4digits", "1234", ""},
		{"Medium_10digits", "1234567890", ""},
		{"SSN_Format", "123-45-6789", ""},
		{"CreditCard_Format", "4532-1234-5678-9010", ""},
	}

	// Tokenize all test cases first
	for i := range testCases {
		tokenized, err := primitive.Tokenize(testCases[i].plaintext)
		if err != nil {
			b.Fatalf("Failed to tokenize %s: %v", testCases[i].name, err)
		}
		testCases[i].tokenized = tokenized
	}

	// Now benchmark detokenize
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := primitive.Detokenize(tc.tokenized, tc.plaintext)
				if err != nil {
					b.Fatalf("Detokenize failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkRoundTrip benchmarks the full encrypt-decrypt cycle
func BenchmarkRoundTrip(b *testing.B) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		b.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		b.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("benchmark-tweak")
	primitive, err := New(handle, tweak)
	if err != nil {
		b.Fatalf("Failed to create FPE primitive: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext string
	}{
		{"Short_4digits", "1234"},
		{"Medium_10digits", "1234567890"},
		{"Long_16digits", "1234567890123456"},
		{"SSN_Format", "123-45-6789"},
		{"CreditCard_Format", "4532-1234-5678-9010"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tokenized, err := primitive.Tokenize(tc.plaintext)
				if err != nil {
					b.Fatalf("Tokenize failed: %v", err)
				}
				_, err = primitive.Detokenize(tokenized, tc.plaintext)
				if err != nil {
					b.Fatalf("Detokenize failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkKeySizes benchmarks performance with different key sizes
func BenchmarkKeySizes(b *testing.B) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		b.Fatalf("Failed to register KeyManager: %v", err)
	}

	plaintext := "1234567890"
	tweak := []byte("benchmark-tweak")

	keySizes := []struct {
		name string
		tmpl func() *tink_go_proto.KeyTemplate
	}{
		{"AES128", KeyTemplateAES128},
		{"AES192", KeyTemplateAES192},
		{"AES256", KeyTemplateAES256},
	}

	for _, ks := range keySizes {
		b.Run(ks.name, func(b *testing.B) {
			handle, err := keyset.NewHandle(ks.tmpl())
			if err != nil {
				b.Fatalf("Failed to create keyset handle: %v", err)
			}

			primitive, err := New(handle, tweak)
			if err != nil {
				b.Fatalf("Failed to create FPE primitive: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := primitive.Tokenize(plaintext)
				if err != nil {
					b.Fatalf("Tokenize failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkTweakVariations benchmarks performance with different tweak sizes
func BenchmarkTweakVariations(b *testing.B) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		b.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		b.Fatalf("Failed to create keyset handle: %v", err)
	}

	plaintext := "1234567890"

	tweaks := []struct {
		name  string
		value []byte
	}{
		{"Empty", []byte("")},
		{"Short_8bytes", []byte("short")},
		{"Medium_16bytes", []byte("medium-tweak-16")},
		{"Long_32bytes", []byte("very-long-tweak-value-32bytes")},
		{"VeryLong_64bytes", make([]byte, 64)},
	}

	// Initialize the very long tweak
	cryptorand.Read(tweaks[4].value)

	for _, tw := range tweaks {
		b.Run(tw.name, func(b *testing.B) {
			primitive, err := New(handle, tw.value)
			if err != nil {
				b.Fatalf("Failed to create FPE primitive: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := primitive.Tokenize(plaintext)
				if err != nil {
					b.Fatalf("Tokenize failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkConcurrent benchmarks concurrent operations
func BenchmarkConcurrent(b *testing.B) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		b.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		b.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("benchmark-tweak")
	primitive, err := New(handle, tweak)
	if err != nil {
		b.Fatalf("Failed to create FPE primitive: %v", err)
	}

	plaintext := "1234567890"

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := primitive.Tokenize(plaintext)
			if err != nil {
				b.Fatalf("Tokenize failed: %v", err)
			}
		}
	})
}

// BenchmarkRandomInputs benchmarks with random inputs (more realistic workload)
func BenchmarkRandomInputs(b *testing.B) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		b.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		b.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("benchmark-tweak")
	primitive, err := New(handle, tweak)
	if err != nil {
		b.Fatalf("Failed to create FPE primitive: %v", err)
	}

	// Pre-generate random inputs
	inputs := make([]string, 1000)
	for i := range inputs {
		inputs[i] = generateRandomNumericString(10)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := inputs[i%len(inputs)]
		_, err := primitive.Tokenize(input)
		if err != nil {
			b.Fatalf("Tokenize failed: %v", err)
		}
	}
}

// BenchmarkFormatPreservation benchmarks format-preserved inputs vs plain numeric
func BenchmarkFormatPreservation(b *testing.B) {
	_, err := getOrRegisterKeyManager()
	if err != nil {
		b.Fatalf("Failed to register KeyManager: %v", err)
	}

	handle, err := keyset.NewHandle(KeyTemplate())
	if err != nil {
		b.Fatalf("Failed to create keyset handle: %v", err)
	}

	tweak := []byte("benchmark-tweak")
	primitive, err := New(handle, tweak)
	if err != nil {
		b.Fatalf("Failed to create FPE primitive: %v", err)
	}

	benchmarks := []struct {
		name      string
		plaintext string
	}{
		{"Numeric_Only", "1234567890"},
		{"SSN_Format", "123-45-6789"},
		{"CreditCard_Format", "4532-1234-5678-9010"},
		{"Phone_Format", "555-123-4567"},
		{"Email_Format", "user@domain.com"},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := primitive.Tokenize(bm.plaintext)
				if err != nil {
					b.Fatalf("Tokenize failed: %v", err)
				}
			}
		})
	}
}
