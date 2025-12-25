package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/vdparikh/fpe/tinkfpe"
)

// This example demonstrates proper Tink integration using keyset.Handle
func main() {
	// Step 0: Register the FPE KeyManager with Tink's registry
	// In production, this would typically be done at application startup
	keyManager := tinkfpe.NewKeyManager()
	if err := registry.RegisterKeyManager(keyManager); err != nil {
		log.Fatalf("Failed to register FPE KeyManager: %v", err)
	}

	// Step 1: Load existing keyset or create a new one
	// This ensures tokens remain consistent across runs (same key = same tokens)
	keysetFile := "fpe_keyset.json"
	var handle *keyset.Handle
	var err error

	if _, err := os.Stat(keysetFile); err == nil {
		// Keyset file exists - load it to maintain consistency
		handle, err = loadKeyset(keysetFile)
		if err != nil {
			log.Fatalf("Failed to load existing keyset: %v", err)
		}
		fmt.Printf("✓ Loaded existing keyset from: %s (tokens will be consistent)\n", keysetFile)
	} else {
		// Keyset file doesn't exist - create a new one
		handle, err = keyset.NewHandle(tinkfpe.KeyTemplate())
		if err != nil {
			log.Fatalf("Failed to create keyset handle: %v", err)
		}
		fmt.Println("✓ Created new keyset handle using KeyTemplate()")

		// Store the keyset to file for future use
		// For examples/testing, we use insecurecleartextkeyset (unencrypted)
		// WARNING: In production, use encrypted keysets with KMS or AEAD
		if err := storeKeyset(handle, keysetFile); err != nil {
			log.Fatalf("Failed to store keyset: %v", err)
		}
		fmt.Printf("✓ Keyset stored to: %s (will be reused in future runs)\n", keysetFile)
	}

	// Step 3: Create FPE primitive from keyset handle (following Tink's pattern)
	tweak := []byte("tenant-1234|customer.ssn")
	fpePrimitive, err := tinkfpe.New(handle, tweak)
	if err != nil {
		log.Fatalf("Failed to create FPE primitive: %v", err)
	}

	// Step 4: Use the primitive
	plaintext := "123-45-6789"
	tokenized, err := fpePrimitive.Tokenize(plaintext)
	if err != nil {
		log.Fatalf("Failed to tokenize: %v", err)
	}

	detokenized, err := fpePrimitive.Detokenize(tokenized, plaintext)
	if err != nil {
		log.Fatalf("Failed to detokenize: %v", err)
	}

	fmt.Printf("Plaintext:   %s\n", plaintext)
	fmt.Printf("Tokenized:   %s\n", tokenized)
	fmt.Printf("Detokenized: %s\n", detokenized)
	fmt.Printf("Match:       %v\n", plaintext == detokenized)
}

// storeKeyset saves a keyset handle to a file.
// For examples/testing, this uses insecurecleartextkeyset (unencrypted).
// WARNING: In production, use encrypted keysets with keyset.Write() and an AEAD.
func storeKeyset(handle *keyset.Handle, filename string) error {
	// Create a file writer
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write the keyset to file (unencrypted for examples)
	// In production, use: handle.Write(writer, aead) with encryption
	writer := keyset.NewJSONWriter(file)
	return insecurecleartextkeyset.Write(handle, writer)
}

// loadKeyset loads a keyset handle from a file.
// For examples/testing, this uses insecurecleartextkeyset (unencrypted).
// WARNING: In production, use encrypted keysets with keyset.Read() and an AEAD.
func loadKeyset(filename string) (*keyset.Handle, error) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read the keyset from file (unencrypted for examples)
	// In production, use: keyset.Read(reader, aead) with decryption
	reader := keyset.NewJSONReader(file)
	return insecurecleartextkeyset.Read(reader)
}
