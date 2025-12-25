# Format-Preserving Encryption (FPE) for Google Tink

[![Test](https://github.com/vdparikh/fpe/actions/workflows/test.yml/badge.svg)](https://github.com/vdparikh/fpe/actions/workflows/test.yml)

An **opinionated Google Tink implementation** of Format-Preserving Encryption (FPE) using the FF1 algorithm, as specified in NIST SP 800-38G.

This package provides a first-class Tink primitive that integrates seamlessly with Tink's key management system, following Tink's design patterns and conventions.

## Overview

Format-Preserving Encryption (FPE) allows you to encrypt data while preserving its original format. For example, encrypting a Social Security Number `123-45-6789` will produce another value in the same format, such as `972-22-7396`, where the hyphens remain in the same positions.

This is particularly useful for:
- **Tokenization**: Replacing sensitive data with tokens that look like the original
- **Database encryption**: Encrypting data without changing column types or sizes
- **Compliance**: Maintaining data formats required by legacy systems

## Features

- ✅ **NIST SP 800-38G FF1 Algorithm**: Full implementation of the standardized FF1 format-preserving encryption
- ✅ **First-Class Tink Integration**: Native Tink primitive with `KeyManager` support and `keyset.Handle` integration
- ✅ **Tink Design Patterns**: Follows Tink's primitive patterns, similar to `DeterministicAEAD`
- ✅ **Format Preservation**: Automatically preserves format characters (hyphens, dots, colons, @ signs, etc.)
- ✅ **Alphabet Detection**: Automatically detects the character set (numeric, alphanumeric) from input data
- ✅ **Deterministic**: Same plaintext + tweak + key = same ciphertext (like Tink's `DeterministicAEAD`)

## Installation

```bash
go get github.com/vdparikh/fpe
```

## Usage

### Tink Integration (Recommended)

This package follows Tink's standard pattern: **register KeyManager → create keyset handle → get primitive → use it**.

```go
package main

import (
	"fmt"
	"log"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/vdparikh/fpe/tinkfpe"
)

func main() {
	// Step 1: Register the FPE KeyManager with Tink's registry
	// In production, do this at application startup
	keyManager := tinkfpe.NewKeyManager()
	if err := registry.RegisterKeyManager(keyManager); err != nil {
		log.Fatalf("Failed to register FPE KeyManager: %v", err)
	}

	// Step 2: Create a keyset handle using KeyTemplate() (one line!)
	// This generates a secure random key automatically (AES-256 by default)
	handle, err := keyset.NewHandle(tinkfpe.KeyTemplate())
	if err != nil {
		log.Fatalf("Failed to create keyset handle: %v", err)
	}

	// Step 3: Get FPE primitive from keyset handle (just like any Tink primitive!)
	tweak := []byte("tenant-1234|customer.ssn")
	primitive, err := tinkfpe.New(handle, tweak)
	if err != nil {
		log.Fatalf("Failed to create FPE primitive: %v", err)
	}

	// Step 4: Use the primitive
	plaintext := "123-45-6789"
	tokenized, err := primitive.Tokenize(plaintext)
	if err != nil {
		log.Fatalf("Failed to tokenize: %v", err)
	}
	fmt.Printf("Tokenized: %s\n", tokenized)

	detokenized, err := primitive.Detokenize(tokenized, plaintext)
	if err != nil {
		log.Fatalf("Failed to detokenize: %v", err)
	}
	fmt.Printf("Detokenized: %s\n", detokenized)
}
```

### Standalone API (For Non-Tink Use Cases)

If you're not using Tink, you can use the standalone API:

```go
package main

import (
	"fmt"
	"log"
	"github.com/vdparikh/fpe"
)

func main() {
	key := []byte("your-encryption-key-32-bytes-long!")
	tweak := []byte("tenant-1234|customer.ssn")
	
	// Create FPE instance (standalone)
	fpeInstance, err := fpe.NewFF1(key, tweak)
	if err != nil {
		log.Fatal(err)
	}
	
	plaintext := "123-45-6789"
	tokenized, err := fpeInstance.Tokenize(plaintext)
	if err != nil {
		log.Fatal(err)
	}
	
	detokenized, err := fpeInstance.Detokenize(tokenized, plaintext, "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Tokenized: %s, Detokenized: %s\n", tokenized, detokenized)
}
```

## Package Structure

This package follows Tink's organizational patterns:

- **`fpe/`** (root): High-level API and public interfaces
  - `fpe.FPE`: Tink-compatible interface (similar to `DeterministicAEAD`)
  - `fpe.NewFF1()`: Standalone constructor for non-Tink use cases
  
- **`fpe/tinkfpe/`**: Tink integration layer
  - `tinkfpe.New()`: Factory function to create FPE primitives from `keyset.Handle`
  - `tinkfpe.KeyTemplate()`: Creates a key template for easy key generation (one line!)
  - `tinkfpe.KeyManager`: Tink `KeyManager` implementation for FPE keys
  
- **`fpe/subtle/`**: Low-level cryptographic primitives
  - Core NIST FF1 algorithm implementation (raw keys)
  - Not intended for direct use by most users

## API Reference

### Tink API (Recommended)

#### `tinkfpe.KeyTemplate() *tink_go_proto.KeyTemplate`

Creates a key template for FPE FF1 keys. This is the easiest way to generate keys:

```go
handle, err := keyset.NewHandle(tinkfpe.KeyTemplate())
```

The default template generates AES-256 keys (32 bytes). For different key sizes:
- `tinkfpe.KeyTemplateAES128()` - AES-128 (16 bytes)
- `tinkfpe.KeyTemplateAES192()` - AES-192 (24 bytes)  
- `tinkfpe.KeyTemplateAES256()` - AES-256 (32 bytes, recommended)

#### `tinkfpe.NewKeysetHandleFromKey(key []byte) (*keyset.Handle, error)`

Creates a keyset handle from a raw key (e.g., from an HSM or custom key management system). This is useful when you have a key from a system that isn't a standard Tink KMS client.

- **key**: Raw key bytes (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
- **Returns**: `*keyset.Handle` or error

Example:

```go
// Get key from your HSM or key management system
hsmKey := []byte{...} // 32-byte key

// Create keyset handle from the raw key
handle, err := tinkfpe.NewKeysetHandleFromKey(hsmKey)
if err != nil {
    log.Fatal(err)
}

// Use it with FPE
primitive, err := tinkfpe.New(handle, []byte("tweak"))
```

**Note**: This creates an unencrypted keyset. In production, consider encrypting the keyset before storing it using `keyset.Write()` with an AEAD.

#### `tinkfpe.New(handle *keyset.Handle, tweak []byte) (fpe.FPE, error)`

Creates a new FPE primitive from a Tink keyset handle. This follows Tink's standard pattern.

- **handle**: Tink keyset handle (from `keyset.NewHandle(tinkfpe.KeyTemplate())`, `tinkfpe.NewKeysetHandleFromKey()`, or KMS)
- **tweak**: Public, non-secret value for domain separation (e.g., tenant ID, table name)
- **Returns**: `fpe.FPE` interface (Tink-compatible) or error

#### `fpe.FPE` Interface

The `fpe.FPE` interface follows Tink's primitive pattern, similar to `tink.DeterministicAEAD`:

```go
type FPE interface {
    Tokenize(plaintext string) (string, error)
    Detokenize(tokenized string, originalPlaintext string) (string, error)
}
```

- **`Tokenize(plaintext string)`**: Encrypts plaintext while preserving format. Deterministic: same input always produces same output.
- **`Detokenize(tokenized, originalPlaintext string)`**: Decrypts tokenized value. The `originalPlaintext` parameter is used for alphabet detection to ensure consistency.

#### `tinkfpe.KeyManager`

The `KeyManager` implements Tink's `registry.KeyManager` interface, allowing FPE to be registered with Tink's registry:

```go
keyManager := tinkfpe.NewKeyManager()
registry.RegisterKeyManager(keyManager)
```

### Standalone API

#### `fpe.NewFF1(key, tweak []byte) (*fpe.FF1, error)`

Creates a new FF1 FPE instance (standalone, not Tink-compatible).

- **key**: Encryption key (minimum 16 bytes, preferably 32 bytes for AES-256)
- **tweak**: Public, non-secret value for domain separation
- **Returns**: `*fpe.FF1` instance or error

#### `(*fpe.FF1) Tokenize(plaintext string) (string, error)`

Encrypts plaintext using format-preserving encryption.

#### `(*fpe.FF1) Detokenize(tokenized, originalPlaintext, alphabet string) (string, error)`

Decrypts tokenized value using format-preserving encryption.

## Supported Formats

The FPE implementation automatically handles various data formats:

- **SSN**: `123-45-6789`
- **Credit Cards**: `4532-1234-5678-9010`
- **Phone Numbers**: `555-123-4567`
- **Email Addresses**: `user@domain.com`
- **Dates**: `2024-03-15` or `03-15-2024`
- **Times**: `14:30:45`
- **IP Addresses**: `192.168.1.1`
- **UUIDs**: `550e8400-e29b-41d4-a716-446655440000`
- **Alphanumeric**: `ABC123XYZ`

Format characters (hyphens, dots, colons, @ signs) are automatically preserved in their original positions.

## Algorithm Details

The implementation uses a Feistel network with 10 rounds, following NIST SP 800-38G:

1. **Format Separation**: Separates format characters from data characters
2. **Alphabet Detection**: Determines the character set (numeric, alphanumeric)
3. **Numeric Conversion**: Converts data characters to numeric representation
4. **Feistel Network**: Applies 10 rounds of encryption/decryption using AES
5. **Format Reconstruction**: Reconstructs the output with format characters preserved

## Testing

This package includes comprehensive test coverage:

- **Wycheproof Test Suite**: 57+ test cases covering NIST test vectors, edge cases, invalid inputs, and security properties
- **NIST Compliance**: All official NIST SP 800-38G test vectors pass
- **Key Manager Tests**: Verifies Tink integration with serialized keysets
- **Format Preservation**: Tests verify format characters are preserved across various data types
- **Cryptographic Property Tests**: Comprehensive tests for collision resistance, bijectivity, key/tweak sensitivity, distribution, and determinism

### Test Suites

#### Wycheproof Test Suite
Validates NIST compliance and edge cases:
```bash
go test ./tinkfpe -v -run TestWycheproofVectors
```

#### Cryptographic Properties
Tests fundamental cryptographic properties:
```bash
go test ./tinkfpe -v -run "TestCollision|TestAvalanche|TestBijectivity|TestKeySensitivity|TestTweakSensitivity|TestDistribution|TestDeterminism"
```

**Test Coverage:**
- **Collision Resistance**: 1,000+ test cases verifying no two different inputs produce the same output
- **Bijectivity**: 10,000 exhaustive tests ensuring one-to-one mapping
- **Key Sensitivity**: Verifies different keys produce different outputs
- **Tweak Sensitivity**: Verifies different tweaks produce different outputs
- **Distribution**: Statistical tests for uniform output distribution
- **Determinism**: Ensures same input + key + tweak = same output
- **Avalanche Effect**: Verifies small input changes produce different outputs

#### Performance Benchmarks
Measure performance characteristics:
```bash
go test ./tinkfpe -bench=. -benchmem
```

```bash
# run specific benchmarks
go test ./tinkfpe -bench=BenchmarkTokenize -benchmem
go test ./tinkfpe -bench=BenchmarkRoundTrip -benchmem
```

**Benchmark Coverage:**
- **Tokenize Performance**: Various input sizes (4-20 characters) and formats
- **Detokenize Performance**: Decryption performance for different input types
- **Round-Trip Performance**: Full encrypt-decrypt cycle timing
- **Key Size Impact**: Performance comparison (AES-128, AES-192, AES-256)
- **Tweak Size Impact**: Performance with different tweak lengths
- **Concurrent Operations**: Parallel execution performance
- **Format Preservation Overhead**: Comparison of formatted vs plain inputs
- **Random Inputs**: Realistic workload performance

Example benchmark output:
```
BenchmarkTokenize/Medium_10digits-10    154780    7754 ns/op    10344 B/op    267 allocs/op
BenchmarkRoundTrip/SSN_Format-10       78923    15123 ns/op    20568 B/op    529 allocs/op
```

#### All Tests
Run all tests (excluding examples):
```bash
go test ./tinkfpe/...
```

Or run tests in the tinkfpe package specifically:
```bash
go test ./tinkfpe -v
```

## Requirements

- **Go**: 1.18 or later
- **Tink**: v1.7.0 or later (for Tink integration)
- **Dependencies**: See `go.mod` for complete dependency list

## Thread Safety

The FPE implementation is **thread-safe** and can be used concurrently by multiple goroutines. Each `FF1` instance and `fpe.FPE` primitive is safe for concurrent use, as operations do not modify internal state.

**Note**: While individual operations are thread-safe, you should use separate primitive instances for different tweaks or keys to ensure proper domain separation.

## Security Considerations

- **Key Management**: Always use Tink's key management system (KMS, HSM, etc.) via `keyset.Handle`. Never use raw `[]byte` keys in production.
- **Tweak Selection**: Use domain-specific tweaks (e.g., tenant ID, table name) for better security and domain separation
- **Key Size**: Use at least 32-byte keys (AES-256) for production. The default `KeyTemplate()` generates AES-256 keys.
- **Deterministic Encryption**: FF1 is deterministic (same input = same output), which is suitable for tokenization but may not be suitable for all use cases (e.g., where semantic security is required).
- **Domain Size**: The implementation enforces a minimum domain size of 1000 (radix^n ≥ 1000) for security. Very small domains (e.g., single characters) will be rejected.
- **Tink Integration**: This package is designed to work with Tink's security best practices - always use encrypted keysets in production. The `insecurecleartextkeyset` package is only for examples and testing.

## Limitations

- **Small Domains**: Inputs with very small domain sizes (radix^n < 1000) are rejected for security reasons. This means single-character inputs or very short numeric strings may not be supported.
- **Maximum Input Length**: Inputs longer than 100,000 characters are rejected to prevent resource exhaustion. For most use cases, this limit is far beyond practical needs.
- **Alphabet Detection**: The implementation automatically detects numeric vs. alphanumeric alphabets. For mixed alphabets or custom character sets, you may need to use the standalone API with explicit alphabet specification.
- **Performance**: FPE is computationally more expensive than standard encryption due to the Feistel network and numeric conversions. For high-throughput scenarios, consider performance testing and benchmarking.
- **Deterministic Nature**: FF1 is deterministic, which means the same plaintext always produces the same ciphertext. This is ideal for tokenization but may not provide semantic security in all contexts.
- **Memory Usage**: Large inputs require significant memory for numeric conversions. Inputs approaching the 100k character limit may require substantial memory.
- **Side-Channel Resistance**: This implementation follows NIST SP 800-38G but does not include explicit side-channel countermeasures. For high-security environments, consider additional protections.

## Examples

See the `examples/` directory for complete working examples:

- **`tink_example.go`**: Demonstrates Tink integration with keyset persistence
- **`random.go`**: Shows random test case generation and validation

Run examples:

```bash
go run examples/tink_example.go
go run examples/random.go
```

## Why Tink?

This package is designed as a **first-class Tink primitive** because:

1. **Secure Key Management**: Tink provides secure key management via KMS, HSM, and encrypted keysets. Keys are never exposed as raw `[]byte` in your application code - they're managed through `keyset.Handle`, reducing the risk of key leakage.

2. **Key Rotation**: Tink's keyset system supports seamless key rotation without code changes. You can add new keys to a keyset, mark old keys as deprecated, and Tink automatically uses the primary key while maintaining backward compatibility.

3. **No Raw Keys in Memory**: Unlike raw key management, Tink's `keyset.Handle` abstraction ensures keys are handled securely. Keys can be encrypted at rest, loaded from secure storage (KMS/HSM), and never appear as plain `[]byte` in your application's memory space.

4. **Consistency**: Follows the same patterns as other Tink primitives (`DeterministicAEAD`, `AEAD`, etc.), making it familiar to Tink users and easy to integrate into existing Tink-based systems.

5. **Security Best Practices**: Leverages Tink's battle-tested security practices, including secure key generation, encrypted keyset storage, and protection against common cryptographic pitfalls.

6. **Ecosystem Integration**: Works seamlessly with Tink's ecosystem (KMS clients, key templates, encrypted keysets, etc.), allowing you to leverage existing Tink infrastructure and tooling.

## Compliance & Standards

This implementation is compliant with:

- **NIST SP 800-38G**: Full compliance with the Format-Preserving Encryption standard
- **FF1 Algorithm**: Correct implementation of the FF1 Feistel network with 10 rounds
- **Test Vectors**: Passes all official NIST test vectors and Wycheproof-style test suite

See `REVIEW.md` for detailed compliance documentation.

## Contributing

Contributions are welcome! Please ensure:

- All tests pass (`go test ./tinkfpe/...`)
- Code follows Go conventions and is properly formatted (`gofmt`)
- New features include appropriate tests
- Documentation is updated for API changes

## License

This package is open source. See the main repository for license details.

## References

- [NIST SP 800-38G: Format-Preserving Encryption](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
- [FF1 Algorithm Specification](https://csrc.nist.gov/publications/detail/sp/800-38g/final)
- [Google Tink Documentation](https://developers.google.com/tink)
- [Wycheproof Test Vectors](https://github.com/google/wycheproof)
