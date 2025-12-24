# Format-Preserving Encryption (FPE) Package

This package implements Format-Preserving Encryption using the FF1 algorithm, as specified in NIST SP 800-38G.

**Tink-Compatible**: While Tink doesn't natively support FPE, this package provides a Tink-compatible primitive interface (`fpe.FPE`) that follows Tink's design patterns and integrates seamlessly with Tink's key management system. This allows FPE to work with Tink KMS clients and key management, just like Tink's built-in primitives (AEAD, MAC, etc.).

## Overview

Format-Preserving Encryption (FPE) allows you to encrypt data while preserving its original format. For example, encrypting a Social Security Number `123-45-6789` will produce another value in the same format, such as `987-65-4321`, where the hyphens remain in the same positions.

This is particularly useful for:
- **Tokenization**: Replacing sensitive data with tokens that look like the original
- **Database encryption**: Encrypting data without changing column types or sizes
- **Compliance**: Maintaining data formats required by legacy systems

## Features

- ✅ **NIST SP 800-38G FF1 Algorithm**: Implements the standardized FF1 format-preserving encryption
- ✅ **Tink-Compatible**: Provides `fpe.FPE` interface that follows Tink's primitive patterns
- ✅ **Format Preservation**: Automatically preserves format characters (hyphens, dots, colons, @ signs, etc.)
- ✅ **Alphabet Detection**: Automatically detects the character set (numeric, alphanumeric) from input data
- ✅ **Provider-Agnostic**: Works with any key management system (just provide a key and tweak)
- ✅ **Deterministic**: Same plaintext + tweak + key = same ciphertext

## Installation

```bash
go get github.com/vdparikh/fpe
```

## Usage

### Tink-Compatible Example (Recommended)

This example follows Tink's pattern: get key → create primitive → use it.

```go
package main

import (
    "fmt"
    "log"
    "github.com/vdparikh/fpe"
)

func main() {
    // Step 1: Get your encryption key (from KMS, HSM, etc.)
    key := []byte("your-encryption-key-32-bytes-long!")
    
    // Step 2: Create FPE primitive (like getting primitive from Tink keyset handle)
    tweak := []byte("tenant-1234|customer.ssn")
    fpePrimitive, err := fpe.NewTinkFPE(key, tweak)
    if err != nil {
        log.Fatal(err)
    }
    
    // Step 3: Use the primitive (just like Tink!)
    plaintext := "123-45-6789"
    tokenized, err := fpePrimitive.Tokenize(plaintext)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Tokenized: %s\n", tokenized)
    
    detokenized, err := fpePrimitive.Detokenize(tokenized, plaintext)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Detokenized: %s\n", detokenized)
}
```

### Standalone Example

For direct use without Tink patterns:

```go
package main

import (
    "fmt"
    "log"
    "github.com/vdparikh/byok/pkg/fpe"
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
    
    // Standalone API takes 3 parameters (includes explicit alphabet)
    detokenized, err := fpeInstance.Detokenize(tokenized, plaintext, "")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Tokenized: %s, Detokenized: %s\n", tokenized, detokenized)
}
```

### Supported Formats

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

## API Reference

### Tink-Compatible API (Recommended)

#### `NewTinkFPE(key, tweak []byte) (FPE, error)`

Creates a new Tink-compatible FPE primitive.

- **key**: Encryption key (minimum 16 bytes, preferably 32 bytes for AES-256)
- **tweak**: Public, non-secret value for domain separation
- **Returns**: FPE interface (Tink-compatible) or error

#### `FPE` Interface

The `fpe.FPE` interface follows Tink's primitive pattern:

```go
type FPE interface {
    Tokenize(plaintext string) (string, error)
    Detokenize(tokenized string, originalPlaintext string) (string, error)
}
```

- **`Tokenize(plaintext string)`**: Encrypts plaintext while preserving format
- **`Detokenize(tokenized, originalPlaintext string)`**: Decrypts tokenized value. The `originalPlaintext` parameter is used for alphabet detection to ensure consistency.

### Standalone API

#### `NewFF1(key, tweak []byte) (*FF1, error)`

Creates a new FF1 FPE instance (standalone, not Tink-compatible).

- **key**: Encryption key (minimum 16 bytes, preferably 32 bytes for AES-256)
- **tweak**: Public, non-secret value for domain separation
- **Returns**: FF1 instance or error

#### `Tokenize(plaintext string) (string, error)`

Encrypts plaintext using format-preserving encryption.

- **plaintext**: Input string to encrypt
- **Returns**: Tokenized (encrypted) string with preserved format

#### `Detokenize(tokenized, originalPlaintext, alphabet string) (string, error)`

Decrypts tokenized value using format-preserving encryption.

- **tokenized**: Tokenized string to decrypt
- **originalPlaintext**: Original plaintext (used for alphabet detection)
- **alphabet**: Explicit alphabet (if empty, detected from originalPlaintext)
- **Returns**: Decrypted plaintext string

## Algorithm Details

The implementation uses a Feistel network with 10 rounds, following NIST SP 800-38G:

1. **Format Separation**: Separates format characters from data characters
2. **Alphabet Detection**: Determines the character set (numeric, alphanumeric)
3. **Numeric Conversion**: Converts data characters to numeric representation
4. **Feistel Network**: Applies 10 rounds of encryption/decryption
5. **Format Reconstruction**: Reconstructs the output with format characters preserved

## Security Considerations

- **Key Management**: Always use a secure key management system (HSM, KMS, etc.)
- **Tweak Selection**: Use domain-specific tweaks (e.g., tenant ID, table name) for better security
- **Key Size**: Use at least 32-byte keys (AES-256) for production
- **Deterministic Encryption**: FF1 is deterministic (same input = same output), which may not be suitable for all use cases

## License

This package is open source. See the main repository for license details.

## References

- [NIST SP 800-38G: Format-Preserving Encryption](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
- [FF1 Algorithm Specification](https://csrc.nist.gov/publications/detail/sp/800-38g/final)

