# Wycheproof-Style Test Suite for FPE/FF1

## What is Wycheproof?

**Wycheproof** (pronounced "why-check-proof") is a Google project that provides cryptographic test vectors to detect known bugs in cryptographic implementations. It's designed to catch common implementation errors, edge cases, and vulnerabilities.

## Key Characteristics of Wycheproof-Style Tests

1. **Comprehensive Coverage**: Tests cover valid inputs, invalid inputs, edge cases, and known vulnerabilities
2. **Structured JSON Format**: Test vectors are stored in JSON with metadata
3. **Expected Results**: Each test case specifies whether it should pass, fail, or be rejected
4. **Vulnerability-Focused**: Tests are designed to catch specific bugs and weaknesses
5. **Documentation**: Each test case includes comments explaining what it tests

## Test Vector Structure

A Wycheproof-style test vector typically includes:

```json
{
  "algorithm": "FF1",
  "generatorVersion": "1.0",
  "numberOfTests": 100,
  "testGroups": [
    {
      "type": "ValidInput",
      "tests": [
        {
          "tcId": 1,
          "comment": "Normal encryption with AES-128",
          "key": "2B7E151628AED2A6ABF7158809CF4F3C",
          "tweak": "",
          "plaintext": "0123456789",
          "ciphertext": "3047523683",
          "result": "valid"
        }
      ]
    },
    {
      "type": "InvalidKey",
      "tests": [
        {
          "tcId": 2,
          "comment": "Key too short (should be rejected)",
          "key": "2B7E15",
          "tweak": "",
          "plaintext": "0123456789",
          "result": "invalid"
        }
      ]
    }
  ]
}
```

## Test Categories for FPE/FF1

### 1. Valid Input Tests
- Normal encryption/decryption with various key sizes (128, 192, 256 bits)
- Different radix values (10, 36, 62)
- Various input lengths (short, medium, long)
- With and without tweaks
- Different alphabet types (numeric, alphanumeric, mixed case)

### 2. Invalid Key Tests
- Keys too short (< 16 bytes)
- Keys too long (> 32 bytes)
- Keys with invalid sizes (not 16, 24, or 32)
- Null/empty keys
- Keys with all zeros
- Keys with all ones

### 3. Invalid Input Tests
- Empty plaintext
- Plaintext with invalid characters (not in alphabet)
- Plaintext length = 0
- Plaintext length = 1 (edge case for Feistel network)
- Very long plaintexts (boundary conditions)

### 4. Invalid Tweak Tests
- Tweak too long (if there's a limit)
- Tweak with special characters
- Null tweak (should be allowed as empty)

### 5. Edge Cases
- Minimum radix (2)
- Maximum radix (implementation limit)
- Odd-length inputs
- Even-length inputs
- Single character input
- Two character input
- Maximum length input

### 6. Format Preservation Tests
- SSN format (XXX-XX-XXXX)
- Credit card format (XXXX-XXXX-XXXX-XXXX)
- Email format (user@domain.com)
- Phone format (XXX-XXX-XXXX)
- Mixed format strings

### 7. Determinism Tests
- Same plaintext + same key + same tweak = same ciphertext
- Different tweaks produce different ciphertexts
- Different keys produce different ciphertexts

### 8. Round-Trip Tests
- Encrypt then decrypt should recover original
- Multiple encrypt/decrypt cycles
- Decrypt of encrypted value should match original

### 9. Known Vulnerability Tests
- Tests for common FF1 implementation bugs:
  - Incorrect P/Q array construction
  - Wrong numradix encoding
  - Incorrect Feistel round structure
  - Key derivation errors (should not derive per round)
  - Tweak integration errors

### 10. Boundary Condition Tests
- Radix = 2 (binary)
- Radix = 256 (byte-level)
- Input length = 1
- Input length = maximum supported
- Maximum tweak length
- Minimum tweak length (empty)

## Implementation Requirements

### 1. JSON Test Vector File
- Structured format with metadata
- Grouped by test type
- Each test has unique ID, comment, and expected result

### 2. Test Runner
- Loads JSON test vectors
- Iterates through test groups
- Executes each test case
- Validates expected results (pass/fail/reject)
- Reports failures with context

### 3. Test Execution Logic
```go
for each testGroup:
    for each test:
        if test.result == "valid":
            // Should succeed
            result, err := encrypt(test.key, test.tweak, test.plaintext)
            if err != nil {
                reportFailure("Expected success but got error")
            }
            if result != test.ciphertext {
                reportFailure("Ciphertext mismatch")
            }
        else if test.result == "invalid":
            // Should be rejected
            result, err := encrypt(test.key, test.tweak, test.plaintext)
            if err == nil {
                reportFailure("Expected rejection but succeeded")
            }
```

### 4. Documentation
- Explain what each test category covers
- Document known vulnerabilities being tested
- Reference relevant standards and research papers
- Include examples of bugs caught by each test

## Benefits of Wycheproof-Style Tests

1. **Bug Detection**: Catches common implementation errors
2. **Regression Prevention**: Ensures fixes don't break existing functionality
3. **Compliance Verification**: Validates against standards
4. **Security Assurance**: Tests for known vulnerabilities
5. **Cross-Implementation**: Can test multiple implementations
6. **Continuous Integration**: Easy to automate in CI/CD

## Example Test Vector Structure for FPE/FF1

```json
{
  "algorithm": "FF1",
  "generatorVersion": "1.0",
  "numberOfTests": 50,
  "testGroups": [
    {
      "type": "ValidInput",
      "tests": [
        {
          "tcId": 1,
          "comment": "NIST Sample #1: AES-128, empty tweak",
          "key": "2B7E151628AED2A6ABF7158809CF4F3C",
          "tweak": "",
          "plaintext": "0123456789",
          "ciphertext": "3047523683",
          "result": "valid"
        }
      ]
    },
    {
      "type": "InvalidKey",
      "tests": [
        {
          "tcId": 10,
          "comment": "Key too short (8 bytes, minimum is 16)",
          "key": "2B7E151628AED2A6",
          "tweak": "",
          "plaintext": "0123456789",
          "result": "invalid"
        }
      ]
    },
    {
      "type": "EdgeCase",
      "tests": [
        {
          "tcId": 20,
          "comment": "Single character input (n=1)",
          "key": "2B7E151628AED2A6ABF7158809CF4F3C",
          "tweak": "",
          "plaintext": "0",
          "result": "valid"
        }
      ]
    }
  ]
}
```

## Test Suite Implementation

This package includes a comprehensive Wycheproof-style test suite located in:

- **Test Vectors**: `testdata/wycheproof_ff1_vectors.json` - 57+ test cases covering all categories
- **Test Runner**: `tinkfpe/wycheproof_test.go` - Automated test execution with detailed reporting
- **Key Manager Tests**: `tinkfpe/key_manager_test.go` - Tests KeyManager with NIST vectors from Wycheproof suite
- **Cryptographic Properties**: `tinkfpe/cryptographic_properties_test.go` - Tests for collision resistance, bijectivity, key/tweak sensitivity, distribution, and determinism

The test suite validates:
- ✅ NIST SP 800-38G compliance (official test vectors)
- ✅ Format preservation across various data formats
- ✅ Deterministic encryption behavior
- ✅ Round-trip correctness
- ✅ Edge cases and boundary conditions
- ✅ Invalid input rejection
- ✅ Key validation
- ✅ Collision resistance (no two inputs produce same output)
- ✅ Bijectivity (one-to-one mapping verified)
- ✅ Key and tweak sensitivity
- ✅ Output distribution uniformity

### Running Tests

**Wycheproof Test Suite:**
```bash
go test ./tinkfpe -v -run TestWycheproofVectors
```

**Cryptographic Property Tests:**
```bash
go test ./tinkfpe -v -run "TestCollision|TestAvalanche|TestBijectivity|TestKeySensitivity|TestTweakSensitivity|TestDistribution|TestDeterminism"
```

**All Tests:**
```bash
go test ./tinkfpe -v
```

### Cryptographic Property Tests

In addition to the Wycheproof-style test suite, this package includes comprehensive tests for fundamental cryptographic properties:

1. **Collision Resistance** (`TestCollisionResistance`): Verifies that different inputs produce different outputs (no collisions). Tests include:
   - Numeric inputs (10 test cases)
   - Format-preserved inputs (8 test cases)
   - Random inputs (1,000 test cases)

2. **Bijectivity** (`TestBijectivity`): Verifies that encryption is a bijection (one-to-one and onto mapping). Tests 10,000 inputs exhaustively to ensure every input maps to a unique output.

3. **Key Sensitivity** (`TestKeySensitivity`): Verifies that different keys produce different outputs for the same input. Tests 10 different keys.

4. **Tweak Sensitivity** (`TestTweakSensitivity`): Verifies that different tweaks produce different outputs for the same input. Tests various tweak values (empty, short, long).

5. **Distribution** (`TestDistribution`): Tests that outputs are well-distributed (not biased). Analyzes digit distribution across 10,000 ciphertexts.

6. **Determinism** (`TestDeterminism`): Verifies that same input + same key + same tweak = same output across multiple primitive instances.

7. **Avalanche Effect** (`TestAvalancheEffect`): Verifies that small changes in input produce different outputs (adjusted for FPE's format-preserving nature).

These tests provide additional confidence in the cryptographic correctness of the implementation beyond the Wycheproof test vectors.

