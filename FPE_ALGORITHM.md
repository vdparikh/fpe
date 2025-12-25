# Understanding Format-Preserving Encryption (FPE) FF1

A simplified guide to understanding the FF1 algorithm and how it works.

## What is Format-Preserving Encryption?

**Format-Preserving Encryption (FPE)** is a special type of encryption that produces ciphertext in the **same format** as the plaintext.

### Example

```
Plaintext:  123-45-6789  (SSN format)
Ciphertext: 972-22-7396  (Still SSN format!)
```

Notice how:
- ✅ The hyphens stay in the same positions
- ✅ The output is still 9 digits with hyphens
- ✅ It looks like a valid SSN format
- ✅ But the actual numbers are encrypted

## Why is FPE Useful?

### 1. **Tokenization**
Replace sensitive data with tokens that look like the original:
- Credit card: `4532-1234-5678-9010` → `7891-2345-6789-0123`
- Phone: `555-123-4567` → `234-567-8901`

### 2. **Database Compatibility**
Encrypt data without changing:
- Column types (still VARCHAR, still numeric)
- Data length (same number of characters)
- Format constraints (still matches validation rules)

### 3. **Legacy System Integration**
Work with systems that expect specific formats:
- APIs that validate SSN format
- Forms that check credit card patterns
- Reports that need consistent formatting

## How Does FF1 Work?

FF1 (Format-Preserving Encryption, method 1) is a NIST-standardized algorithm. Here's how it works in simple terms:

### The Big Picture

```
Input:  "123-45-6789"
   ↓
1. Separate format from data: "123456789" (data) + positions of "-" (format)
   ↓
2. Convert to numbers: [1, 2, 3, 4, 5, 6, 7, 8, 9]
   ↓
3. Encrypt using Feistel network (10 rounds)
   ↓
4. Convert back to characters: [9, 7, 2, 2, 2, 7, 3, 9, 6]
   ↓
5. Reconstruct with format: "972-22-7396"
   ↓
Output: "972-22-7396"
```

### Key Concepts

#### 1. **Feistel Network** (The Core Encryption)

Think of it like shuffling a deck of cards in rounds:

```
Round 1: Split deck in half → Shuffle left with right
Round 2: Swap halves → Shuffle again
Round 3: Swap halves → Shuffle again
... (10 rounds total)
```

In FF1:
- **Input** is split into two halves: `A` and `B`
- Each round: `A_new = B_old`, `B_new = (A_old + F(B_old)) mod radix`
- After 10 rounds, you get the encrypted result

#### 2. **The F Function** (The Shuffling Mechanism)

The `F` function is what actually "shuffles" the data:

```
F(B) = AES_encrypt(special_input) → convert to numbers
```

It uses AES encryption internally, but converts the result to match the input format.

#### 3. **Tweak** (Domain Separation)

A **tweak** is like a "salt" that ensures the same input produces different outputs in different contexts:

```
Same SSN + Different tweaks = Different tokens

"123-45-6789" + tweak="tenant-A" → "972-22-7396"
"123-45-6789" + tweak="tenant-B" → "145-89-2341"
```

This is useful for:
- Multi-tenant systems (different tokens per tenant)
- Different tables (same SSN, different tokens)
- Time-based rotation (change tweak to rotate tokens)

#### 4. **Radix** (The Alphabet Size)

The **radix** is the number of possible characters:

- **Radix 10**: Only digits (0-9) → `"1234567890"`
- **Radix 36**: Digits + lowercase (0-9, a-z) → `"abc123xyz"`
- **Radix 62**: Digits + lowercase + uppercase (0-9, a-z, A-Z) → `"ABC123xyz"`

FF1 automatically detects the radix from your input.

## Step-by-Step: How FF1 Encrypts "1234567890"

Let's trace through a simplified example:

### Step 1: Input Analysis
```
Input: "1234567890"
Length: 10 characters
Radix: 10 (only digits 0-9)
Alphabet: "0123456789"
```

### Step 2: Convert to Numbers
```
"1234567890" → [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
```

### Step 3: Split in Half
```
Left (A):  [1, 2, 3, 4, 5]   (5 elements)
Right (B): [6, 7, 8, 9, 0]   (5 elements)
```

### Step 4: Feistel Rounds (10 rounds)

**Round 1:**
```
A_old = [1, 2, 3, 4, 5]
B_old = [6, 7, 8, 9, 0]

Compute F(B_old) → [7, 3, 1, 9, 2]  (simplified example)
A_new = B_old = [6, 7, 8, 9, 0]
B_new = (A_old + F(B_old)) mod 10
      = ([1,2,3,4,5] + [7,3,1,9,2]) mod 10
      = [8, 5, 4, 3, 7]
```

**Round 2:**
```
A_old = [6, 7, 8, 9, 0]  (was B from round 1)
B_old = [8, 5, 4, 3, 7]  (was B_new from round 1)
... (continue for 10 rounds)
```

### Step 5: Combine and Convert Back
```
After 10 rounds:
A_final = [3, 0, 4, 7, 5]
B_final = [2, 3, 6, 8, 3]

Combine: [3, 0, 4, 7, 5, 2, 3, 6, 8, 3]
Convert: "3047523683"
```

### Step 6: Format Preservation (if applicable)

If input was `"123-45-6789"`:
```
Data encrypted: "3047523683"
Format positions: hyphens at positions 3 and 6
Reconstruct: "304-75-2368"
```

## Security Properties

### 1. **Deterministic**
Same input + same key + same tweak = same output
```
"123-45-6789" + key + "tenant-A" → Always "972-22-7396"
```

### 2. **Reversible**
Encryption and decryption are perfect inverses:
```
Encrypt("123-45-6789") → "972-22-7396"
Decrypt("972-22-7396") → "123-45-6789"
```

### 3. **Format Preserving**
Output always matches input format:
```
SSN format in → SSN format out
Credit card format in → Credit card format out
```

### 4. **Domain Separation**
Different tweaks produce different outputs:
```
Same input + different tweaks = different outputs
```

## Important Constraints

### 1. **Minimum Domain Size**
For security, the domain must be large enough:
```
Domain size = radix^length

Example:
- Radix 10, length 3: 10^3 = 1,000 ✓ (OK)
- Radix 10, length 2: 10^2 = 100 ✗ (Too small, minimum is 1,000)
- Radix 2, length 9: 2^9 = 512 ✗ (Too small)
- Radix 2, length 10: 2^10 = 1,024 ✓ (OK)
```

**Why?** Small domains are vulnerable to brute force attacks.

### 2. **Key Size**
Keys must be 16, 24, or 32 bytes (AES-128, AES-192, or AES-256):
```
16 bytes = AES-128 (minimum)
24 bytes = AES-192
32 bytes = AES-256 (recommended)
```

### 3. **Input Length**
Maximum practical length is ~100,000 characters (to prevent resource exhaustion).

## Real-World Example: Tokenizing SSNs

```go
// Setup
key := [...] // 32-byte AES-256 key
tweak := []byte("tenant-1234|customer.ssn")

// Create FPE instance
fpe, err := tinkfpe.New(keysetHandle, tweak)

// Tokenize
ssn := "123-45-6789"
token, err := fpe.Tokenize(ssn)
// token = "972-22-7396" (same format!)

// Detokenize (recover original)
original, err := fpe.Detokenize(token, ssn)
// original = "123-45-6789"
```

## How Our Implementation Works

### Package Structure

```
fpe/
├── subtle/          # Core FF1 algorithm (low-level)
│   ├── ff1.go      # Feistel network, encryption/decryption
│   └── numeric.go  # Number conversions (numradix)
├── tinkfpe/        # Tink integration (high-level)
│   ├── key_manager.go    # Key management
│   └── fpe_factory.go    # Creates FPE primitives
└── format.go         # Format preservation utilities
```

### Encryption Flow

1. **Input**: `"123-45-6789"`
2. **Format Detection**: Separates `"123456789"` (data) from `"-"` positions
3. **Alphabet Detection**: Detects radix 10 (numeric)
4. **Numeric Conversion**: `"123456789"` → `[1,2,3,4,5,6,7,8,9]`
5. **FF1 Encryption**: 10 Feistel rounds with AES
6. **Numeric Conversion**: `[9,7,2,2,2,7,3,9,6]` → `"972227396"`
7. **Format Reconstruction**: `"972227396"` + format → `"972-22-7396"`

### Key Features

- ✅ **NIST SP 800-38G Compliant**: Follows the official standard
- ✅ **Tink Integration**: Works with Google Tink key management
- ✅ **Automatic Format Detection**: Handles SSNs, credit cards, emails, etc.
- ✅ **Thread-Safe**: Can be used concurrently
- ✅ **Production-Ready**: Comprehensive tests, benchmarks, security validation

## Common Use Cases

### 1. **Payment Tokenization**
```
Credit Card: 4532-1234-5678-9010
Token:       7891-2345-6789-0123
→ Store token in database, keep original encrypted elsewhere
```

### 2. **PII Masking**
```
SSN:     123-45-6789
Token:   972-22-7396
→ Use token for testing, development, analytics
```

### 3. **Multi-Tenant Data Isolation**
```
Same SSN + tenant-A tweak → Token-A
Same SSN + tenant-B tweak → Token-B
→ Each tenant sees different tokens for same data
```

## Summary

**FF1 Format-Preserving Encryption:**
- ✅ Encrypts data while preserving format
- ✅ Uses Feistel network (10 rounds) with AES
- ✅ Supports tweaks for domain separation
- ✅ Automatically handles various formats (SSN, credit cards, etc.)
- ✅ Deterministic and reversible
- ✅ NIST-standardized and secure

**Key Takeaway:** FF1 lets you encrypt sensitive data (like SSNs, credit cards) while keeping the output in the same format, making it perfect for tokenization and database encryption without schema changes.

## Further Reading

- **NIST SP 800-38G**: [Official FF1 Specification](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
- **Test Vectors**: See `testdata/wycheproof_ff1_vectors.json` for official NIST test cases
- **Implementation Details**: See `REVIEW.md` for compliance documentation

