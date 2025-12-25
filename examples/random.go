package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/vdparikh/fpe/tinkfpe"
)

func main() {
	// Step 1: Register the FPE KeyManager with Tink's registry
	// In production, this would typically be done at application startup
	keyManager := tinkfpe.NewKeyManager()
	if err := registry.RegisterKeyManager(keyManager); err != nil {
		log.Fatalf("Failed to register FPE KeyManager: %v", err)
	}

	// Step 2: Create a keyset handle using the key template (one line!)
	// This is the recommended way - generates a secure random key automatically
	handle, err := keyset.NewHandle(tinkfpe.KeyTemplate())
	if err != nil {
		log.Fatalf("Failed to create keyset handle: %v", err)
	}
	fmt.Println("✓ Created keyset handle using KeyTemplate()")

	// Step 3: Get FPE primitive from keyset handle (following Tink's pattern)
	tweak := []byte("tenant-1234|customer.ssn")
	fpePrimitive, err := tinkfpe.New(handle, tweak)
	if err != nil {
		log.Fatalf("Failed to create FPE primitive: %v", err)
	}

	fmt.Println(strings.Repeat("=", 200))
	fmt.Printf("%-50s | %-50s | %-50s | %s\n", "Plaintext", "Tokenized Value", "Detokenized Value", "Match?")
	fmt.Println(strings.Repeat("-", 200))

	for i := 0; i < 50; i++ {
		plaintext := generateRandomTestCase()
		if len(plaintext) < 4 {
			continue
		}

		// plaintext := "123-45-6789"
		// fmt.Printf("%s |", plaintext)

		tokenized, err := fpePrimitive.Tokenize(plaintext)
		if err != nil {
			fatal("Failed to tokenize", err)
		}
		// fmt.Printf("%s |", tokenized)

		detokenized, err := fpePrimitive.Detokenize(tokenized, plaintext)
		if err != nil {
			fatal("Failed to detokenize", err)
		}
		// fmt.Printf("%s |", detokenized)

		matchStr := ""
		if plaintext == detokenized {
			// fmt.Printf("✓ Passed\n")
			matchStr = "true"
		} else {
			// fmt.Printf("✗ Failed\n", plaintext, detokenized)
			// os.Exit(1)
			matchStr = "false"
		}

		fmt.Printf("%-50s | %-50s | %-50s | %s\n", plaintext, tokenized, detokenized, matchStr)
	}
}

// generateRandomTestCase generates a random test case with various formats
func generateRandomTestCase() string {
	// Random format type - expanded to include more formats
	formatType, _ := rand.Int(rand.Reader, big.NewInt(12))

	switch formatType.Int64() {
	case 0:
		// SSN format: XXX-XX-XXXX
		return fmt.Sprintf("%s-%s-%s",
			randomDigits(3),
			randomDigits(2),
			randomDigits(4))
	case 1:
		// Credit Card format: XXXX-XXXX-XXXX-XXXX
		return fmt.Sprintf("%s-%s-%s-%s",
			randomDigits(4),
			randomDigits(4),
			randomDigits(4),
			randomDigits(4))
	case 2:
		// Phone format: XXX-XXX-XXXX
		return fmt.Sprintf("%s-%s-%s",
			randomDigits(3),
			randomDigits(3),
			randomDigits(4))
	case 3:
		// Alphanumeric: mixed case letters and digits
		length, _ := rand.Int(rand.Reader, big.NewInt(10))
		return randomAlphanumeric(int(length.Int64()) + 5) // 5-14 chars
	case 4:
		// Email prefix: letters.dots
		parts, _ := rand.Int(rand.Reader, big.NewInt(3))
		result := randomLetters(int(parts.Int64()) + 2) // 2-4 chars
		if parts.Int64() > 0 {
			result += "." + randomLetters(int(parts.Int64())+2)
		}
		return result
	case 5:
		// Pure numeric: variable length
		length, _ := rand.Int(rand.Reader, big.NewInt(15))
		return randomDigits(int(length.Int64()) + 5) // 5-19 digits
	case 6:
		// Date format: MM-DD-YYYY
		month, _ := rand.Int(rand.Reader, big.NewInt(12))
		day, _ := rand.Int(rand.Reader, big.NewInt(28))
		year, _ := rand.Int(rand.Reader, big.NewInt(100))
		return fmt.Sprintf("%02d-%02d-%04d",
			int(month.Int64())+1,
			int(day.Int64())+1,
			int(year.Int64())+1950)
	case 7:
		// Date format: YYYY-MM-DD
		year, _ := rand.Int(rand.Reader, big.NewInt(100))
		month, _ := rand.Int(rand.Reader, big.NewInt(12))
		day, _ := rand.Int(rand.Reader, big.NewInt(28))
		return fmt.Sprintf("%04d-%02d-%02d",
			int(year.Int64())+1950,
			int(month.Int64())+1,
			int(day.Int64())+1)
	case 8:
		// Email address: user@domain.com
		userLen, _ := rand.Int(rand.Reader, big.NewInt(8))
		domainLen, _ := rand.Int(rand.Reader, big.NewInt(8))
		user := randomAlphanumeric(int(userLen.Int64()) + 3) // 3-10 chars
		domain := randomLetters(int(domainLen.Int64()) + 3)  // 3-10 chars
		tlds := []string{"com", "org", "net", "edu", "gov", "io", "co"}
		tldIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(tlds))))
		return fmt.Sprintf("%s@%s.%s", user, domain, tlds[tldIdx.Int64()])
	case 9:
		// Time format: HH:MM:SS
		hour, _ := rand.Int(rand.Reader, big.NewInt(24))
		minute, _ := rand.Int(rand.Reader, big.NewInt(60))
		second, _ := rand.Int(rand.Reader, big.NewInt(60))
		return fmt.Sprintf("%02d:%02d:%02d",
			int(hour.Int64()),
			int(minute.Int64()),
			int(second.Int64()))
	case 10:
		// UUID-like format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
		return fmt.Sprintf("%s-%s-%s-%s-%s",
			randomHex(8),
			randomHex(4),
			randomHex(4),
			randomHex(4),
			randomHex(12))
	case 11:
		// IP address format: XXX.XXX.XXX.XXX
		octet1, _ := rand.Int(rand.Reader, big.NewInt(255))
		octet2, _ := rand.Int(rand.Reader, big.NewInt(255))
		octet3, _ := rand.Int(rand.Reader, big.NewInt(255))
		octet4, _ := rand.Int(rand.Reader, big.NewInt(255))
		return fmt.Sprintf("%d.%d.%d.%d",
			int(octet1.Int64()),
			int(octet2.Int64()),
			int(octet3.Int64()),
			int(octet4.Int64()))
	default:
		// Mixed format with hyphens
		length, _ := rand.Int(rand.Reader, big.NewInt(10))
		return randomMixedFormat(int(length.Int64()) + 5)
	}
}

// randomDigits generates a random string of digits
func randomDigits(length int) string {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		digit, _ := rand.Int(rand.Reader, big.NewInt(10))
		result[i] = byte('0' + digit.Int64())
	}
	return string(result)
}

// randomLetters generates a random string of letters (mixed case)
func randomLetters(length int) string {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		letter, _ := rand.Int(rand.Reader, big.NewInt(52))
		if letter.Int64() < 26 {
			result[i] = byte('A' + letter.Int64())
		} else {
			result[i] = byte('a' + letter.Int64() - 26)
		}
	}
	return string(result)
}

// randomAlphanumeric generates a random alphanumeric string
func randomAlphanumeric(length int) string {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		charType, _ := rand.Int(rand.Reader, big.NewInt(3))
		switch charType.Int64() {
		case 0:
			// Digit
			digit, _ := rand.Int(rand.Reader, big.NewInt(10))
			result[i] = byte('0' + digit.Int64())
		case 1:
			// Uppercase
			letter, _ := rand.Int(rand.Reader, big.NewInt(26))
			result[i] = byte('A' + letter.Int64())
		case 2:
			// Lowercase
			letter, _ := rand.Int(rand.Reader, big.NewInt(26))
			result[i] = byte('a' + letter.Int64())
		}
	}
	return string(result)
}

// randomMixedFormat generates a random string with hyphens
func randomMixedFormat(length int) string {
	parts := []string{}
	remaining := length
	for remaining > 0 {
		partLen := 3
		if remaining > 3 {
			partLenBig, _ := rand.Int(rand.Reader, big.NewInt(int64(remaining-2)))
			partLen = int(partLenBig.Int64()) + 2
		}
		if partLen > remaining {
			partLen = remaining
		}
		parts = append(parts, randomDigits(partLen))
		remaining -= partLen
		if remaining > 0 {
			remaining-- // for hyphen
		}
	}
	return strings.Join(parts, "-")
}

// randomHex generates a random hexadecimal string
func randomHex(length int) string {
	hexChars := "0123456789abcdef"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		charIdx, _ := rand.Int(rand.Reader, big.NewInt(16))
		result[i] = hexChars[charIdx.Int64()]
	}
	return string(result)
}

func fatal(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
		os.Exit(1)
	}
}
