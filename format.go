package fpe

// SeparateFormatAndData separates format characters (hyphens, dots, etc.) from data characters.
// Returns a format mask (true = format char, false = data char) and the data characters only.
// Format characters include: hyphens (-), dots (.), colons (:), at signs (@), etc.
func SeparateFormatAndData(s string) ([]bool, string) {
	formatMask := make([]bool, len(s))
	dataChars := make([]byte, 0, len(s))

	for i, char := range s {
		// Check if it's a format character (non-alphanumeric)
		// Format characters include: hyphens (-), dots (.), colons (:), at signs (@)
		if (char >= '0' && char <= '9') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') {
			formatMask[i] = false
			dataChars = append(dataChars, byte(char))
		} else {
			// Format character: preserve position
			formatMask[i] = true
		}
	}

	return formatMask, string(dataChars)
}

// ReconstructWithFormat reconstructs a string with format characters in their original positions.
func ReconstructWithFormat(data string, formatMask []bool, original string) string {
	result := make([]byte, len(formatMask))
	dataIdx := 0

	for i := 0; i < len(formatMask); i++ {
		if formatMask[i] {
			// Preserve format character from original
			result[i] = original[i]
		} else {
			// Use data character
			if dataIdx < len(data) {
				result[i] = data[dataIdx]
				dataIdx++
			} else {
				// Fallback if data is shorter than expected
				result[i] = '0'
			}
		}
	}

	return string(result)
}

// DetermineAlphabet determines the alphabet (character set) from the plaintext.
// Only considers alphanumeric characters (format chars are handled separately).
func DetermineAlphabet(plaintext string) string {
	hasLetters := false
	hasDigits := false

	for _, char := range plaintext {
		if char >= '0' && char <= '9' {
			hasDigits = true
		} else if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') {
			hasLetters = true
		}
	}

	// Build alphabet based on what's in the plaintext (alphanumeric only)
	alphabet := ""
	if hasDigits {
		alphabet += "0123456789"
	}
	if hasLetters {
		alphabet += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	// Default: numeric
	if alphabet == "" {
		alphabet = "0123456789"
	}

	return alphabet
}
