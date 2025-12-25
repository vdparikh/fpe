package fpe

// StringToNumeric converts a string to a numeric representation based on alphabet.
// This is a high-level utility function used by the public FPE API.
func StringToNumeric(s, alphabet string) []uint16 {
	result := make([]uint16, len(s))
	alphabetMap := make(map[rune]int)
	for i, char := range alphabet {
		alphabetMap[char] = i
	}

	for i, char := range s {
		if idx, ok := alphabetMap[char]; ok {
			result[i] = uint16(idx)
		} else {
			// Character not in alphabet, use 0 as default
			result[i] = 0
		}
	}

	return result
}

// NumericToString converts a numeric representation back to string based on alphabet.
// This is a high-level utility function used by the public FPE API.
func NumericToString(numeric []uint16, alphabet string, length int) string {
	result := make([]byte, length)
	for i := 0; i < length && i < len(numeric); i++ {
		if int(numeric[i]) < len(alphabet) {
			result[i] = alphabet[numeric[i]]
		} else {
			result[i] = alphabet[0] // Default to first character
		}
	}
	return string(result)
}
