package fpe

// stringToNumeric converts a string to a numeric representation based on alphabet.
func stringToNumeric(s, alphabet string) []uint16 {
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

// numericToString converts a numeric representation back to string based on alphabet.
func numericToString(numeric []uint16, alphabet string, length int) string {
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

// numericToBytes converts numeric representation to bytes for encryption.
func numericToBytes(numeric []uint16, radix int) []byte {
	// Convert each numeric value to bytes
	result := make([]byte, len(numeric)*2)
	for i, val := range numeric {
		result[i*2] = byte(val >> 8)
		result[i*2+1] = byte(val & 0xFF)
	}
	return result
}

// bytesToNumeric converts bytes back to numeric representation.
func bytesToNumeric(data []byte, radix int, length int) []uint16 {
	result := make([]uint16, length)
	for i := 0; i < length && i*2+1 < len(data); i++ {
		val := uint16(data[i*2])<<8 | uint16(data[i*2+1])
		result[i] = val % uint16(radix)
	}
	return result
}
