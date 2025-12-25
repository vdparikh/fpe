// Package subtle provides low-level cryptographic primitives for Format-Preserving Encryption.
package subtle

import (
	"math/big"
)

// numradixEncode converts a numeric string (base-radix) to a big integer, then to bytes.
// This implements the NIST FF1 numradix encoding.
func numradixEncode(numeric []uint16, radix int) *big.Int {
	result := big.NewInt(0)
	radixBig := big.NewInt(int64(radix))

	for _, digit := range numeric {
		result.Mul(result, radixBig)
		result.Add(result, big.NewInt(int64(digit)))
	}

	return result
}

// numradixDecode converts bytes (interpreted as big-endian integer) to a numeric string (base-radix).
// This implements the NIST FF1 numradix decoding.
func numradixDecode(val *big.Int, radix int, length int) []uint16 {
	result := make([]uint16, length)
	radixBig := big.NewInt(int64(radix))
	temp := new(big.Int).Set(val)

	for i := length - 1; i >= 0; i-- {
		var remainder big.Int
		temp.DivMod(temp, radixBig, &remainder)
		result[i] = uint16(remainder.Int64())
	}

	return result
}

// numradixToBytes converts a numeric string to bytes using numradix encoding.
func numradixToBytes(numeric []uint16, radix int) []byte {
	val := numradixEncode(numeric, radix)
	bytes := val.Bytes()

	// Ensure big-endian representation with proper length
	minBytes := (len(numeric)*bitLength(radix) + 7) / 8
	if len(bytes) < minBytes {
		padded := make([]byte, minBytes)
		copy(padded[minBytes-len(bytes):], bytes)
		return padded
	}

	return bytes
}

// bitLength returns the number of bits needed to represent radix-1.
func bitLength(radix int) int {
	if radix <= 1 {
		return 1
	}
	bits := 0
	for n := radix - 1; n > 0; n >>= 1 {
		bits++
	}
	return bits
}
