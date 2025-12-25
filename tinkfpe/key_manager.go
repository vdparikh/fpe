// Package tinkfpe provides Tink integration for Format-Preserving Encryption.
// This file contains the KeyManager implementation that registers FF1 with Tink's registry.
package tinkfpe

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/proto/tink_go_proto"
	"github.com/vdparikh/fpe/subtle"
	"google.golang.org/protobuf/proto"
)

const (
	// FPEKeyTypeURL is the type URL for FPE FF1 keys in Tink's registry.
	FPEKeyTypeURL = "type.googleapis.com/google.crypto.tink.FpeFf1Key"
)

// KeyManager implements registry.KeyManager for FPE keys.
// This allows FPE to be registered with Tink's registry and used with keyset handles.
type KeyManager struct {
	typeURL string
}

// NewKeyManager creates a new FPE key manager.
func NewKeyManager() *KeyManager {
	return &KeyManager{
		typeURL: FPEKeyTypeURL,
	}
}

// Primitive creates an FPE primitive from the given serialized key.
func (km *KeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	// Parse the serialized key
	// For now, we'll extract the key value directly
	// In a full implementation, this would parse the protobuf key format
	keyLen := len(serializedKey)

	// Validate key size: must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)
	if keyLen < 16 {
		return nil, fmt.Errorf("key too short: %d bytes (minimum 16)", keyLen)
	}
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, fmt.Errorf("invalid key size: %d bytes (must be 16, 24, or 32)", keyLen)
	}

	// Create FF1 instance from subtle package
	// Note: In a real implementation, we'd parse the key format and extract tweak
	ff1, err := subtle.NewFF1(serializedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create FF1: %w", err)
	}

	// Return the FF1 instance wrapped in a primitive interface
	// The factory will handle wrapping this in the FPE interface
	return ff1, nil
}

// DoesSupport returns true if this KeyManager supports the given key type URL.
func (km *KeyManager) DoesSupport(typeURL string) bool {
	return typeURL == km.typeURL
}

// TypeURL returns the type URL of the keys managed by this KeyManager.
func (km *KeyManager) TypeURL() string {
	return km.typeURL
}

// NewKey generates a new key according to the given key template.
func (km *KeyManager) NewKey(serializedKeyTemplate []byte) (proto.Message, error) {
	// Generate a new random key
	// For FPE, we need at least 16 bytes (AES-128), preferably 32 bytes (AES-256)
	keySize := 32 // Default to AES-256

	// In a full implementation, we'd parse the template to get key size
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// In a full implementation, this would return a proper protobuf message
	// For now, we return nil as a placeholder - the actual implementation would
	// create and return a FpeFf1Key protobuf message
	// This is a simplified version for demonstration
	return nil, fmt.Errorf("NewKey not fully implemented - use NewKeyData instead")
}

// NewKeyData creates a new KeyData from the given key template.
func (km *KeyManager) NewKeyData(serializedKeyTemplate []byte) (*tink_go_proto.KeyData, error) {
	// Parse the template to get key size
	keySize := 32 // Default to AES-256
	if len(serializedKeyTemplate) > 0 {
		// Template value contains the key size as a single byte
		keySize = int(serializedKeyTemplate[0])
		// Validate key size
		if keySize != 16 && keySize != 24 && keySize != 32 {
			return nil, fmt.Errorf("invalid key size in template: %d bytes (must be 16, 24, or 32)", keySize)
		}
	}

	// Generate a new random key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// Return a KeyData protobuf message
	// SYMMETRIC = 2
	return &tink_go_proto.KeyData{
		TypeUrl:         km.typeURL,
		Value:           key,
		KeyMaterialType: 2, // SYMMETRIC
	}, nil
}

// Verify that KeyManager implements registry.KeyManager
var _ registry.KeyManager = (*KeyManager)(nil)

// KeyTemplate creates a key template for FPE FF1 keys.
// This allows users to generate keys with a single line:
//
//	handle, err := keyset.NewHandle(tinkfpe.KeyTemplate())
//
// The template generates AES-256 keys (32 bytes) by default for maximum security.
// For different key sizes, use KeyTemplateAES128() or KeyTemplateAES192().
func KeyTemplate() *tink_go_proto.KeyTemplate {
	return KeyTemplateAES256()
}

// KeyTemplateAES128 creates a key template for FPE FF1 with AES-128 (16 bytes).
func KeyTemplateAES128() *tink_go_proto.KeyTemplate {
	return &tink_go_proto.KeyTemplate{
		TypeUrl:          FPEKeyTypeURL,
		Value:            []byte{16}, // Key size: 16 bytes
		OutputPrefixType: tink_go_proto.OutputPrefixType_RAW,
	}
}

// KeyTemplateAES192 creates a key template for FPE FF1 with AES-192 (24 bytes).
func KeyTemplateAES192() *tink_go_proto.KeyTemplate {
	return &tink_go_proto.KeyTemplate{
		TypeUrl:          FPEKeyTypeURL,
		Value:            []byte{24}, // Key size: 24 bytes
		OutputPrefixType: tink_go_proto.OutputPrefixType_RAW,
	}
}

// KeyTemplateAES256 creates a key template for FPE FF1 with AES-256 (32 bytes).
// This is the recommended template for maximum security.
func KeyTemplateAES256() *tink_go_proto.KeyTemplate {
	return &tink_go_proto.KeyTemplate{
		TypeUrl:          FPEKeyTypeURL,
		Value:            []byte{32}, // Key size: 32 bytes
		OutputPrefixType: tink_go_proto.OutputPrefixType_RAW,
	}
}

// NewKeysetHandleFromKey creates a keyset handle from a raw key (e.g., from an HSM).
// This is useful when you have a key from a custom HSM or key management system
// that isn't a standard Tink KMS client.
//
// The key must be 16, 24, or 32 bytes (AES-128, AES-192, or AES-256).
//
// Example:
//
//	hsmKey := []byte{...} // 32-byte key from your HSM
//	handle, err := tinkfpe.NewKeysetHandleFromKey(hsmKey)
//	if err != nil {
//		log.Fatal(err)
//	}
//	primitive, err := tinkfpe.New(handle, []byte("tweak"))
//
// Note: This creates an unencrypted keyset. In production, consider encrypting
// the keyset before storing it using keyset.Write() with an AEAD.
func NewKeysetHandleFromKey(key []byte) (*keyset.Handle, error) {
	// Validate key size
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, fmt.Errorf("invalid key size: %d bytes (must be 16, 24, or 32)", keyLen)
	}

	// Generate a unique key ID
	keyIDBytes := make([]byte, 4)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}
	keyID := binary.BigEndian.Uint32(keyIDBytes)

	// Create KeyData structure
	keyData := &tink_go_proto.KeyData{
		TypeUrl:         FPEKeyTypeURL,
		Value:           key,
		KeyMaterialType: 2, // SYMMETRIC
	}

	// Create a keyset key
	keysetKey := &tink_go_proto.Keyset_Key{
		KeyData:          keyData,
		KeyId:            keyID,
		Status:           tink_go_proto.KeyStatusType_ENABLED,
		OutputPrefixType: tink_go_proto.OutputPrefixType_RAW,
	}

	// Create the keyset
	ks := &tink_go_proto.Keyset{
		PrimaryKeyId: keyID,
		Key:          []*tink_go_proto.Keyset_Key{keysetKey},
	}

	// Convert to keyset handle
	buf := &keyset.MemReaderWriter{Keyset: ks}
	return insecurecleartextkeyset.Read(buf)
}
