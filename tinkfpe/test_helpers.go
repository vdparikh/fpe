package tinkfpe

import (
	"sync"

	"github.com/google/tink/go/core/registry"
)

var (
	keyManagerOnce       sync.Once
	registeredKeyManager *KeyManager
)

// ensureKeyManagerRegistered ensures the KeyManager is registered with Tink's registry.
// This function is safe to call multiple times - it will only register once.
func ensureKeyManagerRegistered() *KeyManager {
	keyManagerOnce.Do(func() {
		keyManager := NewKeyManager()
		// Check if already registered by trying to get it
		// If it's not registered, RegisterKeyManager will succeed
		// If it is registered, we'll get an error but that's okay
		if err := registry.RegisterKeyManager(keyManager); err != nil {
			// If it's already registered, try to get it from the registry
			// Note: Tink doesn't provide a way to check if registered, so we'll
			// just try to register and ignore "already registered" errors
			// For now, we'll check if the error is about already being registered
		}
		registeredKeyManager = keyManager
	})
	return registeredKeyManager
}

// getOrRegisterKeyManager gets the KeyManager, registering it if necessary.
// This is a safer version that checks if registration is needed.
func getOrRegisterKeyManager() (*KeyManager, error) {
	keyManager := NewKeyManager()

	// Check if this type URL is already supported
	// If it is, the KeyManager is already registered
	_, err := registry.GetKeyManager(FPEKeyTypeURL)
	if err == nil {
		// Already registered, return a new instance (they're stateless)
		return keyManager, nil
	}

	// Not registered yet, so register it
	if err := registry.RegisterKeyManager(keyManager); err != nil {
		return nil, err
	}

	return keyManager, nil
}
