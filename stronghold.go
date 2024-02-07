// SPDX-FileCopyrightText: 2024 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

package stronghold

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	// saltSize is the size of the salt in bytes.
	saltSize = 24
	// keySize is the size of the key in bytes.
	keySize = 16
	// maxSecretSize is the maximum size of the secret in bytes.
	maxSecretSize = 1024
	// maxAADSize is the maximum size of the additional data in bytes.
	maxAADSize = 4096
)

var (
	// ErrEmptySecret is returned when the secret is empty.
	ErrEmptySecret = errors.New("empty secret")
	// ErrSecretTooLong is returned when the secret is too long.
	ErrSecretTooLong = errors.New("secret too long")
	// ErrAADTooLong is returned when the additional data is too long.
	ErrAADTooLong = errors.New("aad too long")
	// ErrStoredHashTooShort is returned when the stored hash is too short.
	ErrStoredHashTooShort = errors.New("stored hash too short")
	// ErrContextMismatch is returned when the context does not match the stored context.
	ErrContextMismatch = errors.New("context mismatch")
	// ErrHashMismatch is returned when the hash does not match the stored hash.
	ErrHashMismatch = errors.New("hash mismatch")
)

// operationError is an error that includes the operation name.
type operationError struct {
	operation string
	err       error
}

// Error returns the error message.
func (e *operationError) Error() string {
	if e.err == nil {
		return "op:" + e.operation + " - no error provided"
	}
	return "op:" + e.operation + " - " + e.err.Error()
}

// Unwrap returns the wrapped error.
func (e *operationError) Unwrap() error {
	return e.err
}

// Is returns true if the target error is the same as the wrapped error.
func (e *operationError) Is(target error) bool {
	return e.err == target
}

// Hash is a hash implementation that uses a remote HSM to hash the password.
type Hash struct {
	// Remote is the remote HSM.
	RemoteHashFunc func(context.Context, []byte) ([]byte, error)
	// KeyDerivation is the key derivation function.
	KeyDerivation KDF
	// Encryption is the authenticated encryption with associated data.
	Encryption AEAD
}

// Seal hashes the secret and seals the context with the provided additional data.
// It returns the sealed context.
//
// The AAD is the additional data that is used to seal the context. Consider to use
// a canonical representation of the context to prevent mismatches.
// The result is expected to be in the format SALT || ENCRYPTED_HASH.
func (s *Hash) Seal(ctx context.Context, secret, aad []byte) ([]byte, error) {
	// Check arguments
	switch {
	case len(secret) == 0:
		return nil, &operationError{"Seal", ErrEmptySecret}
	case len(secret) > maxSecretSize:
		return nil, &operationError{"Seal", ErrSecretTooLong}
	case len(aad) > maxAADSize:
		return nil, &operationError{"Seal", ErrAADTooLong}
	case s.RemoteHashFunc == nil:
		return nil, &operationError{"Seal", fmt.Errorf("remote hash function not set")}
	}

	// Use salt locally to hash the secret and prevent rainbow table attacks.
	salt := make([]byte, saltSize)
	n, err := rand.Read(salt[:])
	if err != nil {
		return nil, &operationError{"Seal", fmt.Errorf("salt generation error: %w", err)}
	}
	if n != saltSize {
		return nil, &operationError{"Seal", fmt.Errorf("salt generation: short read")}
	}

	// Use HMAC-SHA256 to prevent length extension attacks and ensure FIPS compliance.
	hm1 := hmac.New(sha256.New, salt)
	hm1.Write([]byte("stronghold-secret-normalization-v1"))
	hm1.Write([]byte(secret))

	// Use another secret to hash the previous hash with a remote HSM
	// This is to prevent the hash from being used in another system
	// even if the database is compromised.
	// The password is not transmitted to the remote HSM.
	h1, err := s.RemoteHashFunc(ctx, hm1.Sum(nil))
	if err != nil {
		return nil, &operationError{"Seal", fmt.Errorf("remote hash error: %w", err)}
	}

	// Derive the encryption key from the remote hash according to FIPS or not.
	var (
		encryptionKey []byte
	)
	if builder, ok := kdfRegistry[s.KeyDerivation]; ok {
		var err error
		encryptionKey, err = builder(h1, salt, keySize)
		if err != nil {
			return nil, &operationError{"Seal", fmt.Errorf("encryption key error: %w", err)}
		}
	} else {
		return nil, &operationError{"Seal", fmt.Errorf("key derivation mode not set")}
	}

	// Initialize the AEAD mode with the encryption key.
	var (
		aead cipher.AEAD
	)
	if builder, ok := aeadRegistry[s.Encryption]; ok {
		var err error
		aead, err = builder(encryptionKey)
		if err != nil {
			return nil, &operationError{"Seal", fmt.Errorf("encryption key error: %w", err)}
		}
	} else {
		return nil, &operationError{"Seal", fmt.Errorf("encryption mode not set")}
	}

	// Store the salt and the encrypted hash together
	// SALT || ENCRYPTED_HASH
	final := make([]byte, 0, saltSize+len(h1)+aead.Overhead())
	final = append(final, salt...)

	// Encrypt the KDF output to prevent the hash from being used in another system
	// even if the database is compromised. Seal the context with provided additional data
	// to prevent encrypted hash from being used in another context.
	return append(final, aead.Seal(h1[:0], final[:saltSize], h1, aad)...), nil
}

// Verify verifies the secret against the stored hash and additional data.
// It returns nil if the secret matches the stored hash, ErrHashMismatch if the
// hash does not match, or ErrContextMismatch if the context does not match the
// stored context.
//
// The stored hash is expected to be in the format SALT || ENCRYPTED_HASH.
// AAD is the additional data that was used to seal the context. Consider to use
// a canonical representation of the context to prevent mismatches.
func (s *Hash) Verify(ctx context.Context, secret, storedHash, aad []byte) error {
	// Check arguments
	switch {
	case len(secret) == 0:
		return &operationError{"Verify", ErrEmptySecret}
	case len(secret) > maxSecretSize:
		return &operationError{"Verify", ErrSecretTooLong}
	case len(aad) > maxAADSize:
		return &operationError{"Verify", ErrAADTooLong}
	case len(storedHash) < saltSize:
		return &operationError{"Verify", ErrStoredHashTooShort}
	case s.RemoteHashFunc == nil:
		return &operationError{"Verify", fmt.Errorf("remote hash function not set")}
	}

	// Normalize the password charset and the length.
	// Use HMAC-SHA256 to prevent length extension attacks and ensure FIPS compliance.
	hm1 := hmac.New(sha256.New, storedHash[:saltSize])
	hm1.Write([]byte("stronghold-secret-normalization-v1"))
	hm1.Write([]byte(secret))

	// Use another secret to hash the previous hash with a remote HSM
	// This is to prevent the hash from being used in another system
	// even if the database is compromised.
	// The password is not transmitted to the remote HSM.
	h1, err := s.RemoteHashFunc(ctx, hm1.Sum(nil))
	if err != nil {
		return &operationError{"Verify", fmt.Errorf("remote hash error: %w", err)}
	}

	// Derive the encryption key from the remote hash according to FIPS or not.
	var (
		encryptionKey []byte
	)
	if builder, ok := kdfRegistry[s.KeyDerivation]; ok {
		var err error
		encryptionKey, err = builder(h1, storedHash[:saltSize], keySize)
		if err != nil {
			return &operationError{"Verify", fmt.Errorf("encryption key error: %w", err)}
		}
	} else {
		return &operationError{"Verify", fmt.Errorf("key derivation mode not set")}
	}

	// Initialize the AEAD mode with the encryption key.
	var (
		aead cipher.AEAD
	)
	if builder, ok := aeadRegistry[s.Encryption]; ok {
		var err error
		aead, err = builder(encryptionKey)
		if err != nil {
			return &operationError{"Verify", fmt.Errorf("encryption key error: %w", err)}
		}
	} else {
		return &operationError{"Verify", fmt.Errorf("encryption mode not set")}
	}

	// Decrypt the stored hash
	plaintext, err := aead.Open(nil, storedHash[:saltSize], storedHash[saltSize:], aad)
	if err != nil {
		return &operationError{"Verify", ErrContextMismatch}
	}

	// Compare the hashes
	if !hmac.Equal(h1, plaintext) {
		return &operationError{"Verify", ErrHashMismatch}
	}

	return nil
}
