// SPDX-FileCopyrightText: 2024 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

package stronghold

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestSmokeStrongHold(t *testing.T) {
	subject := []byte("zenithar")
	secret := []byte("123456")

	sh := &Hash{
		RemoteHashFunc: func(ctx context.Context, b []byte) ([]byte, error) {
			// This is the remote HSM
			return hmac.New(sha256.New, []byte("remote-hash")).Sum(b), nil
		},
	}

	// Create a new hash
	h, err := sh.Seal(context.Background(), secret, []byte(subject))
	if err != nil {
		t.Error(err)
		return
	}

	// Verify new hash
	err = sh.Verify(context.Background(), secret, h, []byte(subject))
	if err != nil {
		t.Error(err)
		return
	}
}

func TestSeal(t *testing.T) {
	sh := &Hash{
		KeyDerivation: SCRYPT,
		Encryption:   AESGCM,
		RemoteHashFunc: func(ctx context.Context, b []byte) ([]byte, error) {
			// This is the remote HSM
			return hmac.New(sha256.New, []byte("remote-hash")).Sum(b), nil
		},
	}

	t.Run("EmptySecret", func(t *testing.T) {
		_, err := sh.Seal(context.Background(), []byte(""), []byte("zenithar"))
		if !errors.Is(err, ErrEmptySecret) {
			t.Errorf("expected %v, got %v", ErrEmptySecret, err)
		}
	})

	t.Run("SecretTooLong", func(t *testing.T) {
		_, err := sh.Seal(context.Background(), make([]byte, maxSecretSize+1), []byte("zenithar"))
		if !errors.Is(err, ErrSecretTooLong) {
			t.Errorf("expected %v, got %v", ErrSecretTooLong, err)
		}
	})

	t.Run("AADTooLong", func(t *testing.T) {
		_, err := sh.Seal(context.Background(), []byte("123456"), make([]byte, maxAADSize+1))
		if !errors.Is(err, ErrAADTooLong) {
			t.Errorf("expected %v, got %v", ErrAADTooLong, err)
		}
	})

	t.Run("RemoteHashFuncNotSet", func(t *testing.T) {
		sh.RemoteHashFunc = nil
		_, err := sh.Seal(context.Background(), []byte("123456"), []byte("zenithar"))
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})

	t.Run("RemoteHashError", func(t *testing.T) {
		sh.RemoteHashFunc = func(ctx context.Context, b []byte) ([]byte, error) {
			return nil, errors.New("remote hash error")
		}
		_, err := sh.Seal(context.Background(), []byte("123456"), []byte("zenithar"))
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})
}

func TestVerify(t *testing.T) {
	sh := &Hash{
		KeyDerivation: SCRYPT,
		Encryption:   AESGCM,
		RemoteHashFunc: func(ctx context.Context, b []byte) ([]byte, error) {
			// This is the remote HSM
			return hmac.New(sha256.New, []byte("remote-hash")).Sum(b), nil
		},
	}

	t.Run("EmptySecret", func(t *testing.T) {
		err := sh.Verify(context.Background(), []byte(""), make([]byte, saltSize+1), []byte("zenithar"))
		if !errors.Is(err, ErrEmptySecret) {
			t.Errorf("expected %v, got %v", ErrEmptySecret, err)
		}
	})

	t.Run("SecretTooLong", func(t *testing.T) {
		err := sh.Verify(context.Background(), make([]byte, maxSecretSize+1), make([]byte, saltSize+1), []byte("zenithar"))
		if !errors.Is(err, ErrSecretTooLong) {
			t.Errorf("expected %v, got %v", ErrSecretTooLong, err)
		}
	})

	t.Run("AADTooLong", func(t *testing.T) {
		err := sh.Verify(context.Background(), []byte("123456"), make([]byte, saltSize+1), make([]byte, maxAADSize+1))
		if !errors.Is(err, ErrAADTooLong) {
			t.Errorf("expected %v, got %v", ErrAADTooLong, err)
		}
	})

	t.Run("StoredHashTooShort", func(t *testing.T) {
		err := sh.Verify(context.Background(), []byte("123456"), []byte(""), []byte("zenithar"))
		if !errors.Is(err, ErrStoredHashTooShort) {
			t.Errorf("expected %v, got %v", ErrStoredHashTooShort, err)
		}
	})
	
	t.Run("RemoteHashFuncNotSet", func(t *testing.T) {
		sh.RemoteHashFunc = nil
		err := sh.Verify(context.Background(), []byte("123456"), make([]byte, saltSize+1), []byte("zenithar"))
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})

	t.Run("RemoteHashError", func(t *testing.T) {
		sh.RemoteHashFunc = func(ctx context.Context, b []byte) ([]byte, error) {
			return nil, errors.New("remote hash error")
		}
		err := sh.Verify(context.Background(), []byte("123456"), make([]byte, saltSize+1), []byte("zenithar"))
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})
}

func BenchmarkSeal(b *testing.B) {
	subject := []byte("zenithar")
	secret := []byte("123456")

	sh := &Hash{
		RemoteHashFunc: func(ctx context.Context, b []byte) ([]byte, error) {
			// This is the remote HSM
			return hmac.New(sha256.New, []byte("remote-hash")).Sum(b), nil
		},
	}

	for i := 0; i < b.N; i++ {
		_, err := sh.Seal(context.Background(), secret, []byte(subject))
		if err != nil {
			b.Error(err)
			return
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	subject := []byte("zenithar")
	secret := []byte("123456")

	sh := &Hash{
		RemoteHashFunc: func(ctx context.Context, b []byte) ([]byte, error) {
			// This is the remote HSM
			return hmac.New(sha256.New, []byte("remote-hash")).Sum(b), nil
		},
	}

	storedHash, err := sh.Seal(context.Background(), secret, subject)
	if err != nil {
		b.Error(err)
		return
	}

	for i := 0; i < b.N; i++ {
		err := sh.Verify(context.Background(), secret, storedHash, subject)
		if err != nil {
			b.Error(err)
			return
		}
	}
}

func FuzzSeal(f *testing.F) {
	sh := &Hash{
		RemoteHashFunc: func(ctx context.Context, b []byte) ([]byte, error) {
			// This is the remote HSM
			return hmac.New(sha256.New, []byte("remote-hash")).Sum(b), nil
		},
	}

	f.Fuzz(func(t *testing.T, secret []byte, aad []byte) {
		sh.Seal(context.Background(), secret, []byte(aad))
	})
}

func FuzzVerify(f *testing.F) {
	sh := &Hash{
		RemoteHashFunc: func(ctx context.Context, b []byte) ([]byte, error) {
			// This is the remote HSM
			return hmac.New(sha256.New, []byte("remote-hash")).Sum(b), nil
		},
	}

	subject := []byte("zenithar")
	secret := []byte("123456")

	storedHash, err := sh.Seal(context.Background(), secret, subject)
	if err != nil {
		f.Error(err)
		return
	}
	f.Add(secret, storedHash, subject)
	f.Add(secret, storedHash, []byte(""))
	f.Add(secret, storedHash[:saltSize-1], []byte("zenithar"))

	f.Fuzz(func(t *testing.T, secret, storedHash, aad []byte) {
		sh.Verify(context.Background(), secret, storedHash, aad)
	})
}
