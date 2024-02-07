// SPDX-FileCopyrightText: 2024 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

// Package stronghold provides a secure way to store and verify secrets.
//
// The package provides a way to store a secret in a secure way. The secret is
// stored as a hash and can be verified later. The package uses a key derivation
// function to derive a key from the secret and a salt. The key is used to
// encrypt the secret using an authenticated encryption with associated data
// (AEAD) scheme. The encrypted secret is then hashed using a remote hardware
// security module (HSM).
//
// This is inspirred by the Facebook Onion PRF service.
package stronghold
