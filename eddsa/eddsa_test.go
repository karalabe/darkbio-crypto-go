// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eddsa

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/dark-bio/crypto-go/pem"
)

// Test vectors from RFC 8410 Sections 10.1 and 10.3
// https://datatracker.ietf.org/doc/html/rfc8410
var ietfVectors = struct {
	SecretKeySeed  string // 32-byte seed hex
	SecretKeyPEM   string // PKCS#8 v1 PEM
	SecretKeyV2PEM string // PKCS#8 v2 PEM with attribute and embedded public key
	PublicKeyPEM   string // SPKI PEM
}{
	SecretKeySeed: "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842",
	SecretKeyPEM: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----`,
	SecretKeyV2PEM: `-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----`,
	PublicKeyPEM: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----`,
}

// Tests operations with IETF test vectors: the private key must parse into
// the published raw seed, re-encode into the published PEM and DER, and
// derive the RFC's matching public key.
func TestIETFVectors(t *testing.T) {
	// Round trip the secret key pem and verify the expected seed
	key, err := ParseSecretKeyPEM(ietfVectors.SecretKeyPEM)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}
	keyBytes := key.Marshal()
	if hex.EncodeToString(keyBytes[:]) != ietfVectors.SecretKeySeed {
		t.Fatalf("seed mismatch: have %x, want %s", keyBytes, ietfVectors.SecretKeySeed)
	}
	if strings.TrimSpace(key.MarshalPEM()) != strings.TrimSpace(ietfVectors.SecretKeyPEM) {
		t.Fatal("private key PEM re-encoding mismatch")
	}
	// Round trip the secret key der
	_, der, err := pem.Decode([]byte(ietfVectors.SecretKeyPEM))
	if err != nil {
		t.Fatalf("failed to decode PEM: %v", err)
	}
	if !bytes.Equal(key.MarshalDER(), der) {
		t.Fatal("private key DER re-encoding mismatch")
	}
	// Verify the expected public key
	if strings.TrimSpace(key.PublicKey().MarshalPEM()) != strings.TrimSpace(ietfVectors.PublicKeyPEM) {
		t.Fatal("derived public key PEM mismatch")
	}
	// Round trip the public key pem
	pub, err := ParsePublicKeyPEM(ietfVectors.PublicKeyPEM)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	if strings.TrimSpace(pub.MarshalPEM()) != strings.TrimSpace(ietfVectors.PublicKeyPEM) {
		t.Fatal("public key PEM re-encoding mismatch")
	}
	// Round trip the public key der
	_, der, err = pem.Decode([]byte(ietfVectors.PublicKeyPEM))
	if err != nil {
		t.Fatalf("failed to decode PEM: %v", err)
	}
	if !bytes.Equal(pub.MarshalDER(), der) {
		t.Fatal("public key DER re-encoding mismatch")
	}
}

// Tests that the RFC 8410 v2 private key vector carrying an attribute and an
// embedded public key is rejected: only v1 keys without embedded public data
// are supported.
func TestIETFV2Rejected(t *testing.T) {
	if _, err := ParseSecretKeyPEM(ietfVectors.SecretKeyV2PEM); err == nil {
		t.Fatal("expected v2 private key with attributes to be rejected")
	}
}

// Tests signing and verifying messages. Note, this test is not meant to test
// cryptography, it is mostly an API sanity check to verify that everything
// seems to work.
func TestSignVerify(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	message := []byte("message to authenticate")
	signature, _ := secret.Sign(message)

	if err := public.Verify(message, signature); err != nil {
		t.Fatalf("failed to verify message: %v", err)
	}
	// Verify wrong message fails
	if err := public.Verify([]byte("wrong message"), signature); err == nil {
		t.Fatal("expected verification to fail for wrong message")
	}
}
