// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xhpke

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/dark-bio/crypto-go/pem"
)

// Tests that a private key can be serialized to bytes and parsed back.
func TestSecretKeyBytesRoundtrip(t *testing.T) {
	key := GenerateKey()
	keyBytes := key.Marshal()
	parsed := ParseSecretKey(keyBytes)
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("secret key bytes roundtrip failed")
	}
}

// Tests that a public key can be serialized to bytes and parsed back.
func TestPublicKeyBytesRoundtrip(t *testing.T) {
	key := GenerateKey().PublicKey()
	keyBytes := key.Marshal()
	parsed, err := ParsePublicKey(keyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("public key bytes roundtrip failed")
	}
}

// Tests that a private key can be serialized to DER and parsed back.
func TestSecretKeyDERRoundtrip(t *testing.T) {
	key := GenerateKey()
	der := key.MarshalDER()
	parsed, err := ParseSecretKeyDER(der)
	if err != nil {
		t.Fatalf("failed to parse DER: %v", err)
	}
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("secret key DER roundtrip failed")
	}
}

// Tests that a private key can be serialized to PEM and parsed back.
func TestSecretKeyPEMRoundtrip(t *testing.T) {
	key := GenerateKey()
	pemStr := key.MarshalPEM()
	parsed, err := ParseSecretKeyPEM(pemStr)
	if err != nil {
		t.Fatalf("failed to parse PEM: %v", err)
	}
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("secret key PEM roundtrip failed")
	}
}

// Tests that a public key can be serialized to DER and parsed back.
func TestPublicKeyDERRoundtrip(t *testing.T) {
	key := GenerateKey().PublicKey()
	der := key.MarshalDER()
	parsed, err := ParsePublicKeyDER(der)
	if err != nil {
		t.Fatalf("failed to parse DER: %v", err)
	}
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("public key DER roundtrip failed")
	}
}

// Tests that a public key can be serialized to PEM and parsed back.
func TestPublicKeyPEMRoundtrip(t *testing.T) {
	key := GenerateKey().PublicKey()
	pemStr := key.MarshalPEM()
	parsed, err := ParsePublicKeyPEM(pemStr)
	if err != nil {
		t.Fatalf("failed to parse PEM: %v", err)
	}
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("public key PEM roundtrip failed")
	}
}

// Test vectors from draft-connolly-cfrg-xwing-kem-10 Appendix D
// https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem
var ietfVectors = struct {
	SecretKeySeed string // 32-byte seed hex
	SecretKeyPEM  string // PKCS#8 v1 PEM
	PublicKeyPEM  string // SPKI PEM
}{
	SecretKeySeed: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	SecretKeyPEM: `-----BEGIN PRIVATE KEY-----
MDQCAQAwDQYLKwYBBAGD5i2ByHoEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
GhscHR4f
-----END PRIVATE KEY-----`,
	PublicKeyPEM: `-----BEGIN PUBLIC KEY-----
MIIE1DANBgsrBgEEAYPmLYHIegOCBMEAb1QJigoOZBFGYUtpYLpg2GA9YvRH+atJ
m0e9aQbMQLBh2GNKPoiQbyhJWOdEHKbHJcu5cJW3ZxpGK2aByeZYC7yNYLFJ+mAm
EEOvu6UvIFpgKDhIUVlq3zcavqmNM0c4PSu2c0OPZ4NhK/hwFPe5Gol0AmU0XfZ5
NARz0cTBdohuXim48Fi7fHNTFmhs/1w764wmHLAJcKacGvzFS5TLhuHOY7pjbjlc
pFEB4hx70EwxPqGa8kFB79KtREFqJbpPZZEO99iAnDCT8EqvAOPNluNcSqPIAsGK
1vOdpLS42YyL15Atg6B7pFOWZ0pgJDyrk+gP2bHId3N2qcwNb6EV4mOTgLnGvnhI
vRNYjGRwOgU10ZoPgWM6l2oKEFtm7ihdD9JV6CwDMZJfQ4O278dh72CZI1oLmHJj
WKqdAbi4llGfkhR0u3wUuyIlK1wvENQSRsmyPnZEhJNn9UGhX2O8koo5u3vHPwe2
ZcSWu2VYyPRUiacuxLrNNOnFlMM4cbcj8DSV6ItDkasm5DBD3rYRezkZ5FxMGxar
KOR93XI2Y4VHZhkvwYBspwq7eGy9swky5oyKNwvPsHmDoBLDJmuT76YmV/S4ODdM
sLuV4OwGVBsHZdmc8VO8a5YTXKeApVs2R3ieMZFeRig8+ce7boRT+2aCEFFB8dwN
ANhe7XA7bGyWH3nIRSdrQkiUnAZ4LlE+spkbldlgQuOMvto1JEmytQhOvaUiamIG
QAeJEwowlkSYSLYp/upKLCp0PEoN3Jyz89Z2/FY3MbJsShpm3IRZFwBW1XaX8UQ7
gamjRBK7e/BfMydXWlkR3TAdYFOGfzwwgHEfG/EVh7C7KYQnayaF53ViEOSz+JVT
hCMeVYxvUQyR4PxWtdGIX/KUnpWka8G+4fpx9QJ+EMRDsOkdD9dED0Z6JyISEuiP
XGumQpbK4NIHv8YPiMfPtcRaoYOdGMs3xFhD5UJqSpDIArZCj5U8NZxKwGA0UvrA
tzYeL9NdzIhakhRdT8oBWPG31wtLzRGOSipBVEON8xDESpobmepBWQcmeoiwYkJB
V5wXIvRu1hwuPspUXJlwUXF1OZuADbJdo5WT0GSQ1xQsAOiNLbBH6YmL23rLftkH
9uMEFswN5UokLAohJjAvXVTIW8Zqwvg8eXlFtQZ8qkK9LgwZypdQblB6sKXJ9WM3
CEmcGfJK7FE705A6XXO27EmR98cuuZHBw3iJgFyx6jigzAIXayfFjWOM5aMmaEV8
+bm+AnygIUBXlxcl1UEC6JlnFusq2CNFO2BbhVNwsbIbOTLN7UFgqplzx+uuWsR2
TZTPfMlQbwd7rXMBLbtKyBQKOHRkEuszyVFFliBfcHY1hiIX2bYJGMYmjZNEkVuE
eiR2waJw8VSlyEI0FlrPyGk5hwLOqemgfnsOmeqb3LeEH+nA+iXIM4CSVho+3dxw
AfR4rWV4GmAkqtFl2baXmtrESKRGL1ZGhVJ/diQ0/ppCWoRDe0VzkuyoDJE1BhUe
OhMjnzQvynZVtuquhFoiHOs+Z/VjnGGT9v3u9X45m4CLfzqitXQKre2QFj3F13XJ
+vfx+9B12rNE6dfRRmRygfu6ezxWyv1YM7epMOxCBufDptd2T+gdeg==
-----END PUBLIC KEY-----`,
}

// Tests operations with IETF test vectors: the private key must parse into
// the published raw seed, re-encode into the published PEM and DER, and
// expand to the draft's matching public key.
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

// Tests sealing and opening various combinations of messages.
func TestSealOpen(t *testing.T) {
	// Create the keys
	secret := GenerateKey()
	public := secret.PublicKey()

	// Run a bunch of different authentication/encryption combinations
	tests := []struct {
		name    string
		sealMsg []byte
		authMsg []byte
	}{
		// Only message to authenticate
		{
			sealMsg: []byte{},
			authMsg: []byte("message to authenticate"),
		},
		// Only message to encrypt
		{
			sealMsg: []byte("message to encrypt"),
			authMsg: []byte{},
		},
		// Both message to authenticate and to encrypt
		{
			sealMsg: []byte("message to encrypt"),
			authMsg: []byte("message to authenticate"),
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Seal the message to the public key
			sessionKey, ciphertext, err := public.Seal(tt.sealMsg, tt.authMsg, []byte("test"))
			if err != nil {
				t.Fatalf("test %d: failed to seal: %v", i, err)
			}
			// Open the sealed message with the secret key
			plaintext, err := secret.Open(&sessionKey, ciphertext, tt.authMsg, []byte("test"))
			if err != nil {
				t.Fatalf("test %d: failed to open: %v", i, err)
			}
			// Validate that the cleartext matches our expected encrypted payload
			if !bytes.Equal(plaintext, tt.sealMsg) {
				t.Fatalf("test %d: plaintext mismatch: got %q, want %q", i, plaintext, tt.sealMsg)
			}
		})
	}
}

// Tests that a sender/receiver context can be established and used to
// encrypt/decrypt multiple messages in sequence.
func TestContextSealOpen(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	// Set up the sender and receiver contexts
	sender, encapKey, err := public.NewSender([]byte("test-session"))
	if err != nil {
		t.Fatalf("failed to setup sender: %v", err)
	}
	receiver, err := secret.NewReceiver(&encapKey, []byte("test-session"))
	if err != nil {
		t.Fatalf("failed to setup receiver: %v", err)
	}
	// Encrypt and decrypt multiple messages in sequence
	type testMsg struct {
		seal, auth []byte
	}
	messages := []testMsg{
		{[]byte("first message"), []byte("auth-1")},
		{[]byte("second message"), []byte("auth-2")},
		{[]byte("third message"), nil},
		{nil, []byte("auth-only")}, // empty message
		{[]byte("fifth message after empty"), []byte("auth-5")},
	}
	for i, msg := range messages {
		ciphertext, err := sender.Seal(msg.seal, msg.auth)
		if err != nil {
			t.Fatalf("failed to seal message %d: %v", i, err)
		}
		plaintext, err := receiver.Open(ciphertext, msg.auth)
		if err != nil {
			t.Fatalf("failed to open message %d: %v", i, err)
		}
		if !bytes.Equal(plaintext, msg.seal) {
			t.Fatalf("message %d mismatch: got %q, want %q", i, plaintext, msg.seal)
		}
	}
}

// Tests that a receiver context rejects messages decrypted out of order.
// The HPKE sequence counter is only advanced on success, so after a failed
// open the context remains usable for the correct next message.
func TestContextRejectsOutOfOrder(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	sender, encapKey, err := public.NewSender([]byte("test-order"))
	if err != nil {
		t.Fatalf("failed to setup sender: %v", err)
	}
	receiver, err := secret.NewReceiver(&encapKey, []byte("test-order"))
	if err != nil {
		t.Fatalf("failed to setup receiver: %v", err)
	}
	// Seal two messages
	ct0, err := sender.Seal([]byte("message 0"), []byte("aad-0"))
	if err != nil {
		t.Fatalf("failed to seal message 0: %v", err)
	}
	ct1, err := sender.Seal([]byte("message 1"), []byte("aad-1"))
	if err != nil {
		t.Fatalf("failed to seal message 1: %v", err)
	}
	// Try to open the second message first (should fail: wrong nonce)
	if _, err := receiver.Open(ct1, []byte("aad-1")); err == nil {
		t.Fatal("should reject out-of-order message")
	}
	// The sequence counter doesn't advance on failure, so the correct
	// next message (ct0) should still work
	pt0, err := receiver.Open(ct0, []byte("aad-0"))
	if err != nil {
		t.Fatalf("should open in-order message: %v", err)
	}
	if !bytes.Equal(pt0, []byte("message 0")) {
		t.Fatalf("message 0 mismatch: got %q", pt0)
	}
	// And now ct1 should work since the counter has advanced
	pt1, err := receiver.Open(ct1, []byte("aad-1"))
	if err != nil {
		t.Fatalf("should open next message: %v", err)
	}
	if !bytes.Equal(pt1, []byte("message 1")) {
		t.Fatalf("message 1 mismatch: got %q", pt1)
	}
}

// Tests that mismatched domains between sender and receiver prevent
// decryption (the HPKE contexts derive different keys).
func TestContextRejectsWrongDomain(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	sender, encapKey, err := public.NewSender([]byte("domain-a"))
	if err != nil {
		t.Fatalf("failed to setup sender: %v", err)
	}
	receiver, err := secret.NewReceiver(&encapKey, []byte("domain-b"))
	if err != nil {
		t.Fatalf("failed to setup receiver: %v", err)
	}
	ciphertext, err := sender.Seal([]byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}
	if _, err := receiver.Open(ciphertext, []byte("aad")); err == nil {
		t.Fatal("should reject mismatched domain")
	}
}

// Tests that mismatched additional authenticated data between seal and open
// prevents decryption for both single-shot and context-based APIs.
func TestRejectsWrongAuth(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	// Single-shot: wrong AAD must fail
	sessionKey, ciphertext, err := public.Seal([]byte("secret"), []byte("correct-aad"), []byte("domain"))
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}
	if _, err := secret.Open(&sessionKey, ciphertext, []byte("wrong-aad"), []byte("domain")); err == nil {
		t.Fatal("single-shot should reject wrong AAD")
	}

	// Context-based: wrong AAD must fail
	sender, encapKey, err := public.NewSender([]byte("domain"))
	if err != nil {
		t.Fatalf("failed to setup sender: %v", err)
	}
	receiver, err := secret.NewReceiver(&encapKey, []byte("domain"))
	if err != nil {
		t.Fatalf("failed to setup receiver: %v", err)
	}
	ct, err := sender.Seal([]byte("secret"), []byte("correct-aad"))
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}
	if _, err := receiver.Open(ct, []byte("wrong-aad")); err == nil {
		t.Fatal("context should reject wrong AAD")
	}

	// Verify recovery: correct AAD still works after failed attempt
	pt, err := receiver.Open(ct, []byte("correct-aad"))
	if err != nil {
		t.Fatalf("should open with correct AAD: %v", err)
	}
	if !bytes.Equal(pt, []byte("secret")) {
		t.Fatalf("plaintext mismatch: got %q", pt)
	}
}
