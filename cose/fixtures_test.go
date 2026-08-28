// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cose

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

// fixtureCorpus is the v0.16 fixture corpus pinning the COSE wire format.
type fixtureCorpus struct {
	XdsaSeed  string `json:"xdsa_seed"`
	XhpkeSeed string `json:"xhpke_seed"`
	Domain    string `json:"domain"`
	Payload   string `json:"payload"`
	Aad       string `json:"aad"`
	Timestamp int64  `json:"timestamp"`
	Sign1     string `json:"sign1"`
	Encrypt0  string `json:"encrypt0"`
}

// fixtures loads the v0.16 fixture corpus.
func fixtures(t *testing.T) *fixtureCorpus {
	t.Helper()

	blob, err := os.ReadFile(filepath.Join("testdata", "v0.16.json"))
	if err != nil {
		t.Fatalf("failed to read fixtures: %v", err)
	}
	corpus := new(fixtureCorpus)
	if err := json.Unmarshal(blob, corpus); err != nil {
		t.Fatalf("failed to parse fixtures: %v", err)
	}
	return corpus
}

// mustHex decodes a hex encoded fixture field.
func mustHex(t *testing.T, field string) []byte {
	t.Helper()

	blob, err := hex.DecodeString(field)
	if err != nil {
		t.Fatalf("failed to decode fixture field: %v", err)
	}
	return blob
}

// Tests that the v0.16 fixture corpus still validates, since that was in the
// first public release of the Ark, so we can't change the format anymore.
func TestV016Fixtures(t *testing.T) {
	fx := fixtures(t)

	var xdsaSeed [xdsa.SecretKeySize]byte
	copy(xdsaSeed[:], mustHex(t, fx.XdsaSeed))
	var xhpkeSeed [xhpke.SecretKeySize]byte
	copy(xhpkeSeed[:], mustHex(t, fx.XhpkeSeed))

	signer := xdsa.ParseSecretKey(xdsaSeed)
	recipient := xhpke.ParseSecretKey(xhpkeSeed)

	domain := mustHex(t, fx.Domain)
	payload := mustHex(t, fx.Payload)
	aad := mustHex(t, fx.Aad)
	sign1 := mustHex(t, fx.Sign1)
	encrypt0 := mustHex(t, fx.Encrypt0)

	// Verify the committed signature and check the embedded payload
	got, err := VerifyAt[[]byte](sign1, aad, signer.PublicKey(), domain, nil, 0)
	if err != nil {
		t.Fatalf("failed to verify fixture signature: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("fixture signature payload mismatch")
	}
	// Wrong domains and tampered structures must fail
	if _, err := VerifyAt[[]byte](sign1, aad, signer.PublicKey(), []byte("wrong"), nil, 0); err == nil {
		t.Fatal("fixture signature verified with wrong domain")
	}
	tampered := bytes.Clone(sign1)
	tampered[len(tampered)-1] ^= 1
	if _, err := VerifyAt[[]byte](tampered, aad, signer.PublicKey(), domain, nil, 0); err == nil {
		t.Fatal("tampered fixture signature verified")
	}
	// Open the committed encrypted message and check the payload
	got, err = OpenAt[[]byte](encrypt0, aad, recipient, signer.PublicKey(), domain, nil, 0)
	if err != nil {
		t.Fatalf("failed to open fixture message: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("fixture message payload mismatch")
	}
	tampered = bytes.Clone(encrypt0)
	tampered[len(tampered)-1] ^= 1
	if _, err := OpenAt[[]byte](tampered, aad, recipient, signer.PublicKey(), domain, nil, 0); err == nil {
		t.Fatal("tampered fixture message opened")
	}
}
