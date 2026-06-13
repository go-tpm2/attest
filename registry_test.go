// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package attest

import (
	"bytes"
	"testing"
)

// TestMemRegistry covers TrustEK/Trusted, BindAK/AKPub, the miss path, and that
// AKPub returns a copy (mutating the result does not corrupt the store).
func TestMemRegistry(t *testing.T) {
	r := NewMemRegistry()
	ek := []byte("ek-public")
	if r.Trusted(ek) {
		t.Fatal("untrusted EK reported trusted")
	}
	r.TrustEK(ek)
	if !r.Trusted(ek) {
		t.Fatal("trusted EK reported untrusted")
	}

	if _, ok := r.AKPub([]byte("ak")); ok {
		t.Fatal("unbound AK reported bound")
	}
	if err := r.BindAK([]byte("ak"), []byte("ak-public")); err != nil {
		t.Fatal(err)
	}
	got, ok := r.AKPub([]byte("ak"))
	if !ok || !bytes.Equal(got, []byte("ak-public")) {
		t.Fatalf("AKPub got %q ok=%v", got, ok)
	}
	// Mutating the returned slice must not affect the store.
	got[0] ^= 0xFF
	again, _ := r.AKPub([]byte("ak"))
	if !bytes.Equal(again, []byte("ak-public")) {
		t.Fatal("AKPub returned an aliased slice")
	}
}
