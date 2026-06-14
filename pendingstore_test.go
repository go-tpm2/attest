// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package attest

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-tpm2/tpm2"
)

// TestMemPendingStoreSingleUse exercises the in-memory store directly: a put is
// readable exactly once (consume semantics), a missing/already-taken entry
// returns ok=false, and a re-put overwrites a prior value.
func TestMemPendingStoreSingleUse(t *testing.T) {
	s := NewMemPendingStore()
	ak := []byte("ak-1")

	// Missing entry: Take returns ok=false on both kinds.
	if _, ok := s.TakeEnroll(ak); ok {
		t.Fatal("TakeEnroll on empty store should be ok=false")
	}
	if _, ok := s.TakeNonce(ak); ok {
		t.Fatal("TakeNonce on empty store should be ok=false")
	}

	// Enroll: put, then a single successful take, then a second take fails.
	if err := s.PutEnroll(ak, []byte("secret-A")); err != nil {
		t.Fatalf("PutEnroll: %v", err)
	}
	// Overwrite prior value (single pending entry per AK).
	if err := s.PutEnroll(ak, []byte("secret-B")); err != nil {
		t.Fatalf("PutEnroll overwrite: %v", err)
	}
	got, ok := s.TakeEnroll(ak)
	if !ok || !bytes.Equal(got, []byte("secret-B")) {
		t.Fatalf("TakeEnroll got %q ok=%v, want secret-B true", got, ok)
	}
	if _, ok := s.TakeEnroll(ak); ok {
		t.Fatal("second TakeEnroll should be ok=false (single-use)")
	}

	// Nonce: same single-use contract.
	if err := s.PutNonce(ak, []byte("nonce-A")); err != nil {
		t.Fatalf("PutNonce: %v", err)
	}
	gotN, ok := s.TakeNonce(ak)
	if !ok || !bytes.Equal(gotN, []byte("nonce-A")) {
		t.Fatalf("TakeNonce got %q ok=%v, want nonce-A true", gotN, ok)
	}
	if _, ok := s.TakeNonce(ak); ok {
		t.Fatal("second TakeNonce should be ok=false (single-use)")
	}
}

// fakePendingStore is a PendingStore whose Put methods can be made to fail, to
// drive the Verifier's store-write error branches. It otherwise behaves like a
// shared in-memory map (so a Verifier over it is fully usable).
type fakePendingStore struct {
	inner          *MemPendingStore
	failPutEnroll  bool
	failPutNonce   bool
	putEnrollCalls int
	putNonceCalls  int
}

func newFakePendingStore() *fakePendingStore {
	return &fakePendingStore{inner: NewMemPendingStore()}
}

var errStoreDown = errors.New("pending store unavailable")

func (f *fakePendingStore) PutEnroll(akName, secret []byte) error {
	f.putEnrollCalls++
	if f.failPutEnroll {
		return errStoreDown
	}
	return f.inner.PutEnroll(akName, secret)
}

func (f *fakePendingStore) TakeEnroll(akName []byte) ([]byte, bool) {
	return f.inner.TakeEnroll(akName)
}

func (f *fakePendingStore) PutNonce(akName, nonce []byte) error {
	f.putNonceCalls++
	if f.failPutNonce {
		return errStoreDown
	}
	return f.inner.PutNonce(akName, nonce)
}

func (f *fakePendingStore) TakeNonce(akName []byte) ([]byte, bool) {
	return f.inner.TakeNonce(akName)
}

// TestNewVerifierWithStoreNil falls back to a fresh MemPendingStore when the
// caller passes a nil store (so the Verifier is still usable).
func TestNewVerifierWithStoreNil(t *testing.T) {
	v := NewVerifierWithStore(NewMemRegistry(), GoldenPolicy{}, fixedNonce([32]byte{}), nil)
	if v.pending == nil {
		t.Fatal("nil store should be replaced with a MemPendingStore")
	}
	// And it actually works as a single-use store.
	if err := v.pending.PutEnroll([]byte("a"), []byte("s")); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.pending.TakeEnroll([]byte("a")); !ok {
		t.Fatal("fallback store not functional")
	}
}

// TestEnrollStoreWriteError surfaces a PendingStore.PutEnroll failure as an
// Enroll error (the activation challenge cannot be stashed).
func TestEnrollStoreWriteError(t *testing.T) {
	ek := newEK(t)
	ak := newAK(t)
	akName, _ := tpm2.ObjectName(ak.pub)
	reg := NewMemRegistry()
	reg.TrustEK(ek.pub)
	store := newFakePendingStore()
	store.failPutEnroll = true
	v := NewVerifierWithStore(reg, GoldenPolicy{}, fixedNonce([32]byte{}), store)
	if _, err := v.Enroll(EnrollRequest{EKPub: ek.pub, AKPub: ak.pub, AKName: akName}); !errors.Is(err, errStoreDown) {
		t.Fatalf("got %v want errStoreDown", err)
	}
}

// TestChallengeStoreWriteError surfaces a PendingStore.PutNonce failure as a
// Challenge error (the nonce cannot be stashed for the later Admit).
func TestChallengeStoreWriteError(t *testing.T) {
	store := newFakePendingStore()
	v, _, _, akName := enrolledWithStore(t, [32]byte{}, store)
	store.failPutNonce = true
	if _, err := v.Challenge(AdmissionRequest{AKName: akName}); !errors.Is(err, errStoreDown) {
		t.Fatalf("got %v want errStoreDown", err)
	}
}

// enrolledWithStore mirrors the enrolled() helper but over an explicit
// PendingStore, so store-backed paths can be exercised end to end.
func enrolledWithStore(t *testing.T, nonce [32]byte, store PendingStore) (*Verifier, *MemRegistry, testKey, []byte) {
	t.Helper()
	ek := newEK(t)
	ak := newAK(t)
	akName, err := tpm2.ObjectName(ak.pub)
	if err != nil {
		t.Fatalf("ObjectName: %v", err)
	}
	reg := NewMemRegistry()
	reg.TrustEK(ek.pub)
	v := NewVerifierWithStore(reg, GoldenPolicy{}, fixedNonce(nonce), store)
	ch, err := v.Enroll(EnrollRequest{EKPub: ek.pub, AKPub: ak.pub, AKName: akName})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	recovered := activateInverse(t, ek.priv, akName, ch.CredentialBlob, ch.Secret)
	if err := v.CompleteEnroll(akName, EnrollProof{ActivationSecret: recovered}); err != nil {
		t.Fatalf("CompleteEnroll: %v", err)
	}
	return v, reg, ak, akName
}

// TestVerifierSharedStoreHA proves the HA property at the attest layer: two
// Verifier instances over the SAME PendingStore — a Challenge issued by one is
// admissible by the other (the nonce crossed the shared store), and the nonce
// is single-use (a second Admit against the same challenge is stale).
func TestVerifierSharedStoreHA(t *testing.T) {
	nonce := [32]byte{0x42}
	store := newFakePendingStore()

	// Replica A enrols the node (binds the AK into the shared registry).
	ek := newEK(t)
	ak := newAK(t)
	akName, _ := tpm2.ObjectName(ak.pub)
	reg := NewMemRegistry()
	reg.TrustEK(ek.pub)

	vA := NewVerifierWithStore(reg, GoldenPolicy{}, fixedNonce(nonce), store)
	vB := NewVerifierWithStore(reg, GoldenPolicy{}, fixedNonce(nonce), store)

	ch, err := vA.Enroll(EnrollRequest{EKPub: ek.pub, AKPub: ak.pub, AKName: akName})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	recovered := activateInverse(t, ek.priv, akName, ch.CredentialBlob, ch.Secret)
	if err := vA.CompleteEnroll(akName, EnrollProof{ActivationSecret: recovered}); err != nil {
		t.Fatalf("CompleteEnroll: %v", err)
	}

	pcr := bytes.Repeat([]byte{0x7e}, 32)
	vA.SetPolicy(GoldenPolicy{0: pcr})
	vB.SetPolicy(GoldenPolicy{0: pcr})

	// Challenge on replica A; Admit on replica B (nonce travels via the store).
	adm, err := vA.Challenge(AdmissionRequest{AKName: akName})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	quoted, sig := attestBuilder{extraData: adm.Nonce[:], pcrs: []int{0}, pcrValues: [][]byte{pcr}}.sign(t, ak.priv)
	resp := AdmissionResponse{Quoted: quoted, Signature: sig, PCRs: map[int][]byte{0: pcr}}

	granted, err := vB.Admit(akName, resp)
	if err != nil || !granted {
		t.Fatalf("cross-replica Admit: granted=%v err=%v", granted, err)
	}
	// Single-use: a replay against the consumed nonce (on either replica) is stale.
	if granted, err := vA.Admit(akName, resp); granted || err != ErrStaleNonce {
		t.Fatalf("replay Admit: granted=%v err=%v want stale", granted, err)
	}
}
