// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package attest

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-tpm2/tpm2"
)

// fixedNonce returns a Nonce source yielding n every call (deterministic tests).
func fixedNonce(n [32]byte) Nonce {
	return func() ([32]byte, error) { return n, nil }
}

// enrolled wires a Verifier with a trusted EK and an AK bound through the full
// enrolment handshake, returning the verifier, registry, the AK key, and the
// AK Name. It also asserts MakeCredential round-trips via the in-test
// ActivateCredential inverse.
func enrolled(t *testing.T, nonce [32]byte) (*Verifier, *MemRegistry, testKey, []byte) {
	t.Helper()
	ek := newEK(t)
	ak := newAK(t)
	akName, err := tpm2.ObjectName(ak.pub)
	if err != nil {
		t.Fatalf("ObjectName: %v", err)
	}

	reg := NewMemRegistry()
	reg.TrustEK(ek.pub)
	v := NewVerifier(reg, GoldenPolicy{}, fixedNonce(nonce))

	ch, err := v.Enroll(EnrollRequest{EKPub: ek.pub, AKPub: ak.pub, AKName: akName})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	// Node side: recover the activation secret via the in-test inverse.
	recovered := activateInverse(t, ek.priv, akName, ch.CredentialBlob, ch.Secret)
	if err := v.CompleteEnroll(akName, EnrollProof{ActivationSecret: recovered}); err != nil {
		t.Fatalf("CompleteEnroll: %v", err)
	}
	if _, ok := reg.AKPub(akName); !ok {
		t.Fatal("AK not bound after CompleteEnroll")
	}
	return v, reg, ak, akName
}

// TestEnrollHappyAndAdmit drives the whole protocol to ADMITTED.
func TestEnrollHappyAndAdmit(t *testing.T) {
	nonce := [32]byte{1, 2, 3, 4}
	v, _, ak, akName := enrolled(t, nonce)

	pcrs := map[int][]byte{0: bytes.Repeat([]byte{0xa1}, 32), 7: bytes.Repeat([]byte{0xb2}, 32)}
	// Rebuild the verifier's policy to the just-measured PCRs (via SetPolicy).
	v.SetPolicy(GoldenPolicy{0: pcrs[0], 7: pcrs[7]})

	ch, err := v.Challenge(AdmissionRequest{AKName: akName})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	quoted, sig := attestBuilder{
		extraData: ch.Nonce[:],
		pcrs:      []int{0, 7},
		pcrValues: [][]byte{pcrs[0], pcrs[7]},
	}.sign(t, ak.priv)

	granted, err := v.Admit(akName, AdmissionResponse{Quoted: quoted, Signature: sig, PCRs: pcrs})
	if err != nil || !granted {
		t.Fatalf("Admit: granted=%v err=%v", granted, err)
	}
}

// TestEnrollUntrustedEK rejects an EK not on the allowlist.
func TestEnrollUntrustedEK(t *testing.T) {
	ek := newEK(t)
	ak := newAK(t)
	akName, _ := tpm2.ObjectName(ak.pub)
	reg := NewMemRegistry() // EK NOT trusted
	v := NewVerifier(reg, GoldenPolicy{}, fixedNonce([32]byte{}))
	if _, err := v.Enroll(EnrollRequest{EKPub: ek.pub, AKPub: ak.pub, AKName: akName}); err != ErrUnknownEK {
		t.Fatalf("got %v want ErrUnknownEK", err)
	}
}

// TestEnrollMalformedEK trusts a bogus EK blob that cannot be parsed as a point.
func TestEnrollMalformedEK(t *testing.T) {
	reg := NewMemRegistry()
	bogus := []byte{0x00, 0x23, 0x00} // too short to be a TPMT_PUBLIC
	reg.TrustEK(bogus)
	v := NewVerifier(reg, GoldenPolicy{}, fixedNonce([32]byte{}))
	if _, err := v.Enroll(EnrollRequest{EKPub: bogus, AKName: []byte("n")}); err != ErrUnknownEK {
		t.Fatalf("got %v want ErrUnknownEK", err)
	}
}

// TestEnrollMakeCredentialError trusts an EK whose point is well-formed bytes
// but not on the curve, so MakeCredential fails.
func TestEnrollMakeCredentialError(t *testing.T) {
	ak := newAK(t)
	akName, _ := tpm2.ObjectName(ak.pub)
	// An EK public area with a well-formed-but-off-curve point (x=1, y=1).
	bad := buildEKArea(append(bytes.Repeat([]byte{0}, 31), 1), append(bytes.Repeat([]byte{0}, 31), 1))
	reg := NewMemRegistry()
	reg.TrustEK(bad)
	v := NewVerifier(reg, GoldenPolicy{}, fixedNonce([32]byte{}))
	_, err := v.Enroll(EnrollRequest{EKPub: bad, AKName: akName})
	if err != tpm2.ErrEKPointNotOnCurve {
		t.Fatalf("got %v want ErrEKPointNotOnCurve", err)
	}
}

// TestCompleteEnrollWrongSecret rejects a bad activation secret and drops the
// pending entry (so a retry also fails with ErrActivationFailed).
func TestCompleteEnrollWrongSecret(t *testing.T) {
	ek := newEK(t)
	ak := newAK(t)
	akName, _ := tpm2.ObjectName(ak.pub)
	reg := NewMemRegistry()
	reg.TrustEK(ek.pub)
	v := NewVerifier(reg, GoldenPolicy{}, fixedNonce([32]byte{}))
	if _, err := v.Enroll(EnrollRequest{EKPub: ek.pub, AKPub: ak.pub, AKName: akName}); err != nil {
		t.Fatal(err)
	}
	if err := v.CompleteEnroll(akName, EnrollProof{ActivationSecret: []byte("wrong")}); err != ErrActivationFailed {
		t.Fatalf("got %v want ErrActivationFailed", err)
	}
	if _, ok := reg.AKPub(akName); ok {
		t.Fatal("AK should NOT be bound after failed activation")
	}
	// Pending dropped: a second CompleteEnroll has nothing to match.
	if err := v.CompleteEnroll(akName, EnrollProof{ActivationSecret: []byte("wrong")}); err != ErrActivationFailed {
		t.Fatalf("retry: got %v want ErrActivationFailed", err)
	}
}

// TestCompleteEnrollNoPending rejects CompleteEnroll for an unknown AK.
func TestCompleteEnrollNoPending(t *testing.T) {
	v := NewVerifier(NewMemRegistry(), GoldenPolicy{}, fixedNonce([32]byte{}))
	if err := v.CompleteEnroll([]byte("nope"), EnrollProof{ActivationSecret: []byte("x")}); err != ErrActivationFailed {
		t.Fatalf("got %v want ErrActivationFailed", err)
	}
}

// TestChallengeUnboundAK rejects a challenge for an AK that never enrolled.
func TestChallengeUnboundAK(t *testing.T) {
	v := NewVerifier(NewMemRegistry(), GoldenPolicy{}, fixedNonce([32]byte{}))
	if _, err := v.Challenge(AdmissionRequest{AKName: []byte("nope")}); err != ErrUnboundAK {
		t.Fatalf("got %v want ErrUnboundAK", err)
	}
}

// TestChallengeNonceError surfaces a nonce-source failure.
func TestChallengeNonceError(t *testing.T) {
	v, _, _, akName := enrolled(t, [32]byte{})
	v.nonce = func() ([32]byte, error) { return [32]byte{}, errors.New("rng dead") }
	if _, err := v.Challenge(AdmissionRequest{AKName: akName}); err == nil {
		t.Fatal("expected nonce error")
	}
}

// TestAdmitUnboundAK rejects admission for an unbound AK.
func TestAdmitUnboundAK(t *testing.T) {
	v := NewVerifier(NewMemRegistry(), GoldenPolicy{}, fixedNonce([32]byte{}))
	if granted, err := v.Admit([]byte("nope"), AdmissionResponse{}); granted || err != ErrUnboundAK {
		t.Fatalf("got granted=%v err=%v", granted, err)
	}
}

// TestAdmitStaleNonceNoChallenge rejects Admit with no pending challenge.
func TestAdmitStaleNonceNoChallenge(t *testing.T) {
	v, _, _, akName := enrolled(t, [32]byte{})
	if granted, err := v.Admit(akName, AdmissionResponse{}); granted || err != ErrStaleNonce {
		t.Fatalf("got granted=%v err=%v", granted, err)
	}
}

// TestAdmitMalformedSignature rejects a wrong-width signature.
func TestAdmitMalformedSignature(t *testing.T) {
	nonce := [32]byte{5}
	v, _, ak, akName := enrolled(t, nonce)
	if _, err := v.Challenge(AdmissionRequest{AKName: akName}); err != nil {
		t.Fatal(err)
	}
	quoted, _ := attestBuilder{extraData: nonce[:], pcrs: []int{0}, pcrValues: [][]byte{bytes.Repeat([]byte{1}, 32)}}.sign(t, ak.priv)
	if _, err := v.Admit(akName, AdmissionResponse{Quoted: quoted, Signature: []byte{1, 2, 3}, PCRs: map[int][]byte{0: bytes.Repeat([]byte{1}, 32)}}); err != ErrMalformedQuote {
		t.Fatalf("got %v want ErrMalformedQuote", err)
	}
}

// TestAdmitBadAKPublic exercises the parseECCPoint failure inside Admit by
// binding a malformed AK public directly into the registry.
func TestAdmitBadAKPublic(t *testing.T) {
	reg := NewMemRegistry()
	akName := []byte("badak")
	_ = reg.BindAK(akName, []byte{0x00, 0x23}) // too short to parse
	v := NewVerifier(reg, GoldenPolicy{}, fixedNonce([32]byte{9}))
	if _, err := v.Challenge(AdmissionRequest{AKName: akName}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Admit(akName, AdmissionResponse{Signature: make([]byte, 64)}); err != ErrMalformedQuote {
		t.Fatalf("got %v want ErrMalformedQuote", err)
	}
}

// TestAdmitWrongSignature rejects a quote signed by a different key.
func TestAdmitWrongSignature(t *testing.T) {
	nonce := [32]byte{7}
	v, _, _, akName := enrolled(t, nonce)
	other := newAK(t) // signs with the WRONG key
	if _, err := v.Challenge(AdmissionRequest{AKName: akName}); err != nil {
		t.Fatal(err)
	}
	pcr := bytes.Repeat([]byte{0x33}, 32)
	quoted, sig := attestBuilder{extraData: nonce[:], pcrs: []int{0}, pcrValues: [][]byte{pcr}}.sign(t, other.priv)
	if _, err := v.Admit(akName, AdmissionResponse{Quoted: quoted, Signature: sig, PCRs: map[int][]byte{0: pcr}}); err != ErrQuoteSignature {
		t.Fatalf("got %v want ErrQuoteSignature", err)
	}
}

// TestAdmitPCRDigestMismatch rejects a quote whose pcrDigest disagrees with the
// claimed PCRs.
func TestAdmitPCRDigestMismatch(t *testing.T) {
	nonce := [32]byte{8}
	v, _, ak, akName := enrolled(t, nonce)
	if _, err := v.Challenge(AdmissionRequest{AKName: akName}); err != nil {
		t.Fatal(err)
	}
	pcr := bytes.Repeat([]byte{0x44}, 32)
	quoted, sig := attestBuilder{
		extraData: nonce[:], pcrs: []int{0}, pcrValues: [][]byte{pcr},
		pcrDigest: bytes.Repeat([]byte{0xFF}, 32), // wrong digest
	}.sign(t, ak.priv)
	if _, err := v.Admit(akName, AdmissionResponse{Quoted: quoted, Signature: sig, PCRs: map[int][]byte{0: pcr}}); err != ErrPCRDigestMismatch {
		t.Fatalf("got %v want ErrPCRDigestMismatch", err)
	}
}

// TestAdmitMalformedQuote rejects a quote that is not a TPM_ST_ATTEST_QUOTE
// (VerifyQuote's ParseAttest fails before signature/digest).
func TestAdmitMalformedQuote(t *testing.T) {
	nonce := [32]byte{10}
	v, _, ak, akName := enrolled(t, nonce)
	if _, err := v.Challenge(AdmissionRequest{AKName: akName}); err != nil {
		t.Fatal(err)
	}
	pcr := bytes.Repeat([]byte{0x55}, 32)
	quoted, sig := attestBuilder{extraData: nonce[:], pcrs: []int{0}, pcrValues: [][]byte{pcr}, notQuote: true}.sign(t, ak.priv)
	if _, err := v.Admit(akName, AdmissionResponse{Quoted: quoted, Signature: sig, PCRs: map[int][]byte{0: pcr}}); err != ErrMalformedQuote {
		t.Fatalf("got %v want ErrMalformedQuote", err)
	}
}

// TestAdmitStaleNonceWrongExtraData rejects a quote whose extraData != nonce
// (signature and digest valid, but the wrong/old nonce).
func TestAdmitStaleNonceWrongExtraData(t *testing.T) {
	nonce := [32]byte{11}
	v, _, ak, akName := enrolled(t, nonce)
	if _, err := v.Challenge(AdmissionRequest{AKName: akName}); err != nil {
		t.Fatal(err)
	}
	pcr := bytes.Repeat([]byte{0x66}, 32)
	wrong := bytes.Repeat([]byte{0xAB}, 32) // not the issued nonce
	quoted, sig := attestBuilder{extraData: wrong, pcrs: []int{0}, pcrValues: [][]byte{pcr}}.sign(t, ak.priv)
	if _, err := v.Admit(akName, AdmissionResponse{Quoted: quoted, Signature: sig, PCRs: map[int][]byte{0: pcr}}); err != ErrStaleNonce {
		t.Fatalf("got %v want ErrStaleNonce", err)
	}
}

// TestAdmitPolicyMismatch rejects a quote that is fully valid but boots a stack
// the GoldenPolicy does not approve.
func TestAdmitPolicyMismatch(t *testing.T) {
	nonce := [32]byte{12}
	v, _, ak, akName := enrolled(t, nonce)
	golden := bytes.Repeat([]byte{0x01}, 32)
	v.policy = GoldenPolicy{0: golden}
	if _, err := v.Challenge(AdmissionRequest{AKName: akName}); err != nil {
		t.Fatal(err)
	}
	actual := bytes.Repeat([]byte{0x02}, 32) // != golden
	quoted, sig := attestBuilder{extraData: nonce[:], pcrs: []int{0}, pcrValues: [][]byte{actual}}.sign(t, ak.priv)
	granted, err := v.Admit(akName, AdmissionResponse{Quoted: quoted, Signature: sig, PCRs: map[int][]byte{0: actual}})
	if granted {
		t.Fatal("should not be granted")
	}
	if !errors.Is(err, ErrUntrustedBoot) {
		t.Fatalf("got %v want ErrUntrustedBoot", err)
	}
	var ub *UntrustedBootError
	if !errors.As(err, &ub) || ub.PCR != 0 {
		t.Fatalf("want *UntrustedBootError PCR 0, got %v", err)
	}
}

// TestRandNonce exercises the production nonce source and the read-failure
// branch via a failing reader.
func TestRandNonce(t *testing.T) {
	a, err := RandNonce()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RandNonce()
	if a == b {
		t.Fatal("two RandNonce values collided")
	}
	if _, err := nonceFrom(failReader{}); err == nil {
		t.Fatal("expected nonceFrom read error")
	}
}

// TestEnrollRNGFailure surfaces a failing secret RNG in Enroll.
func TestEnrollRNGFailure(t *testing.T) {
	ek := newEK(t)
	ak := newAK(t)
	akName, _ := tpm2.ObjectName(ak.pub)
	reg := NewMemRegistry()
	reg.TrustEK(ek.pub)
	v := NewVerifier(reg, GoldenPolicy{}, fixedNonce([32]byte{}))
	v.rng = failReader{}
	if _, err := v.Enroll(EnrollRequest{EKPub: ek.pub, AKPub: ak.pub, AKName: akName}); err == nil {
		t.Fatal("expected RNG failure")
	}
}

// TestSortInts exercises the swap branch directly with unsorted input.
func TestSortInts(t *testing.T) {
	a := []int{3, 1, 2}
	sortInts(a)
	if a[0] != 1 || a[1] != 2 || a[2] != 3 {
		t.Fatalf("sortInts: %v", a)
	}
	// orderedPCRs over an unsorted-key map returns ascending values.
	got := orderedPCRs(map[int][]byte{5: {0x5}, 1: {0x1}, 3: {0x3}})
	if len(got) != 3 || got[0][0] != 0x1 || got[1][0] != 0x3 || got[2][0] != 0x5 {
		t.Fatalf("orderedPCRs: %v", got)
	}
}

// failReader always fails, to drive RNG read-error branches.
type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("rng failure") }

// TestJoinSplitSignature round-trips a P-256 signature through the wire form,
// including the left-pad path (short r/s) and the over-long truncation path.
func TestJoinSplitSignature(t *testing.T) {
	sig := tpm2.ECDSASignature{R: []byte{0x01, 0x02}, S: []byte{0xFF}}
	wire := JoinSignature(sig)
	if len(wire) != 64 {
		t.Fatalf("wire len %d", len(wire))
	}
	got, err := splitSignature(wire)
	if err != nil {
		t.Fatal(err)
	}
	// R/S are left-padded to 32 bytes; compare the trailing significant bytes.
	if got.R[31] != 0x02 || got.R[30] != 0x01 || got.S[31] != 0xFF {
		t.Fatalf("split mismatch: %x %x", got.R, got.S)
	}
	// Over-long input keeps the low-order bytes.
	long := bytes.Repeat([]byte{0xAA}, 40)
	out := make([]byte, 4)
	copyRightAligned(out, long)
	if !bytes.Equal(out, []byte{0xAA, 0xAA, 0xAA, 0xAA}) {
		t.Fatalf("copyRightAligned long: %x", out)
	}
}
