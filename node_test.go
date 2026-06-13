// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
	"github.com/go-tpm2/tpm2"
)

// fakeTPM is a scripted common.Transport: it dispatches on the command code in
// the request header and returns a canned, well-formed response so the Node's
// real tpm2 command parsers run end to end without a TPM. It signs real Quotes
// with akKey so the in-process Verifier accepts them.
type fakeTPM struct {
	ekArea  []byte
	akArea  []byte
	akKey   *ecdsa.PrivateKey
	nonce   [32]byte // the admission nonce the guest is expected to quote over
	pcrVals [][]byte // PCRRead values, in selection order
	pcrSel  []int

	// failCC, when non-zero, makes the matching command return a TPM error.
	failCC uint32
	// failAKCreate makes the AK (RH_OWNER) CreatePrimary fail while the EK
	// (RH_ENDORSEMENT) one still succeeds.
	failAKCreate bool
	// activateSecret is what ActivateCredential returns.
	activateSecret []byte
}

func (f *fakeTPM) Send(cmd []byte) ([]byte, error) {
	cc, _ := common.GetU32(cmd, 6)
	tagU16, _ := common.GetU16(cmd, 0)
	tag := common.TPM_ST(tagU16)
	if f.failCC != 0 && cc == f.failCC {
		return resp(tag, 0x101, nil), nil // arbitrary non-success rc
	}
	switch cc {
	case 0x00000131: // CreatePrimary (CreateEK and CreatePrimaryPublic share it)
		// Distinguish EK vs AK by the primaryHandle in the handle area: the
		// EK uses TPM_RH_ENDORSEMENT (0x4000000B), the AK uses TPM_RH_OWNER.
		ph, _ := common.GetU32(cmd, 10)
		area := f.akArea
		if ph == 0x4000000B {
			area = f.ekArea
		} else if f.failAKCreate {
			return resp(tag, 0x102, nil), nil // AK CreatePrimary fails
		}
		var p []byte
		p = common.PutU32(p, 0x80000001)            // objectHandle
		p = common.PutU32(p, 0)                     // parameterSize
		p = append(p, common.MarshalTPM2B(area)...) // outPublic
		p = append(p, common.MarshalTPM2B(nil)...)  // creationData (empty)
		p = append(p, common.MarshalTPM2B(nil)...)  // creationHash
		return resp(common.TagSessions, 0, p), nil
	case 0x0000017B: // GetRandom
		return resp(common.TagNoSessions, 0, common.MarshalTPM2B(bytes.Repeat([]byte{0xAB}, 32))), nil
	case 0x00000176: // StartAuthSession
		var p []byte
		p = common.PutU32(p, 0x02000000)           // sessionHandle
		p = append(p, common.MarshalTPM2B(nil)...) // nonceTPM (empty)
		return resp(common.TagNoSessions, 0, p), nil
	case 0x00000151: // PolicySecret
		var p []byte
		p = common.PutU32(p, 0)                    // parameterSize
		p = append(p, common.MarshalTPM2B(nil)...) // timeout
		return resp(common.TagSessions, 0, p), nil
	case 0x00000147: // ActivateCredential
		var p []byte
		p = common.PutU32(p, 0) // parameterSize
		p = append(p, common.MarshalTPM2B(f.activateSecret)...)
		return resp(common.TagSessions, 0, p), nil
	case 0x00000158: // Quote
		// extraData is the qualifyingData the guest passed; echo whatever it
		// sent so the Verifier's nonce check is exercised against the real
		// challenge in the happy path.
		extra := parseQuoteQualifying(cmd)
		quoted := attestBuilder{
			extraData: extra,
			pcrs:      f.pcrSel,
			pcrValues: f.pcrVals,
		}.build()
		digest := sha256.Sum256(quoted)
		r, s, _ := ecdsa.Sign(rand.Reader, f.akKey, digest[:])
		var p []byte
		p = common.PutU32(p, 0)                       // parameterSize
		p = append(p, common.MarshalTPM2B(quoted)...) // TPM2B_ATTEST
		p = common.PutU16(p, 0x0018)                  // sigAlg = ECDSA
		p = common.PutU16(p, 0x000B)                  // hash = SHA256
		p = append(p, common.MarshalTPM2B(r.Bytes())...)
		p = append(p, common.MarshalTPM2B(s.Bytes())...)
		return resp(common.TagSessions, 0, p), nil
	case 0x0000017E: // PCRRead
		var p []byte
		p = common.PutU32(p, 1) // updateCounter
		p = append(p, marshalSelection(f.pcrSel)...)
		p = common.PutU32(p, uint32(len(f.pcrVals))) // TPML_DIGEST count
		for _, v := range f.pcrVals {
			p = append(p, common.MarshalTPM2B(v)...)
		}
		return resp(common.TagNoSessions, 0, p), nil
	}
	return resp(tag, 0x9999, nil), nil
}

// resp frames a response buffer: tag | size | rc | params.
func resp(tag common.TPM_ST, rc uint32, params []byte) []byte {
	out := common.PutU16(nil, uint16(tag))
	out = common.PutU32(out, uint32(10+len(params)))
	out = common.PutU32(out, rc)
	return append(out, params...)
}

// parseQuoteQualifying pulls the qualifyingData TPM2B_DATA out of a Quote
// command body (after handle+auth areas).
func parseQuoteQualifying(cmd []byte) []byte {
	body := cmd[10:] // skip header
	body = body[4:]  // keyHandle (u32)
	authSize, _ := common.GetU32(body, 0)
	body = body[4+int(authSize):] // skip authorizationSize + auth area
	qd, _, err := common.UnmarshalTPM2B(body)
	if err != nil {
		return nil
	}
	out := make([]byte, len(qd))
	copy(out, qd)
	return out
}

// newFake builds a fakeTPM whose AK signs with a fresh key and whose EK/AK
// public areas match it.
func newFake(t *testing.T) *fakeTPM {
	t.Helper()
	ak := newAK(t)
	ek := newEK(t)
	return &fakeTPM{
		ekArea:         ek.pub,
		akArea:         ak.pub,
		akKey:          ak.priv,
		pcrSel:         []int{0, 7},
		pcrVals:        [][]byte{bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)},
		activateSecret: []byte("recovered-activation-secret"),
	}
}

// nodeSel is the PCR selection the Node quotes in these tests.
func nodeSel() []tpm2.PCRSelection {
	return []tpm2.PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{0, 7}}}
}

// TestNodeNew builds a Node over the fake transport and checks its identity.
func TestNodeNew(t *testing.T) {
	f := newFake(t)
	n, err := NewNode(tpm2.New(f), nodeSel())
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if len(n.AKName()) == 0 {
		t.Fatal("empty AK name")
	}
	req := n.EnrollRequest([]byte("cert"))
	if !bytes.Equal(req.AKName, n.AKName()) || !bytes.Equal(req.EKCert, []byte("cert")) {
		t.Fatal("EnrollRequest mismatch")
	}
	if !bytes.Equal(n.AdmissionRequest().AKName, n.AKName()) {
		t.Fatal("AdmissionRequest mismatch")
	}
}

// TestNodeRespondEnroll runs the node's ActivateCredential path.
func TestNodeRespondEnroll(t *testing.T) {
	f := newFake(t)
	n, err := NewNode(tpm2.New(f), nodeSel())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := n.RespondEnroll(EnrollChallenge{CredentialBlob: []byte("blob"), Secret: []byte("sec")})
	if err != nil {
		t.Fatalf("RespondEnroll: %v", err)
	}
	if !bytes.Equal(proof.ActivationSecret, f.activateSecret) {
		t.Fatalf("proof %q", proof.ActivationSecret)
	}
}

// TestNodeRespondAdmission runs the node's Quote+PCRRead path and feeds the
// result through a real Verifier to ADMITTED — the Node and Verifier validated
// against each other in-process.
func TestNodeRespondAdmission(t *testing.T) {
	f := newFake(t)
	node, err := NewNode(tpm2.New(f), nodeSel())
	if err != nil {
		t.Fatal(err)
	}

	reg := NewMemRegistry()
	_ = reg.BindAK(node.AKName(), node.akPub)
	nonce := [32]byte{0xC0, 0xFF, 0xEE}
	golden := GoldenPolicy{0: f.pcrVals[0], 7: f.pcrVals[1]}
	v := NewVerifier(reg, golden, fixedNonce(nonce))

	ch, err := v.Challenge(node.AdmissionRequest())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := node.RespondAdmission(ch)
	if err != nil {
		t.Fatalf("RespondAdmission: %v", err)
	}
	granted, err := v.Admit(node.AKName(), resp)
	if err != nil || !granted {
		t.Fatalf("Admit: granted=%v err=%v", granted, err)
	}
}

// TestFromHandles builds a Node from pre-loaded handles, with and without a
// supplied AK Name.
func TestFromHandles(t *testing.T) {
	f := newFake(t)
	// Derive an AK name to pass explicitly.
	name, _ := tpm2.ObjectName(f.akArea)
	n1, err := FromHandles(tpm2.New(f), 1, f.ekArea, 2, f.akArea, name, nodeSel())
	if err != nil || !bytes.Equal(n1.AKName(), name) {
		t.Fatalf("FromHandles with name: %v", err)
	}
	n2, err := FromHandles(tpm2.New(f), 1, f.ekArea, 2, f.akArea, nil, nodeSel())
	if err != nil || !bytes.Equal(n2.AKName(), name) {
		t.Fatalf("FromHandles derive name: %v", err)
	}
	// A malformed AK area with nil name surfaces the ObjectName error.
	if _, err := FromHandles(tpm2.New(f), 1, f.ekArea, 2, []byte{0x00}, nil, nodeSel()); err == nil {
		t.Fatal("expected ObjectName error")
	}
}

// TestNodeErrorPaths exercises each command failure branch in NewNode and the
// respond methods.
func TestNodeErrorPaths(t *testing.T) {
	sel := nodeSel()

	// CreateEK fails.
	if _, err := NewNode(tpm2.New(&fakeTPM{failCC: 0x00000131}), sel); err == nil {
		t.Fatal("want CreateEK error")
	}

	// CreatePrimaryPublic command itself fails (EK creation still succeeds).
	akFail := newFake(t)
	akFail.failAKCreate = true
	if _, err := NewNode(tpm2.New(akFail), sel); err == nil {
		t.Fatal("want CreatePrimaryPublic error")
	}

	// AK area parses as a public but breaks ObjectName.
	badAK := newFake(t)
	badAK.akArea = []byte{0x00} // ObjectName fails
	if _, err := NewNode(tpm2.New(badAK), sel); err == nil {
		t.Fatal("want ObjectName error")
	}

	// RespondEnroll: GetRandom, StartAuthSession, PolicySecret, Activate fails.
	for _, cc := range []uint32{0x0000017B, 0x00000176, 0x00000151, 0x00000147} {
		f := newFake(t)
		n, err := NewNode(tpm2.New(f), sel)
		if err != nil {
			t.Fatal(err)
		}
		f.failCC = cc
		if _, err := n.RespondEnroll(EnrollChallenge{}); err == nil {
			t.Fatalf("want RespondEnroll error for cc %#x", cc)
		}
	}

	// RespondAdmission: Quote fails, then PCRRead fails.
	for _, cc := range []uint32{0x00000158, 0x0000017E} {
		f := newFake(t)
		n, err := NewNode(tpm2.New(f), sel)
		if err != nil {
			t.Fatal(err)
		}
		f.failCC = cc
		if _, err := n.RespondAdmission(AdmissionChallenge{}); err == nil {
			t.Fatalf("want RespondAdmission error for cc %#x", cc)
		}
	}

	// RespondAdmission: PCRRead returns FEWER digests than the selection, so
	// the node's map-fill detects the short read.
	short := newFake(t)
	short.pcrVals = [][]byte{bytes.Repeat([]byte{1}, 32)} // only 1 for 2 PCRs
	n, err := NewNode(tpm2.New(short), sel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.RespondAdmission(AdmissionChallenge{}); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("want ErrMalformedQuote, got %v", err)
	}
}
