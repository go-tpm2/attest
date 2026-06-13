// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package attest

import (
	"bytes"
	"testing"
)

// TestRoundTrip checks every message marshals and unmarshals to an equal value,
// and that the encoding is stable (re-marshaling the decoded value reproduces
// the bytes).
func TestRoundTrip(t *testing.T) {
	t.Run("EnrollRequest", func(t *testing.T) {
		in := EnrollRequest{EKPub: []byte{1, 2}, EKCert: []byte{3}, AKPub: []byte{4, 5, 6}, AKName: []byte{7}}
		buf := in.Marshal()
		var out EnrollRequest
		if err := out.Unmarshal(buf); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.EKPub, in.EKPub) || !bytes.Equal(out.EKCert, in.EKCert) ||
			!bytes.Equal(out.AKPub, in.AKPub) || !bytes.Equal(out.AKName, in.AKName) {
			t.Fatalf("mismatch: %+v != %+v", out, in)
		}
		if !bytes.Equal(out.Marshal(), buf) {
			t.Fatal("re-marshal unstable")
		}
	})
	t.Run("EnrollChallenge", func(t *testing.T) {
		in := EnrollChallenge{CredentialBlob: []byte{1, 2, 3}, Secret: []byte{4, 5}}
		var out EnrollChallenge
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.CredentialBlob, in.CredentialBlob) || !bytes.Equal(out.Secret, in.Secret) {
			t.Fatal("mismatch")
		}
	})
	t.Run("EnrollProof", func(t *testing.T) {
		in := EnrollProof{ActivationSecret: []byte{9, 8, 7}}
		var out EnrollProof
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.ActivationSecret, in.ActivationSecret) {
			t.Fatal("mismatch")
		}
	})
	t.Run("AdmissionRequest", func(t *testing.T) {
		in := AdmissionRequest{AKName: []byte{1, 1, 2}}
		var out AdmissionRequest
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.AKName, in.AKName) {
			t.Fatal("mismatch")
		}
	})
	t.Run("AdmissionChallenge", func(t *testing.T) {
		var n [32]byte
		for i := range n {
			n[i] = byte(i)
		}
		in := AdmissionChallenge{Nonce: n}
		var out AdmissionChallenge
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out.Nonce != in.Nonce {
			t.Fatal("mismatch")
		}
	})
	t.Run("AdmissionResponse", func(t *testing.T) {
		in := AdmissionResponse{
			Quoted:    []byte{1, 2, 3},
			Signature: []byte{4, 5},
			PCRs:      map[int][]byte{7: {0xaa}, 0: {0xbb, 0xcc}, 3: {}},
			EventLog:  []byte{9},
		}
		buf := in.Marshal()
		var out AdmissionResponse
		if err := out.Unmarshal(buf); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Quoted, in.Quoted) || !bytes.Equal(out.Signature, in.Signature) ||
			!bytes.Equal(out.EventLog, in.EventLog) || len(out.PCRs) != len(in.PCRs) {
			t.Fatalf("mismatch: %+v", out)
		}
		for k, v := range in.PCRs {
			if !bytes.Equal(out.PCRs[k], v) {
				t.Fatalf("PCR %d mismatch", k)
			}
		}
		if !bytes.Equal(out.Marshal(), buf) {
			t.Fatal("re-marshal unstable")
		}
	})
}

// TestDecodeErrors covers the codec's rejection paths: short header, bad magic,
// bad version, wrong kind, truncated body fields, and trailing bytes.
func TestDecodeErrors(t *testing.T) {
	good := EnrollProof{ActivationSecret: []byte{1, 2, 3}}.Marshal()

	cases := []struct {
		name string
		buf  []byte
		want error
	}{
		{"shortHeader", good[:3], ErrShortBuffer},
		{"badMagic", flip(good, 0), ErrBadMagic},
		{"badVersion", flip(good, 4), ErrBadVersion},
		{"wrongKind", flip(good, 5), ErrWrongKind},
		{"trailing", append(append([]byte{}, good...), 0xFF), ErrTrailingBytes},
		{"truncatedLen", good[:7], ErrShortBuffer},             // mid u32 length
		{"truncatedBytes", good[:len(good)-1], ErrShortBuffer}, // body short
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var m EnrollProof
			if err := m.Unmarshal(c.buf); err != c.want {
				t.Fatalf("got %v want %v", err, c.want)
			}
		})
	}
}

// TestPCRMapDecodeErrors covers the map decoder's truncation branches.
func TestPCRMapDecodeErrors(t *testing.T) {
	full := AdmissionResponse{
		Quoted: []byte{1}, Signature: []byte{2},
		PCRs: map[int][]byte{0: {0xaa}}, EventLog: []byte{3},
	}.Marshal()

	// Truncate just before the map count (after Quoted+Signature). Find the
	// offset by re-encoding the prefix: header(6) + Quoted(4+1) + Signature(4+1).
	mapStart := 6 + (4 + 1) + (4 + 1)
	cases := []struct {
		name string
		buf  []byte
	}{
		{"shortCount", full[:mapStart+2]},     // mid count u32
		{"shortIndex", full[:mapStart+4+2]},   // count read, mid index u32
		{"shortValue", full[:mapStart+4+4+2]}, // index read, mid value len
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var m AdmissionResponse
			if err := m.Unmarshal(c.buf); err != ErrShortBuffer {
				t.Fatalf("got %v want ErrShortBuffer", err)
			}
		})
	}
}

// TestFixed32DecodeErrors covers the AdmissionChallenge fixed32 decoder: a
// frame whose nonce is truncated, and propagation of a prior error.
func TestFixed32DecodeErrors(t *testing.T) {
	full := AdmissionChallenge{Nonce: [32]byte{1}}.Marshal()
	var m AdmissionChallenge
	// Truncate the 32-byte nonce.
	if err := m.Unmarshal(full[:6+10]); err != ErrShortBuffer {
		t.Fatalf("short nonce: got %v want ErrShortBuffer", err)
	}
	// Wrong kind sets d.err before fixed32 runs, exercising its err short-circuit
	// (the result then stays the zero error from open's check).
	if err := m.Unmarshal(flip(full, 5)); err != ErrWrongKind {
		t.Fatalf("wrong kind: got %v", err)
	}
}

// TestPCRMapPriorError drives pcrMap's d.err short-circuit: an AdmissionResponse
// whose earlier field (Signature) is truncated, so the map decode never starts.
func TestPCRMapPriorError(t *testing.T) {
	full := AdmissionResponse{
		Quoted: []byte{1}, Signature: []byte{2, 3, 4},
		PCRs: map[int][]byte{0: {0xaa}}, EventLog: nil,
	}.Marshal()
	// Cut inside the Signature length/bytes so Signature decode errors first.
	var m AdmissionResponse
	if err := m.Unmarshal(full[:6+(4+1)+2]); err != ErrShortBuffer {
		t.Fatalf("got %v want ErrShortBuffer", err)
	}
}

// flip returns a copy of b with byte i incremented (to corrupt a header field).
func flip(b []byte, i int) []byte {
	c := append([]byte{}, b...)
	c[i]++
	return c
}
