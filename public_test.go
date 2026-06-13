// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package attest

import (
	"bytes"
	"testing"

	"github.com/go-tpm2/common"
)

// TestParseECCPointGood parses a well-formed AK and EK area (the EK exercises
// the symmetric != NULL branch).
func TestParseECCPointGood(t *testing.T) {
	ak := newAK(t)
	p, err := parseECCPoint(ak.pub)
	if err != nil {
		t.Fatalf("AK: %v", err)
	}
	if len(p.X) == 0 || len(p.Y) == 0 {
		t.Fatal("empty point")
	}
	ek := newEK(t)
	if _, err := parseECCPoint(ek.pub); err != nil {
		t.Fatalf("EK (symmetric!=NULL): %v", err)
	}
}

// TestParseECCPointTruncations truncates a valid AK area at each field boundary
// to exercise every short-buffer branch of parseECCPoint.
func TestParseECCPointTruncations(t *testing.T) {
	good := newAK(t).pub
	// Lengths to truncate AT (each strips off a field the parser then misses).
	// Walk: type(2) nameAlg(2) attrs(4) authPolicy(2+0) sym(2) scheme(2)
	// hash(2) curve(2) kdf(2) then unique x(2+32) y(2+32).
	for _, n := range []int{1, 3, 5, 9, 11, 13, 15, 17, 19, 21, 22, 22 + 33} {
		if n >= len(good) {
			continue
		}
		if _, err := parseECCPoint(good[:n]); err != ErrBadPublic {
			t.Fatalf("truncate@%d: got %v want ErrBadPublic", n, err)
		}
	}
}

// TestParseECCPointBadAuthPolicy makes the authPolicy TPM2B over-declare its
// length so UnmarshalTPM2B fails.
func TestParseECCPointBadAuthPolicy(t *testing.T) {
	var p []byte
	p = common.PutU16(p, algECC)
	p = common.PutU16(p, algSHA256)
	p = common.PutU32(p, 0)
	p = common.PutU16(p, 0xFFFF) // authPolicy claims 65535 bytes; none follow
	if _, err := parseECCPoint(p); err != ErrBadPublic {
		t.Fatalf("got %v want ErrBadPublic", err)
	}
}

// TestParseECCPointBadUnique makes the unique x TPM2B over-declare its length.
func TestParseECCPointBadUnique(t *testing.T) {
	var p []byte
	p = common.PutU16(p, algECC)
	p = common.PutU16(p, algSHA256)
	p = common.PutU32(p, 0)
	p = common.PutU16(p, 0)      // authPolicy empty
	p = common.PutU16(p, 0x0010) // sym NULL
	p = common.PutU16(p, 0x0010) // scheme NULL
	p = common.PutU16(p, eccNistP256)
	p = common.PutU16(p, 0x0010) // kdf NULL
	p = common.PutU16(p, 0xFFFF) // unique x claims 65535 bytes
	if _, err := parseECCPoint(p); err != ErrBadPublic {
		t.Fatalf("bad x: got %v want ErrBadPublic", err)
	}

	// Valid x, over-declared y.
	var q []byte
	q = common.PutU16(q, algECC)
	q = common.PutU16(q, algSHA256)
	q = common.PutU32(q, 0)
	q = common.PutU16(q, 0)
	q = common.PutU16(q, 0x0010)
	q = common.PutU16(q, 0x0010)
	q = common.PutU16(q, eccNistP256)
	q = common.PutU16(q, 0x0010)
	q = append(q, common.MarshalTPM2B(bytes.Repeat([]byte{1}, 32))...) // x ok
	q = common.PutU16(q, 0xFFFF)                                       // y over-declared
	if _, err := parseECCPoint(q); err != ErrBadPublic {
		t.Fatalf("bad y: got %v want ErrBadPublic", err)
	}
}

// TestParseECCPointSchemeKDFDetails covers the scheme!=NULL and kdf!=NULL detail
// branches with their details truncated.
func TestParseECCPointSchemeKDFDetails(t *testing.T) {
	// scheme = ECDSA (non-NULL) but the hashAlg detail is missing.
	var p []byte
	p = common.PutU16(p, algECC)
	p = common.PutU16(p, algSHA256)
	p = common.PutU32(p, 0)
	p = common.PutU16(p, 0)        // authPolicy empty
	p = common.PutU16(p, 0x0010)   // sym NULL
	p = common.PutU16(p, algECDSA) // scheme ECDSA -> expects a hashAlg next
	if _, err := parseECCPoint(p); err != ErrBadPublic {
		t.Fatalf("scheme detail: got %v want ErrBadPublic", err)
	}

	// kdf != NULL but its hashAlg detail is missing.
	var q []byte
	q = common.PutU16(q, algECC)
	q = common.PutU16(q, algSHA256)
	q = common.PutU32(q, 0)
	q = common.PutU16(q, 0)      // authPolicy empty
	q = common.PutU16(q, 0x0010) // sym NULL
	q = common.PutU16(q, 0x0010) // scheme NULL
	q = common.PutU16(q, eccNistP256)
	q = common.PutU16(q, 0x000B) // kdf = SHA256 (non-NULL) -> expects hashAlg
	if _, err := parseECCPoint(q); err != ErrBadPublic {
		t.Fatalf("kdf detail: got %v want ErrBadPublic", err)
	}

	// kdf != NULL WITH its hashAlg detail present, then a valid unique point:
	// the parser consumes the kdf detail and still extracts (x, y).
	var r []byte
	r = common.PutU16(r, algECC)
	r = common.PutU16(r, algSHA256)
	r = common.PutU32(r, 0)
	r = common.PutU16(r, 0)      // authPolicy empty
	r = common.PutU16(r, 0x0010) // sym NULL
	r = common.PutU16(r, 0x0010) // scheme NULL
	r = common.PutU16(r, eccNistP256)
	r = common.PutU16(r, 0x000B) // kdf = SHA256 (non-NULL)
	r = common.PutU16(r, 0x000B) // kdf.details hashAlg
	r = append(r, common.MarshalTPM2B(bytes.Repeat([]byte{1}, 32))...)
	r = append(r, common.MarshalTPM2B(bytes.Repeat([]byte{2}, 32))...)
	pt, err := parseECCPoint(r)
	if err != nil {
		t.Fatalf("kdf detail present: %v", err)
	}
	if pt.X[0] != 1 || pt.Y[0] != 2 {
		t.Fatalf("kdf detail present: wrong point %x %x", pt.X, pt.Y)
	}
}

// TestParseECCPointSymDetails covers the symmetric != NULL keyBits/mode detail
// truncations.
func TestParseECCPointSymDetails(t *testing.T) {
	// sym = AES but keyBits is missing.
	var p []byte
	p = common.PutU16(p, algECC)
	p = common.PutU16(p, algSHA256)
	p = common.PutU32(p, 0)
	p = common.PutU16(p, 0)      // authPolicy empty
	p = common.PutU16(p, algAES) // sym AES -> expects keyBits + mode
	if _, err := parseECCPoint(p); err != ErrBadPublic {
		t.Fatalf("sym keyBits: got %v want ErrBadPublic", err)
	}
	// sym = AES, keyBits present, mode missing.
	q := append([]byte{}, p...)
	q = common.PutU16(q, 128) // keyBits, but mode missing
	if _, err := parseECCPoint(q); err != ErrBadPublic {
		t.Fatalf("sym mode: got %v want ErrBadPublic", err)
	}
	// sym present + keyBits + mode, then scheme missing.
	r := append([]byte{}, q...)
	r = common.PutU16(r, algCFB) // mode, then scheme missing
	if _, err := parseECCPoint(r); err != ErrBadPublic {
		t.Fatalf("scheme after sym: got %v want ErrBadPublic", err)
	}
}
