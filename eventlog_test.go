// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package attest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

// sha256Alg is the SHA-256 bank algorithm ID used throughout these tests.
const sha256Alg = uint16(common.AlgSHA256)

// extend folds digest into a 32-byte virtual PCR cur exactly as the TPM does.
func extend(cur, digest []byte) []byte {
	h := sha256.Sum256(append(append([]byte(nil), cur...), digest...))
	return h[:]
}

// digestOf returns the SHA-256 of s (a convenient stand-in measurement value).
func digestOf(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// TestParseAndReplay parses a hand-built crypto-agile log (spec-ID header plus
// several PCR_EVENT2 entries across two PCRs) and asserts both the parsed events
// and the replayed PCRs.
func TestParseAndReplay(t *testing.T) {
	dA := digestOf("shim")
	dB := digestOf("grub")
	dC := digestOf("kernel")
	log := NewLogBuilder().
		Add(16, 0x0d, dA, []byte("shim")).
		Add(16, 0x0d, dB, nil).
		Add(17, 0x05, dC, []byte("kernel")).
		Bytes()

	events, err := ParseEventLog(log)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events want 3", len(events))
	}
	if events[0].PCR != 16 || events[0].Type != 0x0d || !bytes.Equal(events[0].Digests[sha256Alg], dA) {
		t.Fatalf("event0 wrong: %+v", events[0])
	}
	if !bytes.Equal(events[0].Data, []byte("shim")) {
		t.Fatalf("event0 data: %q", events[0].Data)
	}
	if events[2].PCR != 17 || !bytes.Equal(events[2].Digests[sha256Alg], dC) {
		t.Fatalf("event2 wrong: %+v", events[2])
	}

	pcrs, err := ReplayPCRs(events, sha256Alg)
	if err != nil {
		t.Fatalf("ReplayPCRs: %v", err)
	}
	zero := make([]byte, 32)
	want16 := extend(extend(zero, dA), dB)
	want17 := extend(zero, dC)
	if !bytes.Equal(pcrs[16], want16) {
		t.Fatalf("PCR16 replay mismatch")
	}
	if !bytes.Equal(pcrs[17], want17) {
		t.Fatalf("PCR17 replay mismatch")
	}
}

// TestReplayUnsupportedAlg rejects a replay bank other than SHA-256.
func TestReplayUnsupportedAlg(t *testing.T) {
	if _, err := ReplayPCRs(nil, uint16(common.AlgSHA1)); err != ErrUnknownDigestAlg {
		t.Fatalf("got %v want ErrUnknownDigestAlg", err)
	}
}

// TestReplayMissingAlgDigest rejects an event lacking the replay bank's digest.
func TestReplayMissingAlgDigest(t *testing.T) {
	events := []Event{{PCR: 16, Digests: map[uint16][]byte{uint16(common.AlgSHA1): digestOf("x")}}}
	if _, err := ReplayPCRs(events, sha256Alg); err != ErrUnknownDigestAlg {
		t.Fatalf("got %v want ErrUnknownDigestAlg", err)
	}
}

// TestParseTruncatedHeader walks truncation points within the legacy header and
// the spec-ID body, asserting each yields a typed error (no panic).
func TestParseTruncatedHeader(t *testing.T) {
	header := NewLogBuilder().Bytes() // a valid, complete header (zero events)
	// Truncating at any length strictly shorter than the full header must error;
	// the complete header itself parses fine (covered by TestParseEmptyLogIsEvents).
	for n := 0; n < len(header); n++ {
		_, err := ParseEventLog(header[:n])
		if err == nil {
			t.Fatalf("len=%d parsed a truncated header", n)
		}
		if !errors.Is(err, ErrMalformedLog) && !errors.Is(err, ErrBadSpecID) {
			t.Fatalf("len=%d unexpected error %v", n, err)
		}
	}
}

// TestParseBadSpecIDSignature rejects a header whose signature is not
// "Spec ID Event03".
func TestParseBadSpecIDSignature(t *testing.T) {
	log := NewLogBuilder().Add(16, 0x0d, digestOf("a"), nil).Bytes()
	// The spec-ID signature is the first 16 bytes of the header body, which
	// begins after PCRIndex(4)+EventType(4)+SHA1(20)+EventSize(4) = 32 bytes.
	corrupt := append([]byte(nil), log...)
	corrupt[32] ^= 0xFF
	if _, err := ParseEventLog(corrupt); err != ErrBadSpecID {
		t.Fatalf("got %v want ErrBadSpecID", err)
	}
}

// TestParseSpecIDBodyTruncations wraps progressively-shorter spec-ID bodies in a
// correctly-sized legacy header (EventSize == body length) so each internal
// parseSpecID truncation branch (after signature, after platformClass, after the
// version bytes) is exercised, not the outer EventSize-overrun guard.
func TestParseSpecIDBodyTruncations(t *testing.T) {
	// A full, valid spec-ID body for reference.
	full := buildSpecIDHeader(1, []uint16{sha256Alg, sha256Size})
	// Recover just the spec body: strip the 32-byte legacy header prefix.
	body := full[32:]
	for n := 0; n < len(body); n++ {
		log := wrapLegacy(body[:n])
		_, err := ParseEventLog(log)
		if err != ErrBadSpecID {
			t.Fatalf("n=%d got %v want ErrBadSpecID", n, err)
		}
	}
}

// TestParseZeroAlgs rejects a spec-ID header declaring zero algorithms.
func TestParseZeroAlgs(t *testing.T) {
	log := buildSpecIDHeader(0, nil) // numberOfAlgorithms = 0
	if _, err := ParseEventLog(log); err != ErrBadSpecID {
		t.Fatalf("got %v want ErrBadSpecID", err)
	}
}

// TestParseTruncatedAlgList rejects a header whose algorithm list is cut short
// (count says 2 but only one (alg,size) pair is present).
func TestParseTruncatedAlgList(t *testing.T) {
	// numberOfAlgorithms = 2, but supply only the first pair's bytes.
	var spec []byte
	spec = append(spec, specIDSignature...)
	spec = putLE32(spec, 0)          // platformClass
	spec = append(spec, 0, 2, 0, 2)        // minor/major/errata/uintnSize
	spec = putLE32(spec, 2)          // numberOfAlgorithms = 2
	spec = putLE16(spec, sha256Alg)  // alg[0]
	spec = putLE16(spec, sha256Size) // size[0] (then truncated)
	log := wrapLegacy(spec)
	if _, err := ParseEventLog(log); err != ErrBadSpecID {
		t.Fatalf("got %v want ErrBadSpecID", err)
	}
}

// TestParseTruncatedAlgID rejects a header truncated mid algorithm ID.
func TestParseTruncatedAlgID(t *testing.T) {
	var spec []byte
	spec = append(spec, specIDSignature...)
	spec = putLE32(spec, 0)
	spec = append(spec, 0, 2, 0, 2)
	spec = putLE32(spec, 1)   // 1 algorithm
	spec = common.PutU8(spec, 0x00) // 1 stray byte: cannot read u16 algID
	log := wrapLegacy(spec)
	if _, err := ParseEventLog(log); err != ErrBadSpecID {
		t.Fatalf("got %v want ErrBadSpecID", err)
	}
}

// TestParseMissingVendorInfo rejects a header that ends before vendorInfoSize.
func TestParseMissingVendorInfo(t *testing.T) {
	var spec []byte
	spec = append(spec, specIDSignature...)
	spec = putLE32(spec, 0)
	spec = append(spec, 0, 2, 0, 2)
	spec = putLE32(spec, 1)
	spec = putLE16(spec, sha256Alg)
	spec = putLE16(spec, sha256Size) // ends here: no vendorInfoSize byte
	log := wrapLegacy(spec)
	if _, err := ParseEventLog(log); err != ErrBadSpecID {
		t.Fatalf("got %v want ErrBadSpecID", err)
	}
}

// TestParseTruncatedVendorInfo rejects a header whose vendorInfoSize claims more
// bytes than remain.
func TestParseTruncatedVendorInfo(t *testing.T) {
	var spec []byte
	spec = append(spec, specIDSignature...)
	spec = putLE32(spec, 0)
	spec = append(spec, 0, 2, 0, 2)
	spec = putLE32(spec, 1)
	spec = putLE16(spec, sha256Alg)
	spec = putLE16(spec, sha256Size)
	spec = common.PutU8(spec, 8) // vendorInfoSize=8 but no vendor bytes follow
	log := wrapLegacy(spec)
	if _, err := ParseEventLog(log); err != ErrBadSpecID {
		t.Fatalf("got %v want ErrBadSpecID", err)
	}
}

// TestParseEvent2Truncations truncates a valid log at every offset inside the
// first PCR_EVENT2 record and asserts a typed error at each point.
func TestParseEvent2Truncations(t *testing.T) {
	header := NewLogBuilder().Bytes() // header only, zero events
	full := NewLogBuilder().Add(16, 0x0d, digestOf("a"), []byte("d")).Bytes()
	for n := len(header) + 1; n < len(full); n++ {
		_, err := ParseEventLog(full[:n])
		if err == nil {
			t.Fatalf("len=%d parsed a truncated event2", n)
		}
		if !errors.Is(err, ErrMalformedLog) {
			t.Fatalf("len=%d unexpected error %v", n, err)
		}
	}
}

// TestParseEvent2UnknownAlg rejects an event2 whose digest algorithm was not
// declared in the spec-ID header.
func TestParseEvent2UnknownAlg(t *testing.T) {
	header := NewLogBuilder().Bytes()
	var ev []byte
	ev = putLE32(ev, 16)                       // PCRIndex
	ev = putLE32(ev, 0x0d)                     // EventType
	ev = putLE32(ev, 1)                        // count
	ev = putLE16(ev, uint16(common.AlgSHA384)) // undeclared alg
	ev = append(ev, make([]byte, 48)...)             // a SHA-384-sized digest
	ev = putLE32(ev, 0)                        // EventSize
	log := append(append([]byte(nil), header...), ev...)
	if _, err := ParseEventLog(log); err != ErrUnknownDigestAlg {
		t.Fatalf("got %v want ErrUnknownDigestAlg", err)
	}
}

// TestParseHeaderSizeOverflow rejects a header EventSize that runs past the
// buffer end (the spec-ID slice cannot be read).
func TestParseHeaderSizeOverflow(t *testing.T) {
	var out []byte
	out = putLE32(out, 0)
	out = putLE32(out, evNoAction)
	out = append(out, make([]byte, legacyDigestLen)...)
	out = putLE32(out, 0xFFFFFFFF) // EventSize huge: bytes() short-buffers
	if _, err := ParseEventLog(out); err != ErrMalformedLog {
		t.Fatalf("got %v want ErrMalformedLog", err)
	}
}

// TestParseEmptyLogIsEvents asserts a header-only log parses to zero events.
func TestParseEmptyLogIsEvents(t *testing.T) {
	events, err := ParseEventLog(NewLogBuilder().Bytes())
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("got %d events want 0", len(events))
	}
}

// buildSpecIDHeader renders a legacy-wrapped spec-ID header declaring numAlgs
// algorithms (each pair from algs, a flat [alg0,size0,alg1,size1,...]).
func buildSpecIDHeader(numAlgs uint32, algs []uint16) []byte {
	var spec []byte
	spec = append(spec, specIDSignature...)
	spec = putLE32(spec, 0)
	spec = append(spec, 0, 2, 0, 2)
	spec = putLE32(spec, numAlgs)
	for _, a := range algs {
		spec = putLE16(spec, a)
	}
	spec = common.PutU8(spec, 0) // vendorInfoSize
	return wrapLegacy(spec)
}

// wrapLegacy wraps a spec-ID body in the legacy TCG_PCR_EVENT header event.
func wrapLegacy(spec []byte) []byte {
	var out []byte
	out = putLE32(out, 0)
	out = putLE32(out, evNoAction)
	out = append(out, make([]byte, legacyDigestLen)...)
	out = putLE32(out, uint32(len(spec)))
	out = append(out, spec...)
	return out
}
