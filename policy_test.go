// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package attest

import (
	"bytes"
	"errors"
	"testing"
)

// TestGoldenPolicyMatch admits a PCR set that meets every golden value (and an
// empty golden policy admits anything).
func TestGoldenPolicyMatch(t *testing.T) {
	g := GoldenPolicy{0: bytes.Repeat([]byte{1}, 32), 7: bytes.Repeat([]byte{2}, 32)}
	pcrs := map[int][]byte{0: bytes.Repeat([]byte{1}, 32), 7: bytes.Repeat([]byte{2}, 32), 4: {0xFF}}
	if err := g.Matches(pcrs, nil); err != nil {
		t.Fatalf("Matches: %v", err)
	}
	if err := (GoldenPolicy{}).Matches(pcrs, nil); err != nil {
		t.Fatalf("empty policy: %v", err)
	}
}

// TestGoldenPolicyMissingPCR reports the first missing required PCR.
func TestGoldenPolicyMissingPCR(t *testing.T) {
	g := GoldenPolicy{0: {1}, 7: {2}}
	err := g.Matches(map[int][]byte{0: {1}}, nil) // 7 missing
	var ub *UntrustedBootError
	if !errors.As(err, &ub) || ub.PCR != 7 {
		t.Fatalf("got %v want UntrustedBootError PCR 7", err)
	}
	if !errors.Is(err, ErrUntrustedBoot) {
		t.Fatal("not ErrUntrustedBoot")
	}
	if ub.Error() == "" {
		t.Fatal("empty Error()")
	}
}

// TestGoldenPolicyValueMismatch reports the first PCR whose value differs.
func TestGoldenPolicyValueMismatch(t *testing.T) {
	g := GoldenPolicy{3: {0xAA}}
	err := g.Matches(map[int][]byte{3: {0xBB}}, nil)
	var ub *UntrustedBootError
	if !errors.As(err, &ub) || ub.PCR != 3 {
		t.Fatalf("got %v want UntrustedBootError PCR 3", err)
	}
}

// TestUntrustedBootErrorIsOther confirms Is only matches the sentinel.
func TestUntrustedBootErrorIsOther(t *testing.T) {
	e := &UntrustedBootError{PCR: 1, Reason: "x"}
	if e.Is(errors.New("other")) {
		t.Fatal("Is matched an unrelated error")
	}
}

// elpFixture builds a 3-measurement log over PCR16/17, the matching attested
// PCRs (computed by replay), and the digests, for the EventLogPolicy tests.
func elpFixture() (log []byte, pcrs map[int][]byte, dA, dB, dC []byte) {
	dA, dB, dC = digestOf("shim"), digestOf("grub"), digestOf("kernel")
	log = NewLogBuilder().
		Add(16, 0x0d, dA, nil).
		Add(16, 0x0d, dB, nil).
		Add(17, 0x05, dC, nil).
		Bytes()
	zero := make([]byte, 32)
	pcrs = map[int][]byte{
		16: extend(extend(zero, dA), dB),
		17: extend(zero, dC),
	}
	return
}

// TestEventLogPolicyAdmit is the happy path: a log that replays to the attested
// PCRs and whose every measurement is on the allowlist is admitted.
func TestEventLogPolicyAdmit(t *testing.T) {
	log, pcrs, dA, dB, dC := elpFixture()
	p := NewEventLogPolicy().
		AllowMeasurement(16, dA).
		AllowMeasurement(16, dB).
		AllowMeasurement(17, dC)
	if err := p.Matches(pcrs, log); err != nil {
		t.Fatalf("Matches: %v", err)
	}
}

// TestEventLogPolicyMalformed rejects a log that does not parse.
func TestEventLogPolicyMalformed(t *testing.T) {
	p := NewEventLogPolicy()
	if err := p.Matches(map[int][]byte{}, []byte{0x00, 0x01}); err != ErrMalformedLog {
		t.Fatalf("got %v want ErrMalformedLog", err)
	}
}

// TestEventLogPolicyReplayMissingAlg rejects a parsed log whose events lack the
// SHA-256 bank during the replay step (ReplayPCRs error path).
func TestEventLogPolicyReplayMissingAlg(t *testing.T) {
	// Build a header declaring SHA-1 only, with one SHA-1 event2.
	header := buildSpecIDHeaderAlg(uint16(0x0004), 20)
	var ev []byte
	ev = appendU32(ev, 16)
	ev = appendU32(ev, 0x0d)
	ev = appendU32(ev, 1)
	ev = appendU16(ev, 0x0004)           // SHA-1
	ev = append(ev, make([]byte, 20)...) // SHA-1 digest
	ev = appendU32(ev, 0)                // EventSize
	log := append(append([]byte(nil), header...), ev...)
	p := NewEventLogPolicy()
	if err := p.Matches(map[int][]byte{}, log); err != ErrUnknownDigestAlg {
		t.Fatalf("got %v want ErrUnknownDigestAlg", err)
	}
}

// TestEventLogPolicyTamperedReplay rejects a log whose replay does not equal the
// attested PCRs (one log digest corrupted): ErrEventLogMismatch.
func TestEventLogPolicyTamperedReplay(t *testing.T) {
	log, pcrs, dA, dB, dC := elpFixture()
	// Corrupt PCR16's attested value so the (correct) replay no longer matches.
	pcrs[16] = bytes.Repeat([]byte{0x99}, 32)
	p := NewEventLogPolicy().
		AllowMeasurement(16, dA).
		AllowMeasurement(16, dB).
		AllowMeasurement(17, dC)
	if err := p.Matches(pcrs, log); err != ErrEventLogMismatch {
		t.Fatalf("got %v want ErrEventLogMismatch", err)
	}
}

// TestEventLogPolicyPCRAbsent rejects a log that extends a PCR the quote omits.
func TestEventLogPolicyPCRAbsent(t *testing.T) {
	log, pcrs, _, _, _ := elpFixture()
	delete(pcrs, 17) // the log still extends PCR17
	p := NewEventLogPolicy()
	err := p.Matches(pcrs, log)
	var ub *UntrustedBootError
	if !errors.As(err, &ub) || ub.PCR != 17 {
		t.Fatalf("got %v want UntrustedBootError PCR 17", err)
	}
}

// TestEventLogPolicyUnapproved rejects a log whose first event is not on the
// allowlist (one measurement dropped): ErrUnapprovedMeasurement naming it.
func TestEventLogPolicyUnapproved(t *testing.T) {
	log, pcrs, dA, dB, _ := elpFixture()
	// Allowlist everything EXCEPT PCR17's kernel measurement (dC).
	p := NewEventLogPolicy().
		AllowMeasurement(16, dA).
		AllowMeasurement(16, dB)
	err := p.Matches(pcrs, log)
	var um *UnapprovedMeasurementError
	if !errors.As(err, &um) || um.PCR != 17 || um.EventType != 0x05 {
		t.Fatalf("got %v want UnapprovedMeasurementError PCR 17", err)
	}
	if !errors.Is(err, ErrUnapprovedMeasurement) {
		t.Fatal("not ErrUnapprovedMeasurement")
	}
	if um.Error() == "" {
		t.Fatal("empty Error()")
	}
}

// TestEventLogPolicyRestrictPCRs limits the replay-equality check to a subset of
// PCRs: a PCR outside the restriction need not be present in the quote, and a
// PCR inside it is still checked.
func TestEventLogPolicyRestrictPCRs(t *testing.T) {
	log, pcrs, dA, dB, dC := elpFixture()
	delete(pcrs, 17) // PCR17 absent from the quote, but not gated on
	p := NewEventLogPolicy().
		RestrictPCRs(16).
		AllowMeasurement(16, dA).
		AllowMeasurement(16, dB).
		AllowMeasurement(17, dC)
	if err := p.Matches(pcrs, log); err != nil {
		t.Fatalf("Matches: %v", err)
	}
}

// TestEventLogPolicyEmptyAllowlistRejectsFirst confirms an empty allowlist
// rejects the first event of a (replay-consistent) log.
func TestEventLogPolicyEmptyAllowlistRejectsFirst(t *testing.T) {
	log, pcrs, _, _, _ := elpFixture()
	p := NewEventLogPolicy() // empty allowlist
	var um *UnapprovedMeasurementError
	if err := p.Matches(pcrs, log); !errors.As(err, &um) || um.PCR != 16 {
		t.Fatalf("got %v want UnapprovedMeasurementError PCR 16", err)
	}
}

// TestUnapprovedMeasurementErrorIsOther confirms Is only matches the sentinel.
func TestUnapprovedMeasurementErrorIsOther(t *testing.T) {
	e := &UnapprovedMeasurementError{PCR: 1}
	if e.Is(errors.New("other")) {
		t.Fatal("Is matched an unrelated error")
	}
}

// small big-endian append helpers (kept local so policy_test does not depend on
// the common codec import directly).
func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// buildSpecIDHeaderAlg renders a legacy-wrapped spec-ID header declaring exactly
// one algorithm (alg) with digest width size.
func buildSpecIDHeaderAlg(alg uint16, size uint16) []byte {
	var spec []byte
	spec = append(spec, specIDSignature...)
	spec = appendU32(spec, 0)
	spec = append(spec, 0, 2, 0, 2)
	spec = appendU32(spec, 1)
	spec = appendU16(spec, alg)
	spec = appendU16(spec, size)
	spec = append(spec, 0) // vendorInfoSize
	return wrapLegacy(spec)
}
