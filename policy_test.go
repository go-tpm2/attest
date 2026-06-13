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
	if err := g.Matches(pcrs); err != nil {
		t.Fatalf("Matches: %v", err)
	}
	if err := (GoldenPolicy{}).Matches(pcrs); err != nil {
		t.Fatalf("empty policy: %v", err)
	}
}

// TestGoldenPolicyMissingPCR reports the first missing required PCR.
func TestGoldenPolicyMissingPCR(t *testing.T) {
	g := GoldenPolicy{0: {1}, 7: {2}}
	err := g.Matches(map[int][]byte{0: {1}}) // 7 missing
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
	err := g.Matches(map[int][]byte{3: {0xBB}})
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
