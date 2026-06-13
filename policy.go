// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package attest

import (
	"crypto/subtle"
	"fmt"
	"sort"

	"github.com/go-tpm2/common"
)

// Policy decides whether a set of attested PCR values represents an approved
// boot. The verifier calls Matches AFTER it has cryptographically established
// that the PCR values are genuine (signature + nonce + pcrDigest all checked),
// so a Policy only has to compare values, never crypto.
type Policy interface {
	// Matches reports nil if the PCRs represent an approved stack, or a typed
	// error (e.g. *UntrustedBootError) naming the first failing PCR otherwise.
	Matches(pcrs map[int][]byte) error
}

// GoldenPolicy is the v0.1.0 Policy: a map of required PCR index -> expected
// digest. Matches requires every golden PCR to be present in the attested set
// AND to equal its golden value exactly; the first PCR that is missing or
// differs is named in the returned *UntrustedBootError. Attested PCRs not named
// in the golden map are ignored (the policy constrains only the PCRs it lists).
type GoldenPolicy map[int][]byte

// Matches checks every golden PCR against the attested values in ascending
// index order (so the "first mismatch" reported is deterministic).
func (g GoldenPolicy) Matches(pcrs map[int][]byte) error {
	idxs := make([]int, 0, len(g))
	for i := range g {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	for _, i := range idxs {
		want := g[i]
		got, ok := pcrs[i]
		if !ok {
			return &UntrustedBootError{PCR: i, Reason: "PCR not present in quote"}
		}
		if subtle.ConstantTimeCompare(want, got) != 1 {
			return &UntrustedBootError{PCR: i, Reason: "PCR value != golden"}
		}
	}
	return nil
}

// UntrustedBootError is the typed Policy failure: the index of the first PCR
// that did not match the policy, and a short reason. errors.As lets callers
// recover the PCR index for diagnostics. It satisfies ErrUntrustedBoot under
// errors.Is so callers can branch on the sentinel without unwrapping.
type UntrustedBootError struct {
	// PCR is the index of the first failing PCR.
	PCR int
	// Reason describes the failure (missing vs. value mismatch).
	Reason string
}

// Error implements the error interface.
func (e *UntrustedBootError) Error() string {
	return fmt.Sprintf("attest: untrusted boot: PCR %d: %s", e.PCR, e.Reason)
}

// Is reports that an *UntrustedBootError matches the ErrUntrustedBoot sentinel,
// so callers can write errors.Is(err, ErrUntrustedBoot).
func (e *UntrustedBootError) Is(target error) bool {
	return target == ErrUntrustedBoot
}

// ErrUntrustedBoot is the sentinel every Policy mismatch satisfies under
// errors.Is. A concrete *UntrustedBootError additionally names the PCR.
const ErrUntrustedBoot = common.Error("attest: untrusted boot (PCR policy mismatch)")

// EventLogPolicy is the planned v0.2 Policy that REPLAYS a TCG measured-boot
// event log against the attested PCRs and checks every measured event against
// an allowlist — closing the gap that GoldenPolicy needs a precomputed golden
// digest per platform. It is declared here as a documented stub so the
// interface and intent are stable.
//
// TODO(v0.2): implement TCG event-log (TPM2_EventLog / EFI_TCG2 format) replay:
//   - parse the event stream (spec-id header + per-event digests),
//   - fold each event's digest into a virtual PCR bank and assert the result
//     equals the attested PCR value (proves the log is consistent with the
//     quote), and
//   - check every event against an allowlist of approved measurements,
//
// then satisfy Policy by delegating value-level checks to a GoldenPolicy or to
// the replayed expectations.
type EventLogPolicy interface {
	Policy
	// Replay folds the event log into virtual PCRs and reports whether it is
	// consistent with the attested PCRs (stub for v0.2).
	Replay(eventLog []byte, pcrs map[int][]byte) error
}
