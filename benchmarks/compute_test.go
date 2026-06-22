// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package benchmarks

// Benchmarks for go-tpm2/attest's PURE-GO compute paths — the work that is NOT
// a TPM round-trip and so is genuinely the library's own CPU cost:
//
//   - VerifyQuote      : parse TPMS_ATTEST + ECDSA-P256 verify + PCR-digest recompute
//   - ParseEventLog    : parse a crypto-agile TCG measured-boot log
//   - ReplayPCRs       : fold the parsed events into virtual PCRs (SHA-256)
//   - MakeCredential   : off-TPM ECC credential protection (ECDH + KDFa/KDFe + AES + HMAC)
//
// HONEST baseline: github.com/google/go-tpm's CORE library ships none of these
// (no quote verification, no event-log parser, no MakeCredential — those live
// in the separate go-tpm-tools / go-attestation projects, which pull large
// dependency trees). So the fair, dependency-free baseline here is the Go
// standard-library crypto each path is built on — the irreducible cost any
// verifier, including a go-tpm-based one, must pay. Where our op does strictly
// more than the baseline (parsing + a digest recompute on top of the verify),
// the delta is the library's parsing/framing overhead, which is what we want
// to show is small.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/go-tpm2/attest"
	"github.com/go-tpm2/common"
	"github.com/go-tpm2/tpm2"
)

// ===========================================================================
// VerifyQuote
// ===========================================================================

// quoteFixture is a valid signed quote plus everything VerifyQuote needs.
type quoteFixture struct {
	akPub     tpm2.AKPublic
	quoted    []byte
	sig       tpm2.ECDSASignature
	expected  [][]byte
	rawPub    *ecdsa.PublicKey
	digestSum []byte // SHA-256(quoted), the message the signature covers
}

func makeQuoteFixture(b *testing.B) quoteFixture {
	b.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	pcrs := []int{0, 1, 7}
	pcrValues := [][]byte{fill(32, 0x11), fill(32, 0x22), fill(32, 0x33)}

	// Build a TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE that ParseAttest accepts.
	h := sha256.New()
	for _, v := range pcrValues {
		h.Write(v)
	}
	pcrDigest := h.Sum(nil)

	var a []byte
	a = common.PutU32(a, 0xFF544347) // TPM_GENERATED_VALUE
	a = common.PutU16(a, 0x8018)     // TPM_ST_ATTEST_QUOTE
	a = append(a, common.MarshalTPM2B([]byte("signer"))...)
	a = append(a, common.MarshalTPM2B(fill(32, 0xEE))...) // extraData (nonce)
	a = common.PutU64(a, 1)                               // clock
	a = common.PutU32(a, 0)                               // resetCount
	a = common.PutU32(a, 0)                               // restartCount
	a = common.PutU8(a, 1)                                // safe
	a = common.PutU64(a, 0)                               // firmwareVersion
	a = append(a, marshalSelection(pcrs)...)              // TPML_PCR_SELECTION
	a = append(a, common.MarshalTPM2B(pcrDigest)...)      // TPM2B_DIGEST

	digest := sha256.Sum256(a)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		b.Fatalf("Sign: %v", err)
	}
	return quoteFixture{
		akPub:     tpm2.AKPublic{X: fixed32(priv.X), Y: fixed32(priv.Y)},
		quoted:    a,
		sig:       tpm2.ECDSASignature{R: r.Bytes(), S: s.Bytes()},
		expected:  pcrValues,
		rawPub:    &priv.PublicKey,
		digestSum: digest[:],
	}
}

// BenchmarkVerifyQuote_Ours measures the full attestation check: parse the
// TPMS_ATTEST, ECDSA-verify it, and recompute+compare the PCR digest.
func BenchmarkVerifyQuote_Ours(b *testing.B) {
	f := makeQuoteFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tpm2.VerifyQuote(f.akPub, f.quoted, f.sig, f.expected); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyQuote_StdlibBaseline measures ONLY the irreducible crypto: the
// ECDSA-P256 signature verify over the same message. The gap to _Ours is our
// parse + PCR-digest-recompute overhead (the value the library adds).
func BenchmarkVerifyQuote_StdlibBaseline(b *testing.B) {
	f := makeQuoteFixture(b)
	r := new(big.Int).SetBytes(f.sig.R)
	s := new(big.Int).SetBytes(f.sig.S)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ecdsa.Verify(f.rawPub, f.digestSum, r, s) {
			b.Fatal("verify failed")
		}
	}
}

// ===========================================================================
// Event log: ParseEventLog + ReplayPCRs
// ===========================================================================

// makeEventLog builds a crypto-agile TCG log of n SHA-256 measurements spread
// over PCRs 0..7, using the library's own LogBuilder (exported API).
func makeEventLog(n int) []byte {
	lb := attest.NewLogBuilder()
	for i := 0; i < n; i++ {
		d := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		lb.Add(i%8, 0x0000000D /* EV_EVENT_TAG */, d[:], []byte("m"))
	}
	return lb.Bytes()
}

func benchEventLog(b *testing.B, n int) {
	log := makeEventLog(n)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		events, err := attest.ParseEventLog(log)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := attest.ReplayPCRs(events, uint16(common.AlgSHA256)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEventLog_Parse_Replay_16(b *testing.B)  { benchEventLog(b, 16) }
func BenchmarkEventLog_Parse_Replay_64(b *testing.B)  { benchEventLog(b, 64) }
func BenchmarkEventLog_Parse_Replay_256(b *testing.B) { benchEventLog(b, 256) }

// BenchmarkEventLog_ReplayBaseline_256 measures ONLY the SHA-256 extend chain
// (256 events) — the irreducible replay cost — so the delta to the full
// Parse_Replay_256 above is our parser's framing overhead.
func BenchmarkEventLog_ReplayBaseline_256(b *testing.B) {
	const n = 256
	digests := make([][]byte, n)
	for i := range digests {
		d := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		digests[i] = d[:]
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pcrs := make(map[int][]byte)
		for j, d := range digests {
			pcr := j % 8
			cur, ok := pcrs[pcr]
			if !ok {
				cur = make([]byte, 32)
			}
			next := sha256.Sum256(append(append([]byte(nil), cur...), d...))
			pcrs[pcr] = next[:]
		}
	}
}

// ===========================================================================
// MakeCredential
// ===========================================================================

func makeCredFixture(b *testing.B) (tpm2.EKPublic, []byte, []byte) {
	b.Helper()
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("EK GenerateKey: %v", err)
	}
	ak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("AK GenerateKey: %v", err)
	}
	// AK Name from its TPMT_PUBLIC, the value MakeCredential commits to.
	akName, err := tpm2.ObjectName(akPublicArea(ak))
	if err != nil {
		b.Fatalf("ObjectName: %v", err)
	}
	secret := fill(32, 0x5A)
	return tpm2.EKPublic{X: fixed32(ek.X), Y: fixed32(ek.Y)}, akName, secret
}

// BenchmarkMakeCredential_Ours measures the full off-TPM credential protection:
// ephemeral keygen + ECDH + KDFe/KDFa + AES-128-CFB + HMAC-SHA256 framing.
func BenchmarkMakeCredential_Ours(b *testing.B) {
	ekPub, akName, secret := makeCredFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tpm2.MakeCredential(ekPub, akName, secret, rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMakeCredential_KeygenBaseline measures ONLY the dominant cost inside
// MakeCredential: generating the ephemeral P-256 key pair. This shows the
// credential-protection wrap (KDF + AES + HMAC) adds little over the keygen.
func BenchmarkMakeCredential_KeygenBaseline(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

// ===========================================================================
// helpers (exported-API-only fixtures)
// ===========================================================================

func fill(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func fixed32(n *big.Int) []byte {
	b := n.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// marshalSelection renders a SHA-256-bank TPML_PCR_SELECTION over pcrs.
func marshalSelection(pcrs []int) []byte {
	bitmap := make([]byte, 3)
	for _, p := range pcrs {
		if p >= 0 && p < 24 {
			bitmap[p/8] |= 1 << uint(p%8)
		}
	}
	out := common.PutU32(nil, 1)
	out = common.PutU16(out, uint16(common.AlgSHA256))
	out = common.PutU8(out, 3)
	return append(out, bitmap...)
}

// akPublicArea builds an ECC P-256 restricted-signing TPMT_PUBLIC for priv,
// matching the tpm2 package's AK shape so ObjectName yields the AK Name.
func akPublicArea(priv *ecdsa.PrivateKey) []byte {
	var p []byte
	p = common.PutU16(p, 0x0023)     // TPM_ALG_ECC
	p = common.PutU16(p, 0x000B)     // nameAlg = SHA256
	p = common.PutU32(p, 0x00050072) // objectAttributes
	p = common.PutU16(p, 0)          // authPolicy empty
	p = common.PutU16(p, 0x0010)     // symmetric = NULL
	p = common.PutU16(p, 0x0018)     // scheme = ECDSA
	p = common.PutU16(p, 0x000B)     // hashAlg = SHA256
	p = common.PutU16(p, 0x0003)     // curve = NIST P-256
	p = common.PutU16(p, 0x0010)     // kdf = NULL
	p = append(p, common.MarshalTPM2B(fixed32(priv.X))...)
	p = append(p, common.MarshalTPM2B(fixed32(priv.Y))...)
	return p
}
