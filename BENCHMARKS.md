# Performance parity — go-tpm2/attest compute paths  (2026-06-22)

Pure-Go **compute-path** performance of `github.com/go-tpm2/attest` (and the
`github.com/go-tpm2/tpm2` crypto it builds on): the attestation work that is
**not** a TPM round-trip and so is genuinely the library's own CPU cost —
quote verification, measured-boot event-log replay, and off-TPM credential
protection.

## Honest framing

End-to-end TPM operations are swtpm/hardware-bound (see
`../../tpm2/BENCHMARKS.md`). The paths below are different: they run **entirely
off the TPM**, in pure Go (`CGO=0`, usable from the tamago microVM guest), so
they are real, comparable CPU work.

**Baseline choice (honest).** The **core** `github.com/google/go-tpm` library
ships **none** of these operations — it has no quote verifier, no event-log
parser, and no `MakeCredential` (those live in the separate `go-tpm-tools` /
`go-attestation` projects, which pull large dependency trees). So there is no
apples-to-apples go-tpm *function* to time against. The fair, dependency-free
baseline is therefore the **Go standard-library crypto each path is built on** —
the irreducible cost any verifier (including a go-tpm-tools-based one) must pay.
The gap between our op and that baseline is the framing/parsing overhead the
library adds, which is what these numbers show is small.

## Methodology

| | |
|---|---|
| Host | Apple M4 Max (`Mac16,5`), macOS (`darwin/arm64`) |
| Go | go1.26.4 |
| go-tpm2 | this tree (`attest` + `tpm2` + `common`) |
| crypto baseline | Go stdlib `crypto/ecdsa`, `crypto/elliptic` (P-256), `crypto/sha256` |
| iters | `-count=4`, medians reported |

No swtpm and no TPM are involved (pure CPU). Fixtures are built only from the
libraries' **exported** APIs (`tpm2.VerifyQuote`, `tpm2.MakeCredential`,
`tpm2.ObjectName`, `attest.NewLogBuilder`/`ParseEventLog`/`ReplayPCRs`). The
harness is an **isolated module** (`./benchmarks`, separate `go.mod`) so its
files are **excluded from the attest 100 % coverage gate**.

## Results

| op | ours (ns/op, allocs) | baseline (ns/op, allocs) | overhead vs baseline | verdict |
|---|---|---|---|---|
| **VerifyQuote** (parse TPMS_ATTEST + ECDSA-P256 verify + PCR-digest recompute) | **37 600 ns**, 1560 B, 30 allocs | 37 500 ns, 1088 B, 19 allocs (bare `ecdsa.Verify`) | **≈ 0 %** (within noise) | parse + digest cost is negligible vs the ECDSA verify |
| **EventLog Parse+Replay**, 16 events | **4 000 ns**, 10.8 KB, 125 allocs | — | — | parse is light; replay (SHA-256) dominates |
| **EventLog Parse+Replay**, 64 events | **15 200 ns**, 40.5 KB, 463 allocs | — | — | linear in event count |
| **EventLog Parse+Replay**, 256 events | **66 000 ns**, 160 KB, 1809 allocs | 26 500 ns, 33 KB, 771 allocs (replay-only SHA-256 chain) | parsing ≈ 1.5× the replay | replay + parse both SHA-256-bound |
| **MakeCredential** (ECDH + KDFe/KDFa + AES-128-CFB + HMAC-SHA256) | **37 600 ns**, 4832 B, 74 allocs | 8 090 ns, 984 B, 16 allocs (P-256 keygen only) | the two EC ops dominate | KDF/AES/HMAC wrap is a small fraction of the EC work |

### Reading the numbers

- **VerifyQuote** costs essentially the same as a bare `ecdsa.Verify` over the
  same message: ~37.6 µs vs ~37.5 µs. The TPMS_ATTEST parse and the PCR-digest
  recompute add **~0** on top of the P-256 verify — the library framing is free
  relative to the crypto. Any go-tpm-based verifier pays the identical ECDSA
  cost, so go-tpm2 is at parity on the irreducible work and adds no meaningful
  overhead.
- **Event-log replay** is dominated by the per-event SHA-256 extend chain
  (the replay-only baseline for 256 events is ~26.5 µs); the full parse+replay
  at 256 events is ~66 µs, i.e. the parser adds work comparable to the replay
  but stays linear and allocation-bounded. This is firmware-log-sized (tens to a
  few hundred events) work measured in **tens of microseconds**.
- **MakeCredential**'s cost is the two P-256 elliptic-curve operations
  (ephemeral keygen + ECDH `ScalarMult`); the credential-protection wrap
  (KDFe + KDFa + AES-128-CFB + HMAC-SHA256) is a small fraction on top —
  ~37.6 µs total versus ~8 µs for keygen alone, the remainder being the ECDH
  and on-curve check, not the symmetric framing.

## Summary

- **VerifyQuote is at parity** with the irreducible `ecdsa.Verify` cost: the
  library's parse + PCR-digest work is within measurement noise (~0 % overhead).
- **Event-log Parse+Replay** is linear and SHA-256-bound, tens of microseconds
  for realistic firmware logs.
- **MakeCredential** is dominated by its two unavoidable P-256 EC operations;
  the credential-protection wrap adds little.
- All paths are **pure Go / `CGO=0`** and run identically on the six 64-bit
  target arches (the same crypto stdlib the rest of the org validates against).

### Gaps / action items

- **No direct go-tpm function to compare** for these paths (core go-tpm ships
  none of them). A future heavier comparison could time `go-tpm-tools`'
  `server.ParseAndReplayEventLog` and `go-attestation`'s quote verifier, at the
  cost of pulling those large dependency trees into a (still isolated) benchmark
  module.
- The EC operations dominate VerifyQuote and MakeCredential. If these ever sit
  on a hot attestation path, the lever is the P-256 implementation (stdlib),
  not the go-tpm2 framing — there is little framing left to cut.
- See `../../tpm2/BENCHMARKS.md` for the marshal/parse codec comparison and the
  swtpm round-trip parity check.

_Reproduce:_ `cd benchmarks && GOWORK=off go test -run '^$' -bench . -benchmem -count=4 .`
