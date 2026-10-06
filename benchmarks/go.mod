// Isolated benchmark module for go-tpm2/attest's pure-Go compute paths
// (VerifyQuote, ParseEventLog/ReplayPCRs, MakeCredential). Kept out of the
// attest module so the benchmark files are excluded from its 100%-coverage
// gate. It depends on the library under test and on the Go standard library
// crypto primitives that any TPM-attestation verifier (including a
// google/go-tpm-based one) must call, used as the irreducible-cost baseline.
module github.com/go-tpm2/attest/benchmarks

go 1.27.1

require (
	github.com/go-tpm2/attest v0.5.0
	github.com/go-tpm2/common v0.3.0
	github.com/go-tpm2/tpm2 v0.8.0
)

replace (
	github.com/go-tpm2/attest => ../
	github.com/go-tpm2/common => ../../common
	github.com/go-tpm2/tpm2 => ../../tpm2
)
