// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/attest authors. All rights reserved.

package attest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/go-tpm2/common"
	"github.com/go-tpm2/tpm2"
)

// These helpers let the Verifier — which is pure Go and off-TPM — be fully
// exercised without any TPM. We mint a real P-256 EK keypair and a real P-256
// AK keypair, run the production MakeCredential against an in-test inverse of
// ActivateCredential (proving the round-trip), and hand-build a signed
// TPMS_ATTEST for the admission path and every negative branch.

const (
	algECC      = 0x0023
	algSHA256   = 0x000B
	algECDSA    = 0x0018
	algAES      = 0x0006
	algCFB      = 0x0043
	eccNistP256 = 0x0003
	attestMagic = 0xFF544347
	stQuote     = 0x8018
)

// testKey is an in-test ECC P-256 key standing in for a TPM-resident EK or AK.
type testKey struct {
	priv *ecdsa.PrivateKey
	// pub is the TPMT_PUBLIC bytes carrying this key's point (EK or AK shape).
	pub []byte
}

// newAK mints a P-256 key and wraps its point in an AK-shaped (restricted
// signing) TPMT_PUBLIC, so ObjectName/parseECCPoint over pub agree with the
// signing key.
func newAK(t *testing.T) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return testKey{priv: priv, pub: akPublicArea(priv)}
}

// newEK mints a P-256 key and wraps its point in an EK-shaped (restricted
// decrypt, AES-128-CFB) TPMT_PUBLIC.
func newEK(t *testing.T) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return testKey{priv: priv, pub: ekPublicArea(priv)}
}

// fixed32be left-pads a big.Int to 32 bytes big-endian.
func fixed32be(n *big.Int) []byte {
	b := n.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// akPublicArea builds an ECC P-256 restricted-signing TPMT_PUBLIC for priv.
func akPublicArea(priv *ecdsa.PrivateKey) []byte {
	var p []byte
	p = common.PutU16(p, algECC)
	p = common.PutU16(p, algSHA256)
	p = common.PutU32(p, 0x00050072) // AK attributes (immaterial to parse)
	p = common.PutU16(p, 0)          // authPolicy: empty
	p = common.PutU16(p, 0x0010)     // symmetric = NULL
	p = common.PutU16(p, algECDSA)   // scheme = ECDSA
	p = common.PutU16(p, algSHA256)  // hashAlg
	p = common.PutU16(p, eccNistP256)
	p = common.PutU16(p, 0x0010) // kdf = NULL
	p = append(p, common.MarshalTPM2B(fixed32be(priv.X))...)
	p = append(p, common.MarshalTPM2B(fixed32be(priv.Y))...)
	return p
}

// ekPublicArea builds an EK-shaped ECC P-256 TPMT_PUBLIC for priv.
func ekPublicArea(priv *ecdsa.PrivateKey) []byte {
	return buildEKArea(fixed32be(priv.X), fixed32be(priv.Y))
}

// buildEKArea builds an EK-shaped ECC P-256 TPMT_PUBLIC from raw coordinate
// bytes (so a test can supply an off-curve point to exercise MakeCredential's
// rejection path).
func buildEKArea(x, y []byte) []byte {
	var p []byte
	p = common.PutU16(p, algECC)
	p = common.PutU16(p, algSHA256)
	p = common.PutU32(p, 0x000300B2)
	p = common.PutU16(p, 0)      // authPolicy empty (parse-immaterial)
	p = common.PutU16(p, algAES) // symmetric AES
	p = common.PutU16(p, 128)    // keyBits
	p = common.PutU16(p, algCFB) // mode CFB
	p = common.PutU16(p, 0x0010) // scheme = NULL
	p = common.PutU16(p, eccNistP256)
	p = common.PutU16(p, 0x0010) // kdf = NULL
	p = append(p, common.MarshalTPM2B(x)...)
	p = append(p, common.MarshalTPM2B(y)...)
	return p
}

// activateInverse is the in-test TPM-side recovery: given the EK private key
// and the AK Name, it inverts MakeCredential's outer wrap to recover the
// embedded credential. It mirrors makecred.go using the EXPORTED KDFa/KDFe, so
// a MakeCredential output round-trips to the original secret iff the AK Name
// and EK match — exactly what a real ActivateCredential proves.
func activateInverse(t *testing.T, ek *ecdsa.PrivateKey, akName, credentialBlob, secret []byte) []byte {
	t.Helper()
	// secret = TPM2B_ENCRYPTED_SECRET( TPM2B(Qe.x) || TPM2B(Qe.y) ).
	inner, _, err := common.UnmarshalTPM2B(secret)
	if err != nil {
		t.Fatalf("secret outer TPM2B: %v", err)
	}
	qx, rest, err := common.UnmarshalTPM2B(inner)
	if err != nil {
		t.Fatalf("Qe.x: %v", err)
	}
	qy, _, err := common.UnmarshalTPM2B(rest)
	if err != nil {
		t.Fatalf("Qe.y: %v", err)
	}
	curve := elliptic.P256()
	qxI := new(big.Int).SetBytes(qx)
	qyI := new(big.Int).SetBytes(qy)

	// Z = x-coord of ek_priv * Qe.
	zx, _ := curve.ScalarMult(qxI, qyI, ek.D.Bytes())
	z := leftPad32(zx.Bytes())

	ekX := fixed32be(ek.X)
	// seed = KDFe(Z, "IDENTITY", Qe.x, EK.x, 256).
	seed := tpm2.KDFe(z, "IDENTITY", leftPad32(qx), ekX, 256)
	symKey := tpm2.KDFa(seed, "STORAGE", akName, nil, 128)
	hmacKey := tpm2.KDFa(seed, "INTEGRITY", nil, nil, 256)

	// credentialBlob = TPM2B_ID_OBJECT( TPM2B(outerHMAC) || encIdentity ).
	idObj, _, err := common.UnmarshalTPM2B(credentialBlob)
	if err != nil {
		t.Fatalf("id object: %v", err)
	}
	outerHMAC, encIdentity, err := common.UnmarshalTPM2B(idObj)
	if err != nil {
		t.Fatalf("outer hmac: %v", err)
	}
	// Verify the outer HMAC over encIdentity || akName.
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encIdentity)
	mac.Write(akName)
	if !hmac.Equal(mac.Sum(nil), outerHMAC) {
		t.Fatalf("activateInverse: outer HMAC mismatch (wrong AK name or EK)")
	}
	// Decrypt encIdentity with AES-128-CFB / zero IV -> TPM2B(credential).
	block, err := aes.NewCipher(symKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	iv := make([]byte, block.BlockSize())
	plain := make([]byte, len(encIdentity))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plain, encIdentity)
	cred, _, err := common.UnmarshalTPM2B(plain)
	if err != nil {
		t.Fatalf("credential TPM2B: %v", err)
	}
	out := make([]byte, len(cred))
	copy(out, cred)
	return out
}

// leftPad32 left-pads b to 32 bytes.
func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// attestBuilder assembles a TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE that
// ParseAttest/VerifyQuote will accept, then signs SHA-256(attest) with an AK
// key. The PCR digest defaults to SHA-256 over the concatenated pcrValues.
type attestBuilder struct {
	extraData []byte
	pcrs      []int
	pcrValues [][]byte
	pcrDigest []byte // if nil, computed from pcrValues
	badMagic  bool
	notQuote  bool
}

// build renders the signed TPM2B_ATTEST.data bytes (what Quote returns).
func (b attestBuilder) build() []byte {
	magic := uint32(attestMagic)
	if b.badMagic {
		magic = 0xDEADBEEF
	}
	typ := uint16(stQuote)
	if b.notQuote {
		typ = 0x8017 // TPM_ST_ATTEST_CERTIFY (not a quote)
	}
	var a []byte
	a = common.PutU32(a, magic)
	a = common.PutU16(a, typ)
	a = append(a, common.MarshalTPM2B([]byte("signer"))...) // qualifiedSigner
	a = append(a, common.MarshalTPM2B(b.extraData)...)      // extraData
	// clockInfo (17 bytes): clock u64, resetCount u32, restartCount u32, safe u8.
	a = common.PutU64(a, 1)
	a = common.PutU32(a, 0)
	a = common.PutU32(a, 0)
	a = common.PutU8(a, 1)
	a = common.PutU64(a, 0) // firmwareVersion
	// attested = TPMS_QUOTE_INFO: TPML_PCR_SELECTION || TPM2B_DIGEST.
	a = append(a, marshalSelection(b.pcrs)...)
	pcrDigest := b.pcrDigest
	if pcrDigest == nil {
		h := sha256.New()
		for _, v := range b.pcrValues {
			h.Write(v)
		}
		pcrDigest = h.Sum(nil)
	}
	a = append(a, common.MarshalTPM2B(pcrDigest)...)
	return a
}

// sign builds the attest and signs it with ak, returning (quoted, r||s).
func (b attestBuilder) sign(t *testing.T, ak *ecdsa.PrivateKey) (quoted, sig []byte) {
	t.Helper()
	quoted = b.build()
	digest := sha256.Sum256(quoted)
	r, s, err := ecdsa.Sign(rand.Reader, ak, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	return quoted, JoinSignature(tpm2.ECDSASignature{R: r.Bytes(), S: s.Bytes()})
}

// marshalSelection renders a SHA-256-bank TPML_PCR_SELECTION over the given
// PCR indices (3-octet bitmap), matching the tpm2 package's wire shape.
func marshalSelection(pcrs []int) []byte {
	bitmap := make([]byte, 3)
	for _, p := range pcrs {
		if p >= 0 && p < 24 {
			bitmap[p/8] |= 1 << uint(p%8)
		}
	}
	out := common.PutU32(nil, 1) // one selection
	out = common.PutU16(out, algSHA256)
	out = common.PutU8(out, 3)
	out = append(out, bitmap...)
	return out
}
