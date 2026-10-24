// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeGCEVTPM stands in for tpm2-tools over a Compute Engine vTPM: Google's
// AK template at NV 0x01c10001 (the one the kit read), a certificate for the
// key that template makes, and quotes that key signs over a fixed PCR
// digest. It records every tool call.
type fakeGCEVTPM struct {
	t          *testing.T
	key        *rsa.PrivateKey
	template   []byte
	certDER    []byte
	digest     []byte
	calls      []string
	failQuotes int
	makes      int
}

func newFakeGCEVTPM(t *testing.T) *fakeGCEVTPM {
	t.Helper()
	tmpl, err := os.ReadFile("testdata/gce-vtpm/ak-template-rsa.bin")
	require.NoError(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &fakeGCEVTPM{t: t, key: key, template: tmpl, certDER: gceAKCertForKey(t, &key.PublicKey), digest: bytes.Repeat([]byte{0x5A}, 32)}
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	runCommand = f.run
	oldFetch := gceFetchIntermediate
	t.Cleanup(func() { gceFetchIntermediate = oldFetch })
	gceFetchIntermediate = func(string, time.Duration) ([]byte, error) { return gceAKCertForKey(t, &key.PublicKey), nil }
	return f
}

func gceAKCertForKey(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "an attestation key"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IssuingCertificateURL: []string{"http://issuer.example/ca.crt"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	require.NoError(t, err)
	return der
}

func (f *fakeGCEVTPM) run(_ time.Duration, argv ...string) ([]byte, error) {
	name := filepath.Base(argv[0])
	f.calls = append(f.calls, name+" "+strings.Join(argv[1:], " "))
	arg := func(flag string) string {
		for i := range argv {
			if argv[i] == flag && i+1 < len(argv) {
				return argv[i+1]
			}
		}
		return ""
	}
	switch name {
	case "tpm2_nvread":
		switch argv[len(argv)-1] {
		case gceAKTemplateNVIndexRSA:
			return f.template, nil
		case gceAKCertNVIndexRSA:
			return append(append([]byte(nil), f.certDER...), make([]byte, 64)...), nil // the NV slot is larger than the certificate
		}
		return nil, errors.New("no such NV index")
	case "tpm2_createprimary":
		if arg("-C") != "e" || arg("-G") != "rsa2048:rsassa-sha256:null" {
			return nil, errors.New("not the template's key")
		}
		f.makes++
		return nil, os.WriteFile(arg("-c"), []byte("ak context"), 0o600)
	case "tpm2_readpublic":
		der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
		if err != nil {
			return nil, err
		}
		return nil, os.WriteFile(arg("-o"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
	case "tpm2_quote":
		if f.failQuotes > 0 {
			f.failQuotes--
			return nil, errors.New("the context is gone (TPM_RC_REFERENCE_H0)")
		}
		challenge, err := hex.DecodeString(arg("-q"))
		if err != nil {
			return nil, err
		}
		msg := f.attest(challenge, arg("-l"))
		h := sha256.Sum256(msg)
		sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, h[:])
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(arg("-m"), msg, 0o600); err != nil {
			return nil, err
		}
		return nil, os.WriteFile(arg("-s"), sig, 0o600)
	}
	return nil, os.ErrNotExist
}

// attest builds a TPMS_ATTEST of type quote over the selection.
func (f *fakeGCEVTPM) attest(extra []byte, selection string) []byte {
	var b bytes.Buffer
	w16 := func(v uint16) { _ = binary.Write(&b, binary.BigEndian, v) }
	w32 := func(v uint32) { _ = binary.Write(&b, binary.BigEndian, v) }
	w32(tpmGeneratedValue)
	w16(tpmSTAttestQuote)
	w16(4)
	b.WriteString("qual")
	w16(uint16(len(extra)))
	b.Write(extra)
	_ = binary.Write(&b, binary.BigEndian, uint64(1)) // clock
	w32(1)                                            // reset count
	w32(1)                                            // restart count
	b.WriteByte(1)                                    // safe
	_ = binary.Write(&b, binary.BigEndian, uint64(0x20160511))
	w32(1) // one selection
	w16(tpmAlgSHA256)
	b.WriteByte(3)
	var bits [3]byte
	for _, p := range strings.Split(strings.TrimPrefix(selection, "sha256:"), ",") {
		var n int
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		bits[n/8] |= 1 << (n % 8)
	}
	b.Write(bits[:])
	w16(uint16(len(f.digest)))
	b.Write(f.digest)
	return b.Bytes()
}

// The producer makes the key from Google's template, checks it is the
// certified one, takes the intermediate from the certificate's issuer URL,
// and quotes this boot once.
func TestOpenGCEVTPMMakesTheCertifiedKey(t *testing.T) {
	f := newFakeGCEVTPM(t)
	v, err := openGCEVTPM("", "", nil, time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.close() })
	require.Equal(t, DefaultGCEBootPCRs, v.pcrs)
	require.Equal(t, f.certDER, v.akCert, "the certificate cut to its own length")
	require.Len(t, v.inter, 1)
	require.Equal(t, f.digest, v.boot.PCRDigest)
	spki, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	require.NoError(t, err)
	require.Equal(t, spki, v.akSPKI)
	require.Contains(t, strings.Join(f.calls, "\n"), "-a fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign")
}

func TestOpenGCEVTPMRefusesAnotherKeysCertificate(t *testing.T) {
	f := newFakeGCEVTPM(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f.certDER = gceAKCertForKey(t, &other.PublicKey)
	_, err = openGCEVTPM("", "", nil, time.Minute)
	require.ErrorContains(t, err, "is not the key its certificate names")
}

func TestOpenGCEVTPMTakesTheOperatorsIntermediate(t *testing.T) {
	newFakeGCEVTPM(t)
	gceFetchIntermediate = func(string, time.Duration) ([]byte, error) { return nil, errors.New("no network") }
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	inter := gceAKCertForKey(t, &k.PublicKey)
	v, err := openGCEVTPM("", "", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter}), time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.close() })
	require.Equal(t, [][]byte{inter}, v.inter)
}

// A long-lived daemon's context can be lost; the key is made again from the
// template and the quote taken once more.
func TestGCEVTPMQuoteMakesTheKeyAgainOnce(t *testing.T) {
	f := newFakeGCEVTPM(t)
	v, err := openGCEVTPM("", "", nil, time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.close() })
	f.failQuotes = 1
	msg, sig, err := v.quote(tpmQuoteExtraDataFor([]byte("a nonce of thirty-two bytes ok..")))
	require.NoError(t, err)
	require.NoError(t, verifyTPMQuoteSignature(v.akPub, msg, sig))
	require.Equal(t, 2, f.makes, "made at start and again after the lost context")
	f.failQuotes = 2
	_, _, err = v.quote(tpmQuoteExtraDataFor([]byte("a nonce of thirty-two bytes ok..")))
	require.ErrorContains(t, err, "the context is gone")
}

// The chip's report names the vTPM's key in the second half of REPORT_DATA;
// the envelope carries the report, the certificate, the intermediates and
// the quote for the nonce.
func TestGCPSEVVTPMProducerQuoteBindsTheKeyInTheReport(t *testing.T) {
	newFakeGCEVTPM(t)
	vt, err := openGCEVTPM("", "", nil, time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { _ = vt.close() })

	// The chip: boot B's report, its REPORT_DATA set to what was asked (the
	// producer reads the report, the verifier checks its signature).
	var env gcpSEVVTPMEvidence
	raw, err := os.ReadFile("testdata/gce-vtpm/boot-b/evidence.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &env))
	tsm := &echoTSM{captured: env.Report}
	chip, err := newGCPSEVProducer(GCPSEVProducerConfig{}, tsm)
	require.NoError(t, err)
	p := &GCPSEVVTPMProducer{chip: chip, vtpm: vt}

	nonce := []byte("the challenger's nonce, 32 bytes")
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	var got gcpSEVVTPMEvidence
	require.NoError(t, json.Unmarshal(ev, &got))
	require.Equal(t, GCPSEVVTPMEvidenceSchema, got.Schema)
	report, err := parseSEVSNPReport(got.Report)
	require.NoError(t, err)
	n := sha256.Sum256(nonce)
	ak := sha256.Sum256(vt.akSPKI)
	require.Equal(t, n[:], report.ReportData[:32])
	require.Equal(t, ak[:], report.ReportData[32:])
	q, err := parseTPMQuote(got.QuoteMessage)
	require.NoError(t, err)
	require.Equal(t, n[:], q.ExtraData)
	require.Equal(t, vt.akCert, got.AKCertificate)

	_, err = p.Quote([]byte("short"))
	require.Error(t, err)
	require.NoError(t, p.Close())
}

// echoTSM answers with a captured report whose REPORT_DATA is what was asked.
type echoTSM struct{ captured []byte }

func (e *echoTSM) report(reportData [64]byte, _ uint32) ([]byte, []byte, error) {
	out := append([]byte(nil), e.captured...)
	copy(out[0x50:0x90], reportData[:])
	return out, nil, nil
}

func TestDERLength(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		want int
		err  bool
	}{
		{[]byte{0x30, 0x03, 1, 2, 3, 0, 0}, 5, false},
		{[]byte{0x30, 0x82, 0x00, 0x02, 1, 2, 0}, 6, false},
		{[]byte{0x31, 0x01, 0}, 0, true},
		{[]byte{0x30, 0x85, 0, 0, 0, 0, 1}, 0, true},
		{[]byte{0x30, 0x82, 0x01, 0x00}, 0, true},
	} {
		n, err := derLength(tc.in)
		if tc.err {
			require.Error(t, err, "%x", tc.in)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, tc.want, n)
	}
}
