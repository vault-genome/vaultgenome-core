// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The attestation key of a Compute Engine vTPM (ADR 0037). Google provisions
// every instance's vTPM with an attestation key and a certificate for it in
// the vTPM's NV storage — the RSA key's certificate at index 0x01c10000, its
// template at 0x01c10001 — issued by Google's EK/AK CA through an
// intermediate. The certificate names, under OID 1.3.6.1.4.1.11129.2.1.21,
// the instance it was issued to: its zone, project number and id, instance
// id and name, and whether it is a production instance — the fields Google's
// own verifier reads, and which it requires to say production (go-tpm-tools,
// server/instance_info.go). This file verifies such a certificate to a
// pinned root and reads the instance from it; the quote the key signs is
// checked by sev_snp_vtpm.go.

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// The NV indices of a Compute Engine vTPM's RSA attestation key
// (go-tpm-tools, client/handles.go).
const (
	gceAKCertNVIndexRSA     = "0x01c10000"
	gceAKTemplateNVIndexRSA = "0x01c10001"
)

var oidGCEInstanceInfo = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 21}

// GCEInstance is the instance a vTPM's attestation-key certificate names.
type GCEInstance struct {
	Zone            string `json:"zone"`
	ProjectNumber   uint64 `json:"project_number"`
	ProjectID       string `json:"project_id"`
	InstanceID      uint64 `json:"instance_id"`
	InstanceName    string `json:"instance_name"`
	SecurityVersion int64  `json:"security_version"`
	IsProduction    bool   `json:"is_production"`
}

// parseGCEInstance reads the instance information extension: a SEQUENCE of
// the zone, the project number, the project id, the instance id, the
// instance name and, explicitly tagged [0], the security properties, of
// which the first two — [0] the security version, [1] production — are
// read here; any that follow are Google's and are left alone.
func parseGCEInstance(cert *x509.Certificate) (GCEInstance, error) {
	var g GCEInstance
	var raw []byte
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidGCEInstanceInfo) {
			raw = e.Value
			break
		}
	}
	if raw == nil {
		return g, errors.New("the certificate names no Compute Engine instance (no extension 1.3.6.1.4.1.11129.2.1.21)")
	}
	in := cryptobyte.String(raw)
	var seq, zone, project, name cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		return g, errors.New("instance information: not one SEQUENCE")
	}
	if !seq.ReadASN1(&zone, cbasn1.UTF8String) || !seq.ReadASN1Integer(&g.ProjectNumber) ||
		!seq.ReadASN1(&project, cbasn1.UTF8String) || !seq.ReadASN1Integer(&g.InstanceID) ||
		!seq.ReadASN1(&name, cbasn1.UTF8String) {
		return g, errors.New("instance information: the zone, project and instance are malformed")
	}
	g.Zone, g.ProjectID, g.InstanceName = string(zone), string(project), string(name)
	var props cryptobyte.String
	var present bool
	if !seq.ReadOptionalASN1(&props, &present, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return g, errors.New("instance information: the security properties are malformed")
	}
	if present {
		var inner, v cryptobyte.String
		var ok bool
		if !props.ReadASN1(&inner, cbasn1.SEQUENCE) {
			return g, errors.New("instance information: the security properties are not a SEQUENCE")
		}
		if !inner.ReadOptionalASN1(&v, &ok, cbasn1.Tag(0).Constructed().ContextSpecific()) || (ok && !v.ReadASN1Integer(&g.SecurityVersion)) {
			return g, errors.New("instance information: the security version is malformed")
		}
		if !inner.ReadOptionalASN1(&v, &ok, cbasn1.Tag(1).Constructed().ContextSpecific()) || (ok && !v.ReadASN1Boolean(&g.IsProduction)) {
			return g, errors.New("instance information: the production flag is malformed")
		}
	}
	return g, nil
}

// gceAK is a verified attestation key: its certificate, its key and the
// instance the certificate names.
type gceAK struct {
	Cert     *x509.Certificate
	Key      *rsa.PublicKey
	Instance GCEInstance
}

// gceEKAKRoots is the pinned root, with any the operator adds.
func gceEKAKRoots(extraPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, src := range [][]byte{[]byte(GCEEKAKRootPEM), extraPEM} {
		for rest := src; len(rest) > 0; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("EK/AK root: %w", err)
			}
			pool.AddCert(c)
		}
	}
	return pool, nil
}

// verifyGCEAKCertificate verifies an attestation key's certificate to the
// roots through the intermediates given, and reads its key and instance. A
// key under 2048 bits, a certificate that names no instance, and an
// instance that is not production are refused.
func verifyGCEAKCertificate(leafDER []byte, intermediatesDER [][]byte, roots *x509.CertPool, now time.Time) (*gceAK, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("the AK certificate: %w", err)
	}
	inter := x509.NewCertPool()
	for i, d := range intermediatesDER {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, fmt.Errorf("the AK certificate's intermediate %d: %w", i, err)
		}
		inter.AddCert(c)
	}
	// The TCG's key purposes (tcg-kp-EKCertificate on the root) are unknown
	// to crypto/x509; the chain, not the purpose, is what is checked.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("the AK certificate does not chain to the pinned EK/AK root: %w", err)
	}
	key, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("the AK certificate's key is %T, want RSA of at least 2048 bits", leaf.PublicKey)
	}
	inst, err := parseGCEInstance(leaf)
	if err != nil {
		return nil, err
	}
	if !inst.IsProduction {
		return nil, fmt.Errorf("the AK certificate's instance %s/%s is not a production instance", inst.ProjectID, inst.InstanceName)
	}
	return &gceAK{Cert: leaf, Key: key, Instance: inst}, nil
}

// gceAKTemplate is the TPMT_PUBLIC of a vTPM's RSA attestation key as Google
// stores it at NV index 0x01c10001 (TPM 2.0 Part 2, 12.2.4): the key is a
// primary of the endorsement hierarchy made from it, so the same template
// gives the same key, the one the certificate names.
type gceAKTemplate struct {
	NameAlg    uint16
	Attributes uint32
	AuthPolicy []byte
	Scheme     uint16
	SchemeHash uint16
	KeyBits    uint16
	Exponent   uint32
	Unique     []byte
}

const (
	tpmAlgRSA    = 0x0001
	tpmAlgNull   = 0x0010
	tpmAlgRSASSA = 0x0014
	tpmAlgRSAPSS = 0x0016
)

// parseGCEAKTemplate reads the template; NV padding after it must be zeros.
func parseGCEAKTemplate(b []byte) (*gceAKTemplate, error) {
	r := &tpmReader{b: b}
	if typ := r.u16(); r.err == nil && typ != tpmAlgRSA {
		return nil, fmt.Errorf("AK template: type %#04x, want RSA", typ)
	}
	t := &gceAKTemplate{NameAlg: r.u16(), Attributes: r.u32(), AuthPolicy: r.sized()}
	if sym := r.u16(); r.err == nil && sym != tpmAlgNull {
		return nil, fmt.Errorf("AK template: symmetric %#04x, want NULL for a signing key", sym)
	}
	t.Scheme = r.u16()
	if t.Scheme != tpmAlgNull {
		t.SchemeHash = r.u16()
	}
	t.KeyBits, t.Exponent, t.Unique = r.u16(), r.u32(), r.sized()
	if r.err != nil {
		return nil, fmt.Errorf("AK template: %w", r.err)
	}
	for _, x := range b[r.off:] {
		if x != 0 {
			return nil, errors.New("AK template: bytes after the template")
		}
	}
	return t, nil
}

var tpmAttributeNames = []struct {
	bit  uint
	name string
}{
	{1, "fixedtpm"}, {2, "stclear"}, {4, "fixedparent"}, {5, "sensitivedataorigin"}, {6, "userwithauth"},
	{7, "adminwithpolicy"}, {10, "noda"}, {11, "encryptedduplication"}, {16, "restricted"}, {17, "decrypt"}, {18, "sign"},
}

var tpmHashNames = map[uint16]string{0x0004: "sha1", 0x000B: "sha256", 0x000C: "sha384", 0x000D: "sha512"}

// createPrimaryArgs are the tpm2_createprimary arguments that make the key
// from this template in the endorsement hierarchy; the policy and unique
// fields go to files in dir. tpm2-tools reads -u as a TPMU_PUBLIC_ID whose
// length word is little-endian (tpm2_createprimary(1)).
func (t *gceAKTemplate) createPrimaryArgs(dir string) ([]string, error) {
	var flags []string
	known := uint32(0)
	for _, a := range tpmAttributeNames {
		known |= 1 << a.bit
		if t.Attributes&(1<<a.bit) != 0 {
			flags = append(flags, a.name)
		}
	}
	if t.Attributes&^known != 0 {
		return nil, fmt.Errorf("AK template: attributes %#08x name bits this verifier does not know", t.Attributes)
	}
	nameAlg, ok := tpmHashNames[t.NameAlg]
	if !ok {
		return nil, fmt.Errorf("AK template: name algorithm %#04x", t.NameAlg)
	}
	var scheme string
	switch t.Scheme {
	case tpmAlgRSASSA:
		scheme = "rsassa"
	case tpmAlgRSAPSS:
		scheme = "rsapss"
	default:
		return nil, fmt.Errorf("AK template: scheme %#04x, want RSASSA or RSAPSS", t.Scheme)
	}
	schemeHash, ok := tpmHashNames[t.SchemeHash]
	if !ok {
		return nil, fmt.Errorf("AK template: scheme hash %#04x", t.SchemeHash)
	}
	if t.Exponent != 0 && t.Exponent != 65537 {
		return nil, fmt.Errorf("AK template: exponent %d", t.Exponent)
	}
	args := []string{"-C", "e", "-g", nameAlg, "-G", fmt.Sprintf("rsa%d:%s-%s:null", t.KeyBits, scheme, schemeHash), "-a", strings.Join(flags, "|")}
	if len(t.AuthPolicy) > 0 {
		p := filepath.Join(dir, "ak.policy")
		if err := os.WriteFile(p, t.AuthPolicy, 0o600); err != nil {
			return nil, err
		}
		args = append(args, "-L", p)
	}
	if len(t.Unique) > 0 {
		u := make([]byte, 2+len(t.Unique))
		binary.LittleEndian.PutUint16(u, uint16(len(t.Unique)))
		copy(u[2:], t.Unique)
		p := filepath.Join(dir, "ak.unique")
		if err := os.WriteFile(p, u, 0o600); err != nil {
			return nil, err
		}
		args = append(args, "-u", p)
	}
	return args, nil
}

// DefaultGCEBootPCRs is the selection a Compute Engine guest's vTPM quotes
// and seals to when the operator names none: the firmware's (0-7) and
// GRUB's (8: its commands and the kernel's command line; 9: every file it
// read, the kernel and its initrd among them). PCR 10 (IMA) and above
// change with what runs after boot, not with what booted.
const DefaultGCEBootPCRs = "sha256:0,1,2,3,4,5,6,7,8,9"

// gceVTPM is the producer's half on a Compute Engine guest: the attestation
// key made from Google's template, its certificate and the intermediates to
// Google's root, and a quote of this boot taken at start.
type gceVTPM struct {
	tool    func(string) string
	timeout time.Duration
	pcrs    string
	dir     string // holds the AK's context for the producer's life

	tmpl   *gceAKTemplate
	akPub  *rsa.PublicKey
	akSPKI []byte // the AK's SubjectPublicKeyInfo, DER: what REPORT_DATA names
	akCert []byte
	inter  [][]byte
	boot   *tpmQuote
}

// gceFetchIntermediate fetches a certificate from an authority-information
// URL; a var so tests run without the network. What it returns is checked
// against the pinned root by the verifier, never trusted for itself.
var gceFetchIntermediate = func(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url) //nolint:gosec,noctx // the URL is the certificate's own; what comes back is verified to the pinned root
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// derLength is the length of the DER value at the start of b: NV indices
// hold a certificate in a slot larger than it.
func derLength(b []byte) (int, error) {
	if len(b) < 2 || b[0] != 0x30 {
		return 0, errors.New("not a DER SEQUENCE")
	}
	if b[1] < 0x80 {
		return 2 + int(b[1]), nil
	}
	k := int(b[1] & 0x7F)
	if k == 0 || k > 4 || len(b) < 2+k {
		return 0, errors.New("DER length malformed")
	}
	n := 0
	for _, x := range b[2 : 2+k] {
		n = n<<8 | int(x)
	}
	if 2+k+n > len(b) {
		return 0, errors.New("DER value longer than the NV index")
	}
	return 2 + k + n, nil
}

// openGCEVTPM makes the attestation key from Google's template, checks it
// is the key Google's certificate names, gathers the intermediates (the
// operator's, else the certificate's own authority-information URL), and
// quotes this boot once.
func openGCEVTPM(toolsDir, pcrs string, intermediatesPEM []byte, timeout time.Duration) (_ *gceVTPM, err error) {
	if pcrs == "" {
		pcrs = DefaultGCEBootPCRs
	}
	if err := ValidatePCRSelection(pcrs); err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: %w", err)
	}
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	v := &gceVTPM{timeout: timeout, pcrs: pcrs}
	v.tool = func(name string) string {
		if toolsDir == "" {
			return name
		}
		return filepath.Join(toolsDir, name)
	}
	if v.dir, err = os.MkdirTemp("", "vg-gce-vtpm-*"); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(v.dir)
		}
	}()
	raw, err := runCommand(timeout, v.tool("tpm2_nvread"), "-C", "o", gceAKTemplateNVIndexRSA)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: read the AK template (NV %s): %w", gceAKTemplateNVIndexRSA, err)
	}
	if v.tmpl, err = parseGCEAKTemplate(raw); err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: %w", err)
	}
	if err := v.makeAK(); err != nil {
		return nil, err
	}
	certRaw, err := runCommand(timeout, v.tool("tpm2_nvread"), "-C", "o", gceAKCertNVIndexRSA)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: read the AK certificate (NV %s): %w", gceAKCertNVIndexRSA, err)
	}
	n, err := derLength(certRaw)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: the AK certificate: %w", err)
	}
	v.akCert = append([]byte(nil), certRaw[:n]...)
	cert, err := x509.ParseCertificate(v.akCert)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: the AK certificate: %w", err)
	}
	if !v.akPub.Equal(cert.PublicKey) {
		return nil, errors.New("gcp-sev-snp-vtpm: the key made from Google's AK template is not the key its certificate names")
	}
	if v.inter, err = gceIntermediates(cert, intermediatesPEM, timeout); err != nil {
		return nil, err
	}
	msg, sig, err := v.quote(tpmQuoteExtraDataFor([]byte("vault-genome gcp-sev-snp-vtpm boot identity")))
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: initial TPM quote: %w", err)
	}
	q, err := parseTPMQuote(msg)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: initial TPM quote: %w", err)
	}
	if err := verifyTPMQuoteSignature(v.akPub, msg, sig); err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: initial TPM quote: %w", err)
	}
	v.boot = q
	return v, nil
}

// makeAK makes the attestation key in the endorsement hierarchy from the
// template and reads its public key; the context is kept for quotes.
func (v *gceVTPM) makeAK() error {
	args, err := v.tmpl.createPrimaryArgs(v.dir)
	if err != nil {
		return fmt.Errorf("gcp-sev-snp-vtpm: %w", err)
	}
	ctx := filepath.Join(v.dir, "ak.ctx")
	if _, err := runCommand(v.timeout, append([]string{v.tool("tpm2_createprimary")}, append(args, "-c", ctx)...)...); err != nil {
		return fmt.Errorf("gcp-sev-snp-vtpm: make the AK from its template: %w", err)
	}
	pemPath := filepath.Join(v.dir, "ak.pem")
	if _, err := runCommand(v.timeout, v.tool("tpm2_readpublic"), "-c", ctx, "-f", "pem", "-o", pemPath); err != nil {
		return fmt.Errorf("gcp-sev-snp-vtpm: read the AK's public key: %w", err)
	}
	pemRaw, err := os.ReadFile(pemPath)
	if err != nil {
		return err
	}
	pub, err := parsePEMRSAPublicKey(pemRaw)
	if err != nil {
		return fmt.Errorf("gcp-sev-snp-vtpm: the AK's public key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	if v.akPub != nil && !v.akPub.Equal(pub) {
		return errors.New("gcp-sev-snp-vtpm: the AK made again is another key")
	}
	v.akPub, v.akSPKI = pub, spki
	return nil
}

// gceIntermediates are the operator's (PEM), else the one the certificate's
// authority-information URL serves.
func gceIntermediates(cert *x509.Certificate, operatorPEM []byte, timeout time.Duration) ([][]byte, error) {
	var out [][]byte
	for rest := operatorPEM; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		out = append(out, block.Bytes)
	}
	if len(out) > 0 {
		return out, nil
	}
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, errors.New("gcp-sev-snp-vtpm: the AK certificate names no issuer URL; give the intermediate in the configuration")
	}
	raw, err := gceFetchIntermediate(cert.IssuingCertificateURL[0], timeout)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: fetch the AK certificate's issuer: %w", err)
	}
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	if _, err := x509.ParseCertificate(raw); err != nil {
		return nil, fmt.Errorf("gcp-sev-snp-vtpm: the AK certificate's issuer: %w", err)
	}
	return [][]byte{raw}, nil
}

// quote runs tpm2_quote for a challenge; a context the TPM no longer holds
// (a long-lived daemon) is made again once from the template.
func (v *gceVTPM) quote(challenge [32]byte) (msg, sig []byte, err error) {
	msg, sig, err = v.quoteOnce(challenge)
	if err == nil {
		return msg, sig, nil
	}
	if mkErr := v.makeAK(); mkErr != nil {
		return nil, nil, fmt.Errorf("%w (and %v)", err, mkErr)
	}
	return v.quoteOnce(challenge)
}

func (v *gceVTPM) quoteOnce(challenge [32]byte) (msg, sig []byte, err error) {
	dir, err := os.MkdirTemp("", "vg-quote-*")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	msgPath, sigPath := filepath.Join(dir, "quote.msg"), filepath.Join(dir, "quote.sig")
	if _, err := runCommand(v.timeout, v.tool("tpm2_quote"), "-c", filepath.Join(v.dir, "ak.ctx"), "-l", v.pcrs, "-q", hex.EncodeToString(challenge[:]),
		"-g", "sha256", "-m", msgPath, "-s", sigPath, "-f", "plain"); err != nil {
		return nil, nil, fmt.Errorf("TPM quote: %w", err)
	}
	if msg, err = os.ReadFile(msgPath); err != nil {
		return nil, nil, err
	}
	if sig, err = os.ReadFile(sigPath); err != nil {
		return nil, nil, err
	}
	return msg, sig, nil
}

func (v *gceVTPM) close() error { return os.RemoveAll(v.dir) }
