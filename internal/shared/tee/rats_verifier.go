// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The delegated Verifier (ADR 0025, step 2b): the peer's Evidence record
// goes to a RATS Verifier over Veraison's challenge-response API and the
// returned EAR is verified under the Verifier's pinned key and judged by
// the operator's policy. Appraisal — the chip's signature, the vendor
// chain, the TCB, the guest policy — is the Verifier's; the pin stays
// ours: the launch measurement is read from the message we posted, by
// our own parser, because the bytes we post are the bytes the Verifier
// appraised (the EAR carries the session nonce, and the Verifier's
// scheme compares it with the report's REPORT_DATA byte for byte), and
// the EAR's annotated evidence is the scheme's own shape (for SEV-SNP a
// CoRIM with its CoMID in CBOR) that this side need not decode.
//
// The API, as Veraison serves it and the bench's double repeats it:
//
//	POST {url}/challenge-response/v1/newSession?nonce=<base64url>  → 201, Location
//	POST <session>  Content-Type: <evidence media type>            → 200 {"status":"complete","result":"<EAR JWS>"}
//	                                                                 202 {"status":"processing"} then GET <session>
//	DELETE <session>
//
// Everything is the standard library: net/http, encoding/json, crypto.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Media types of the challenge-response API.
const (
	// RATSSessionMediaType is the session document's type.
	RATSSessionMediaType = "application/vnd.veraison.challenge-response-session+json"
)

// RATSVerifierConfig configures the delegated Verifier.
type RATSVerifierConfig struct {
	// URL is the Verifier's base URL (https://verifier.bank.example).
	// Plain http is accepted for loopback addresses only.
	URL string
	// EARPublicKey is the key the EAR must verify under (ES256).
	EARPublicKey *ecdsa.PublicKey
	// CAPEM, when set, is the certificate pool the Verifier's TLS
	// certificate must chain to; otherwise the system roots.
	CAPEM []byte
	// ClientCertPEM and ClientKeyPEM, when set, are this side's TLS
	// client certificate and key: a Verifier that takes only known
	// callers (mutual TLS) is answered with them. Both or neither.
	ClientCertPEM, ClientKeyPEM []byte
	// PolicyID, when set, is the ear.appraisal-policy-id the appraisal
	// must name.
	PolicyID string
	// Submod, when set, is the appraisal to judge by; otherwise the EAR
	// must carry exactly one.
	Submod string
	// Accept are the ear.status values that admit the peer; empty means
	// affirming only. contraindicated and none are never accepted.
	Accept []string
	// Timeout bounds each request; zero means 10 seconds.
	Timeout time.Duration
	// Transport, when set, is used instead of the one built from CAPEM
	// (tests).
	Transport http.RoundTripper
}

// RATSVerifier delegates appraisal to a RATS Verifier and holds the pin.
type RATSVerifier struct {
	peer     Provider
	expected Measurement
	cfg      RATSVerifierConfig
	client   *http.Client
	base     string
}

const (
	ratsDefaultTimeout = 10 * time.Second
	ratsMaxBody        = 1 << 20
	ratsPollEvery      = 250 * time.Millisecond
	ratsPollMax        = 40
)

// NewRATSVerifier builds the delegated Verifier for a peer of family
// peer, pinned to expected. The family must be one this side can read
// the measurement of; the URL must be https (http on loopback only).
func NewRATSVerifier(peer Provider, expected Measurement, cfg RATSVerifierConfig) (*RATSVerifier, error) {
	if _, err := EvidenceMediaType(peer); err != nil {
		return nil, err
	}
	if _, err := localMeasurement(peer, nil); err != nil && shared_errors.CodeOf(err) == codeNoLocalReader {
		return nil, err
	}
	if want := measurementLen(peer); want != 0 && len(expected) != want {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("tee: rats verifier: the pin for %s is %d bytes, got %d", peer, want, len(expected)), nil)
	}
	if cfg.EARPublicKey == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "tee: rats verifier: the Verifier's EAR public key is required", nil)
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("tee: rats verifier: url %q is not an http(s) URL", cfg.URL), nil)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("tee: rats verifier: %q is plain http to a host that is not loopback; a Verifier is asked over https", cfg.URL), nil)
	}
	for _, a := range cfg.Accept {
		if a != EARStatusAffirming && a != EARStatusWarning {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("tee: rats verifier: accept %q: only affirming and warning can admit a peer", a), nil)
		}
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = ratsDefaultTimeout
	}
	transport := cfg.Transport
	if transport == nil {
		// TLS 1.3 only, as every listener of the product: the Verifier is
		// a peer of the trust boundary, not a web page.
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
		if len(cfg.CAPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CAPEM) {
				return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "tee: rats verifier: the CA file holds no certificate", nil)
			}
			tlsCfg.RootCAs = pool
		}
		if len(cfg.ClientCertPEM) > 0 || len(cfg.ClientKeyPEM) > 0 {
			cert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
			if err != nil {
				return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "tee: rats verifier: the client certificate and key do not make a pair", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		transport = &http.Transport{TLSClientConfig: tlsCfg, Proxy: nil, ForceAttemptHTTP2: true}
	}
	return &RATSVerifier{
		peer: peer, expected: append(Measurement(nil), expected...), cfg: cfg,
		client: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("a Verifier does not redirect")
		}},
		base: strings.TrimRight(cfg.URL, "/"),
	}, nil
}

// URL is the Verifier this verifier asks.
func (v *RATSVerifier) URL() string { return v.base }

// Verify implements Verifier for a caller holding bare Evidence: the
// Evidence goes under its family's media type, as the wire would carry
// it, and the record path is taken.
func (v *RATSVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	mediaType, value, err := WrapEvidence(v.peer, ev, nil)
	if err != nil {
		return nil, err
	}
	m, _, err := v.VerifyRecord(mediaType, value, nonce)
	return m, err
}

// VerifyDetailed implements DetailedVerifier.
func (v *RATSVerifier) VerifyDetailed(ev Evidence, nonce Nonce) (Measurement, *AttestationDetail, error) {
	mediaType, value, err := WrapEvidence(v.peer, ev, nil)
	if err != nil {
		return nil, nil, err
	}
	return v.VerifyRecord(mediaType, value, nonce)
}

// VerifyRecord implements RecordVerifier: the record goes to the
// Verifier under its type, the EAR comes back and is judged, the
// measurement read from the record is held against the pin.
func (v *RATSVerifier) VerifyRecord(mediaType string, value []byte, nonce Nonce) (Measurement, *AttestationDetail, error) {
	if len(nonce) < NonceMinBytes {
		return nil, nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "tee: rats verifier: nonce must be at least NonceMinBytes", nil)
	}
	want, _ := EvidenceMediaType(v.peer)
	if mediaType != want {
		return nil, nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			fmt.Sprintf("tee: evidence type %q, this peer verifier is %s and reads %s", mediaType, v.peer, want), nil)
	}
	// What the pin will be held against, read before any round trip: a
	// message this side cannot read is refused without asking anyone.
	m, err := localMeasurement(v.peer, value)
	if err != nil {
		return nil, nil, err
	}
	sessionNonce := sessionNonceFor(v.peer, nonce)
	ear, err := v.appraise(mediaType, value, sessionNonce)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(ear.Nonce, sessionNonce) {
		return nil, nil, earErr(fmt.Sprintf("eat_nonce is not this session's nonce (%s)", v.base), nil)
	}
	name, sub, err := v.pickSubmod(ear)
	if err != nil {
		return nil, nil, err
	}
	if !v.accepts(sub.Status) {
		return nil, nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			fmt.Sprintf("tee: the Verifier at %s says %s: %s (policy %q); this side admits %v", v.base, name, sub.Status, sub.PolicyID, v.acceptList()), nil)
	}
	if v.cfg.PolicyID != "" && sub.PolicyID != v.cfg.PolicyID {
		return nil, nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			fmt.Sprintf("tee: the Verifier at %s appraised under policy %q, this side requires %q", v.base, sub.PolicyID, v.cfg.PolicyID), nil)
	}
	if !m.Equal(v.expected) {
		return nil, nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			fmt.Sprintf("tee: the Verifier at %s affirms the %s peer, but its measurement differs from the pin", v.base, v.peer), nil)
	}
	detail := &AttestationDetail{Provider: v.peer, Verifier: &VerifierResult{
		URL: v.base, EAR: ear.Raw, Submod: name, Status: sub.Status, PolicyID: sub.PolicyID, TrustVector: sub.TrustVector,
		VerifierDeveloper: ear.VerifierID.Developer, VerifierBuild: ear.VerifierID.Build, IssuedAt: ear.IssuedAt,
	}}
	return m, detail, nil
}

func (v *RATSVerifier) acceptList() []string {
	if len(v.cfg.Accept) == 0 {
		return []string{EARStatusAffirming}
	}
	return v.cfg.Accept
}

func (v *RATSVerifier) accepts(status string) bool {
	for _, a := range v.acceptList() {
		if a == status {
			return true
		}
	}
	return false
}

func (v *RATSVerifier) pickSubmod(ear *EAR) (string, EARAppraisal, error) {
	if v.cfg.Submod != "" {
		sub, ok := ear.Submods[v.cfg.Submod]
		if !ok {
			return "", EARAppraisal{}, earErr(fmt.Sprintf("no appraisal named %q from %s (got %v)", v.cfg.Submod, v.base, submodNames(ear)), nil)
		}
		return v.cfg.Submod, sub, nil
	}
	if len(ear.Submods) != 1 {
		return "", EARAppraisal{}, earErr(fmt.Sprintf("%d appraisals from %s and no submod configured to judge by (%v)", len(ear.Submods), v.base, submodNames(ear)), nil)
	}
	for name, sub := range ear.Submods {
		return name, sub, nil
	}
	return "", EARAppraisal{}, earErr("no appraisal", nil)
}

func submodNames(ear *EAR) []string {
	names := make([]string, 0, len(ear.Submods))
	for n := range ear.Submods {
		names = append(names, n)
	}
	return names
}

func ratsUnavailable(base, msg string, cause error) error {
	return shared_errors.Operational(codeVerifierUnavailable, "tee: the Verifier at "+base+": "+msg, cause)
}

// codeVerifierUnavailable (Operational): the delegated Verifier could
// not be asked, or answered with something other than a result.
const codeVerifierUnavailable = "verifier_unavailable"

// appraise runs one challenge-response session: open it with the nonce,
// post the record, take the EAR, close the session.
func (v *RATSVerifier) appraise(mediaType string, value, sessionNonce []byte) (*EAR, error) {
	ctx := context.Background()
	q := url.Values{"nonce": {base64.URLEncoding.EncodeToString(sessionNonce)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.base+"/challenge-response/v1/newSession?"+q.Encode(), nil)
	if err != nil {
		return nil, ratsUnavailable(v.base, "bad request", err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, ratsUnavailable(v.base, "no session: "+err.Error(), err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, ratsMaxBody))
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusCreated || loc == "" {
		return nil, ratsUnavailable(v.base, fmt.Sprintf("refused a session: HTTP %d", resp.StatusCode), nil)
	}
	session, err := v.resolveSession(loc)
	if err != nil {
		return nil, err
	}
	defer v.closeSession(ctx, session)

	post, err := http.NewRequestWithContext(ctx, http.MethodPost, session, bytes.NewReader(value))
	if err != nil {
		return nil, ratsUnavailable(v.base, "bad request", err)
	}
	post.Header.Set("Content-Type", mediaType)
	post.Header.Set("Accept", RATSSessionMediaType)
	resp, err = v.client.Do(post)
	if err != nil {
		return nil, ratsUnavailable(v.base, "the evidence could not be posted: "+err.Error(), err)
	}
	doc, status, err := readSession(resp)
	if err != nil {
		return nil, ratsUnavailable(v.base, err.Error(), nil)
	}
	for i := 0; doc.Status == "processing" && status == http.StatusAccepted; i++ {
		if i >= ratsPollMax {
			return nil, ratsUnavailable(v.base, "still processing after the wait", nil)
		}
		time.Sleep(ratsPollEvery)
		get, err := http.NewRequestWithContext(ctx, http.MethodGet, session, nil)
		if err != nil {
			return nil, ratsUnavailable(v.base, "bad request", err)
		}
		get.Header.Set("Accept", RATSSessionMediaType)
		resp, err = v.client.Do(get)
		if err != nil {
			return nil, ratsUnavailable(v.base, "the session could not be read: "+err.Error(), err)
		}
		doc, status, err = readSession(resp)
		if err != nil {
			return nil, ratsUnavailable(v.base, err.Error(), nil)
		}
		if doc.Status == "processing" {
			status = http.StatusAccepted
		}
	}
	if doc.Status != "complete" || doc.Result == "" {
		return nil, ratsUnavailable(v.base, fmt.Sprintf("produced no attestation result (HTTP %d, status %q)", status, doc.Status), nil)
	}
	ear, err := VerifyEAR(doc.Result, v.cfg.EARPublicKey)
	if err != nil {
		return nil, err
	}
	return ear, nil
}

type ratsSession struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

func readSession(resp *http.Response) (ratsSession, int, error) {
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, ratsMaxBody))
	if err != nil {
		return ratsSession{}, resp.StatusCode, fmt.Errorf("the session could not be read: %w", err)
	}
	var doc ratsSession
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Status == "" {
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			return ratsSession{}, resp.StatusCode, fmt.Errorf("answered HTTP %d to the evidence", resp.StatusCode)
		}
		return ratsSession{}, resp.StatusCode, fmt.Errorf("the session document is not JSON: %w", err)
	}
	// A session that says "failed" (HTTP 400 from Veraison) is a
	// verdict-less answer: reported below as no attestation result.
	return doc, resp.StatusCode, nil
}

// resolveSession makes the session URL from the Location header, which
// Veraison gives relative to the API root ("session/<id>").
func (v *RATSVerifier) resolveSession(loc string) (string, error) {
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		if !strings.HasPrefix(loc, v.base+"/") {
			return "", ratsUnavailable(v.base, fmt.Sprintf("points the session elsewhere (%s)", loc), nil)
		}
		return loc, nil
	}
	return v.base + "/challenge-response/v1/" + strings.TrimPrefix(loc, "/"), nil
}

func (v *RATSVerifier) closeSession(ctx context.Context, session string) {
	del, err := http.NewRequestWithContext(ctx, http.MethodDelete, session, nil)
	if err != nil {
		return
	}
	if resp, err := v.client.Do(del); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, ratsMaxBody))
		_ = resp.Body.Close()
	}
}

// sessionNonceFor is the nonce the Verifier's session is opened with:
// what the Evidence itself carries for the challenge, because the
// Verifier compares the two. The configfs-tsm producers write
// REPORT_DATA = SHA-256(challenge) || zeros(32); the simulated TEE
// signs the challenge as it is.
func sessionNonceFor(p Provider, challenge Nonce) []byte {
	switch p {
	case ProviderGCPSEVSNP, ProviderGCPTDX:
		var rd [64]byte
		prefix := computeReportDataPrefix(challenge)
		copy(rd[:], prefix[:])
		return rd[:]
	default:
		return append([]byte(nil), challenge...)
	}
}

// codeNoLocalReader (Structural): the family has no reader for the
// measurement on this side, so a delegated verdict could not be pinned.
const codeNoLocalReader = "no_local_measurement_reader"

func measurementLen(p Provider) int {
	switch p {
	case ProviderGCPSEVSNP, ProviderGCPTDX:
		return 48
	case ProviderSimulated:
		return shared_crypto.HashSize
	default:
		return 0
	}
}

// localMeasurement reads the launch measurement from the message of
// family p as it travels on the wire — the field our pin is held
// against — without verifying anything: the Verifier verifies. A nil
// value only asks whether the family has a reader.
func localMeasurement(p Provider, value []byte) (Measurement, error) {
	switch p {
	case ProviderGCPSEVSNP:
		if value == nil {
			return nil, nil
		}
		ev, _, err := UnwrapEvidence(p, MediaTypeTSMReportJSON, value)
		if err != nil {
			return nil, err
		}
		report, err := parseSEVSNPReport(ev)
		if err != nil {
			return nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied, "tee: rats verifier: the SEV-SNP report does not parse", err)
		}
		return Measurement(report.Measurement[:]), nil
	case ProviderGCPTDX:
		if value == nil {
			return nil, nil
		}
		ev, _, err := UnwrapEvidence(p, MediaTypeTSMReportJSON, value)
		if err != nil {
			return nil, err
		}
		q, err := parseTDXQuote(ev)
		if err != nil {
			return nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied, "tee: rats verifier: the TDX quote does not parse", err)
		}
		return tdxMeasurement(q.MRTD, q.RTMR), nil
	case ProviderSimulated:
		if value == nil {
			return nil, nil
		}
		return simulatedStatementMeasurement(value)
	default:
		return nil, shared_errors.Structural(codeNoLocalReader,
			fmt.Sprintf("tee: rats verifier: no reader for the measurement of a %s peer on this side; the pin cannot be held", p), nil)
	}
}

// simulatedStatementMeasurement reads the measurement from a simulated
// TEE statement (magic, nonce length, nonce, measurement, signature).
func simulatedStatementMeasurement(ev []byte) (Measurement, error) {
	magic := simulatedEvidenceMagic
	if len(ev) < len(magic)+4 || string(ev[:len(magic)]) != magic {
		return nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied, "tee: rats verifier: not a simulated statement", nil)
	}
	off := len(magic)
	nlen := binary.BigEndian.Uint32(ev[off : off+4])
	off += 4
	need := uint64(nlen) + uint64(shared_crypto.HashSize) + uint64(shared_crypto.Ed25519SignatureSize)
	if nlen == 0 || uint64(len(ev)-off) < need {
		return nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied, "tee: rats verifier: simulated statement truncated", nil)
	}
	off += int(nlen)
	return append(Measurement(nil), ev[off:off+shared_crypto.HashSize]...), nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
