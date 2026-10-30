// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package console is what the person's console and the release authority
// agree on (ADR 0039): the pass a person is sent, the check that binds the
// server's word to its chip, the state and the journal as the wire carries
// them, and how the person's computer verifies each of them. It writes
// nothing: the files are the daemon's and the application's.
package console

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

const (
	// PassSchema names the pass file a person opens in the console.
	PassSchema = "vault-genome/console-pass/v1"
	// StateSchema names the state the check binds to the chip.
	StateSchema = "vault-genome/console-state/v1"
	// ActionSchema names the payload of a CONSOLE_ACTION audit event.
	ActionSchema = "vault-genome/console-action/v1"

	// ServerName is the name the console listener's certificate carries.
	// The certificate is pinned by the pass, so no address or public CA
	// is part of the proof.
	ServerName = "console.vaultgenome.invalid"

	// NonceBytes is the size of the random challenge of a check.
	NonceBytes = 32

	// StopKeyID is the key id the console's stop list is signed under.
	StopKeyID = "console-operator-stop"

	bindingDomain = "vault-genome/console-check/v1\x00"
)

// Role is what a person may do. A viewer looks; an operator also runs a
// restore check; an owner also invites people, and the first owner holds
// the operator key that signs the stop list.
type Role string

// The roles, least to most.
const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleOwner    Role = "owner"
)

// Valid reports whether r is one of the roles.
func (r Role) Valid() bool {
	return r == RoleViewer || r == RoleOperator || r == RoleOwner
}

// CanRestore reports whether r may start a restore check.
func (r Role) CanRestore() bool { return r == RoleOperator || r == RoleOwner }

// CanAdminister reports whether r may invite and remove people.
func (r Role) CanAdminister() bool { return r == RoleOwner }

// Person is one who may connect: their name as invited, their role, and
// the public half of the key their console made on their own computer.
type Person struct {
	Name         string    `json:"name"`
	Role         Role      `json:"role"`
	PublicKeyHex string    `json:"public_key_hex"`
	AddedAt      time.Time `json:"added_at"`
}

// Invite is the server's record of a pass not yet used, stored under the
// SHA-256 of its code: the code itself is only in the pass.
type Invite struct {
	Name      string    `json:"name"`
	Role      Role      `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// InviteKey is the name an invite is stored under: the hash of its code.
func InviteKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// Pass is the file a person is sent. It says where the server is and what
// it must prove, and it carries a single-use code. Whoever opens it first
// is the one the server admits; the code is dead after that.
type Pass struct {
	Schema            string `json:"schema"`
	ServerLabel       string `json:"server_label"`
	Address           string `json:"address"`
	ServerCertPEM     string `json:"server_cert_pem"`
	Pin               Pin    `json:"pin"`
	AuditPublicKeyPEM string `json:"audit_public_key_pem"`
	AuditKeyID        string `json:"audit_key_id"`

	InviteCode string    `json:"invite_code,omitempty"`
	InviteName string    `json:"invite_name,omitempty"`
	InviteRole Role      `json:"invite_role,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

// ParsePass reads a pass file.
func ParsePass(raw []byte) (Pass, error) {
	var p Pass
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Pass{}, fmt.Errorf("console: not a pass file: %w", err)
	}
	if p.Schema != PassSchema {
		return Pass{}, fmt.Errorf("console: not a pass file: schema %q", p.Schema)
	}
	if p.Address == "" || p.ServerCertPEM == "" || p.AuditPublicKeyPEM == "" || p.AuditKeyID == "" {
		return Pass{}, errors.New("console: the pass names no server")
	}
	if _, err := p.CertDER(); err != nil {
		return Pass{}, err
	}
	return p, nil
}

// CertDER returns the pinned certificate of the console listener.
func (p Pass) CertDER() ([]byte, error) {
	block, _ := pem.Decode([]byte(p.ServerCertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("console: the pass carries no server certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("console: the pass's server certificate: %w", err)
	}
	return block.Bytes, nil
}

// Pin is what the server's chip must show, as the worker pins the authority
// (`tee.peer` of acp-compute.json), with the files inline: it is what
// travels to the person's computer.
type Pin struct {
	Provider              string                  `json:"provider"`
	MeasurementHex        string                  `json:"measurement_hex"`
	AMDCertChainPEM       string                  `json:"amd_cert_chain_pem,omitempty"`
	AMDKDSURL             string                  `json:"amd_kds_url,omitempty"`
	MinReportedTCB        uint64                  `json:"min_reported_tcb,omitempty"`
	SEVSNP                *tee.SEVSNPPolicyConfig `json:"sev_snp,omitempty"`
	CSPIDs                []string                `json:"csp_ids,omitempty"`
	PCRDigests            []string                `json:"pcr_digests,omitempty"`
	PCRSelection          string                  `json:"pcr_selection,omitempty"`
	GCEProjectIDs         []string                `json:"gce_project_ids,omitempty"`
	GCEEKAKRootsPEM       string                  `json:"gce_ek_ak_roots_pem,omitempty"`
	PCSURL                string                  `json:"pcs_url,omitempty"`
	AcceptableTCBStatuses []string                `json:"acceptable_tcb_statuses,omitempty"`
	AttestorPublicKeyHex  string                  `json:"attestor_public_key_hex,omitempty"`
}

// Verifier builds the family's verifier for the pin. It runs on the
// person's computer: the verdict is not the server's. cacheDir keeps what a
// vendor serves (a chip's VCEK, Intel's TCB documents) between checks, each
// still checked on every use.
func (p Pin) Verifier(cacheDir string) (tee.Provider, tee.Verifier, error) {
	provider, err := tee.ParseProvider(p.Provider)
	if err != nil {
		return "", nil, fmt.Errorf("console: the pin's provider: %w", err)
	}
	measurement, err := hex.DecodeString(p.MeasurementHex)
	if err != nil {
		return "", nil, fmt.Errorf("console: the pin's measurement: %w", err)
	}
	snp, err := p.SEVSNP.Policy()
	if err != nil {
		return "", nil, fmt.Errorf("console: the pin's sev_snp: %w", err)
	}
	digests := make([][]byte, 0, len(p.PCRDigests))
	for _, h := range p.PCRDigests {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != sha256.Size {
			return "", nil, fmt.Errorf("console: the pin's pcr_digests: %q is not a 32-byte hex digest", h)
		}
		digests = append(digests, b)
	}
	chain := []byte(p.AMDCertChainPEM)
	spec := tee.VerifierSpec{Provider: provider, ExpectedMeasurement: tee.Measurement(measurement)}
	switch provider {
	case tee.ProviderSimulated:
		pub, err := hex.DecodeString(p.AttestorPublicKeyHex)
		if err != nil || len(pub) != crypto.Ed25519PublicKeySize {
			return "", nil, errors.New("console: the pin's attestor key is not a 32-byte hex key")
		}
		spec.AttestorPubKey = crypto.PublicKey(pub)
	case tee.ProviderGCPSEVSNP:
		spec.GCPSEV = tee.GCPSEVVerifierConfig{AMDRootPEM: chain, AMDKDSURL: p.AMDKDSURL, VCEKCacheDir: cacheDir, MinReportedTCB: p.MinReportedTCB, SEVSNP: snp}
	case tee.ProviderAWSSEVSNP:
		spec.AWSSEVSNP = tee.AWSSEVSNPVerifierConfig{SEV: tee.GCPSEVVerifierConfig{AMDRootPEM: chain, MinReportedTCB: p.MinReportedTCB, SEVSNP: snp}, CSPIDs: p.CSPIDs}
	case tee.ProviderGCPSEVSNPVTPM:
		spec.GCPSEVVTPM = tee.GCPSEVVTPMVerifierConfig{
			SEV:                  tee.GCPSEVVerifierConfig{AMDRootPEM: chain, AMDKDSURL: p.AMDKDSURL, VCEKCacheDir: cacheDir, MinReportedTCB: p.MinReportedTCB, SEVSNP: snp},
			PCRs:                 p.PCRSelection,
			AcceptablePCRDigests: digests,
			ProjectIDs:           p.GCEProjectIDs,
			ExtraRootsPEM:        []byte(p.GCEEKAKRootsPEM),
		}
	case tee.ProviderGCPTDX:
		spec.GCPTDX = tee.GCPTDXVerifierConfig{PCSURL: p.PCSURL, PCSCacheDir: cacheDir, AcceptableTCBStatuses: p.AcceptableTCBStatuses}
	case tee.ProviderAzureSEVSNP:
		spec.AzureSEVSNP = tee.AzureSEVSNPVerifierConfig{AMDRootPEM: chain, AMDKDSURL: p.AMDKDSURL, VCEKCacheDir: cacheDir, MinReportedTCB: p.MinReportedTCB, SEVSNP: snp, AcceptablePCRDigests: digests}
	default:
		return "", nil, fmt.Errorf("console: this console does not verify provider %q yet", provider)
	}
	v, err := tee.BuildVerifier(spec)
	if err != nil {
		return "", nil, fmt.Errorf("console: build the verifier for %s: %w", provider, err)
	}
	return provider, v, nil
}

// State is what the server says about itself at a check. Its exact bytes
// are bound into the chip's report, so nothing between the chip and the
// person's computer can change a word of it.
type State struct {
	Schema         string     `json:"schema"`
	At             time.Time  `json:"at"`
	StartedAt      time.Time  `json:"started_at"`
	Version        string     `json:"version"`
	Commit         string     `json:"commit,omitempty"`
	Provider       string     `json:"provider"`
	MeasurementHex string     `json:"measurement_hex"`
	You            Person     `json:"you"`
	People         []Person   `json:"people"`
	Audit          AuditState `json:"audit"`
	Stop           StopState  `json:"stop"`
	Genomes        []string   `json:"genomes"`
	QueueDepth     int        `json:"queue_depth"`
}

// AuditState is where the journal stands.
type AuditState struct {
	Events int    `json:"events"`
	Base   int    `json:"base"`
	TipHex string `json:"tip_hex"`
	KeyID  string `json:"key_id"`
}

// StopState is the stop list in force. Holder is the public key that may
// sign a new one; empty until the first owner has joined.
type StopState struct {
	HolderPublicKeyHex string    `json:"holder_public_key_hex,omitempty"`
	KeyID              string    `json:"key_id"`
	Serial             uint64    `json:"serial"`
	StopAll            bool      `json:"stop_all"`
	Reason             string    `json:"reason,omitempty"`
	IssuedAt           time.Time `json:"issued_at,omitempty"`
	Error              string    `json:"error,omitempty"`
}

// CheckRequest is the person's challenge.
type CheckRequest struct {
	NonceHex string `json:"nonce_hex"`
}

// CheckResponse is the server's answer: the state, byte for byte, and the
// chip's evidence over the binding of the challenge, the listener's
// certificate and the state.
type CheckResponse struct {
	State    []byte `json:"state"`
	Evidence []byte `json:"evidence"`
}

// BindingNonce is what the chip is asked to sign: the SHA-512 of the
// domain, the person's challenge, the listener's certificate and the
// state. A report for one challenge, one listener or one state does not
// verify for another.
func BindingNonce(challenge, certDER, state []byte) tee.Nonce {
	certSum := sha256.Sum256(certDER)
	stateSum := sha256.Sum256(state)
	h := sha512.New()
	h.Write([]byte(bindingDomain))
	h.Write(challenge)
	h.Write(certSum[:])
	h.Write(stateSum[:])
	return tee.Nonce(h.Sum(nil))
}

// Verdict is what the person's computer concluded from a check.
type Verdict struct {
	State       State
	Measurement tee.Measurement
	Detail      *tee.AttestationDetail
}

// VerifyCheck verifies a check's answer on the person's computer: the
// chip's evidence over the binding, by the verifier the pin built. Any
// failure is an Integrity error and the state is not to be believed.
func VerifyCheck(v tee.Verifier, challenge, certDER []byte, resp CheckResponse) (Verdict, error) {
	bound := BindingNonce(challenge, certDER, resp.State)
	var (
		m      tee.Measurement
		detail *tee.AttestationDetail
		err    error
	)
	if dv, ok := v.(tee.DetailedVerifier); ok {
		m, detail, err = dv.VerifyDetailed(tee.Evidence(resp.Evidence), bound)
	} else {
		m, err = v.Verify(tee.Evidence(resp.Evidence), bound)
	}
	if err != nil {
		return Verdict{}, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "console: the chip's evidence does not verify", err)
	}
	var st State
	if err := json.Unmarshal(resp.State, &st); err != nil {
		return Verdict{}, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "console: the bound state is not readable", err)
	}
	if st.Schema != StateSchema {
		return Verdict{}, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "console: the bound state has an unknown schema", nil)
	}
	return Verdict{State: st, Measurement: m, Detail: detail}, nil
}

// JournalPage is a run of the audit log's live segment as the listener
// serves it: every event signed as it was written, so the person's computer
// checks each of them itself.
type JournalPage struct {
	Base   int                      `json:"base"`
	Total  int                      `json:"total"`
	From   int                      `json:"from"`
	Events []audit_event.AuditEvent `json:"events"`
}

// BrokenJournalError says which event of a walk failed.
type BrokenJournalError struct {
	Index int
	Err   error
}

func (e *BrokenJournalError) Error() string {
	return fmt.Sprintf("console: the journal is broken at record %d: %v", e.Index, e.Err)
}

func (e *BrokenJournalError) Unwrap() error { return e.Err }

// VerifyEvents walks events in order, the first of them at index first of
// the log: each must link to the one before it (prev, when given, for the
// first) and carry a valid audit signature. It returns the hash of the last.
func VerifyEvents(events []audit_event.AuditEvent, first int, prev []byte, resolver keys.Resolver) ([]byte, error) {
	for i := range events {
		evt := events[i]
		if prev != nil && !bytes.Equal(evt.PrevHash, prev) {
			return nil, &BrokenJournalError{Index: first + i, Err: errors.New("it does not link to the record before it")}
		}
		if err := evt.VerifySignature(resolver); err != nil {
			return nil, &BrokenJournalError{Index: first + i, Err: err}
		}
		prev = evt.Hash
	}
	return prev, nil
}

// auditResolver holds one audit key.
type auditResolver struct {
	kid ids.KeyID
	pub crypto.SuitePublicKey
}

// NewAuditResolver is the resolver of a pass: the one audit key it names.
func NewAuditResolver(kid string, publicKeyPEM []byte) (keys.Resolver, error) {
	pub, err := crypto.ParsePublicKeyFile(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("console: the pass's audit key: %w", err)
	}
	return &auditResolver{kid: ids.KeyID(kid), pub: pub}, nil
}

func (r *auditResolver) Resolve(kid ids.KeyID, want keys.Purpose) (keys.VerifyingKey, error) {
	if kid != r.kid {
		return keys.VerifyingKey{}, fmt.Errorf("console: the record is signed under %q, not the audit key %q", kid, r.kid)
	}
	if want != keys.PurposeSigningAudit {
		return keys.VerifyingKey{}, fmt.Errorf("console: purpose %s not accepted", want)
	}
	return keys.VerifyingKey{KeyID: r.kid, Purpose: keys.PurposeSigningAudit, Suite: r.pub.Suite, PublicKey: r.pub.Bytes}, nil
}

// PublicKeyHex is how the wire and the people file name an identity key.
func PublicKeyHex(pub ed25519.PublicKey) string { return hex.EncodeToString(pub) }

// ActionPayload is the body of a CONSOLE_ACTION audit event: who did what
// through the console, on the record before it takes effect.
type ActionPayload struct {
	Schema       string `json:"schema"`
	Action       string `json:"action"`
	Person       string `json:"person"`
	Role         Role   `json:"role,omitempty"`
	PublicKeyHex string `json:"public_key_hex,omitempty"`
	Subject      string `json:"subject,omitempty"`
	HoldsStop    bool   `json:"holds_stop,omitempty"`
	Serial       uint64 `json:"serial,omitempty"`
	StopAll      bool   `json:"stop_all,omitempty"`
	Reason       string `json:"reason,omitempty"`
	ListSHA256   string `json:"list_sha256,omitempty"`
}

// The actions of a CONSOLE_ACTION event.
const (
	ActionPersonJoined  = "person_joined"
	ActionPersonRemoved = "person_removed"
	ActionInviteMade    = "invite_made"
	ActionStopSet       = "stop_set"
	ActionStopLifted    = "stop_lifted"
	ActionStopReady     = "stop_ready"
)

// RestoreResponse answers a restore check's start.
type RestoreResponse struct {
	JobID     string `json:"job_id"`
	RequestID string `json:"request_id"`
	Bundle    string `json:"bundle"`
}

// JobSummary is a job as the console shows it: no model output in it.
type JobSummary struct {
	JobID        string     `json:"job_id"`
	RequestID    string     `json:"request_id"`
	Status       string     `json:"status"`
	State        string     `json:"state"`
	SubmittedAt  time.Time  `json:"submitted_at"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	Bundle       string     `json:"bundle,omitempty"`
	GateLevel    string     `json:"gate_level,omitempty"`
	Fixtures     int        `json:"fixtures,omitempty"`
	ErrorCode    string     `json:"error_code,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

// InviteRequest asks the server for a new single-use code.
type InviteRequest struct {
	Name  string `json:"name"`
	Role  Role   `json:"role"`
	Hours int    `json:"hours,omitempty"`
}

// InviteResponse carries the new code; the owner's console writes the pass.
type InviteResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// JoinRequest redeems a pass.
type JoinRequest struct {
	Code string `json:"code"`
}

// RemoveRequest removes a person.
type RemoveRequest struct {
	PublicKeyHex string `json:"public_key_hex"`
}

// ErrorBody is how the listener says no.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
