// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	cchr "github.com/ai-continuity-platform/core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/ai-continuity-platform/core/internal/contracts/key_release_token"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/exposure"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/kms"
)

// runCrossCloudRestoreCmd parses the operator's flags, loads
// configuration + materials, instantiates a kms.Coordinator, runs
// CoordinateRestore, and prints JSON output.
//
// Flags:
//
//	-config <path>             path to sagvd JSON config (required)
//	-decision-id <id>          source-side ReleaseDecision id (required)
//	-destination-kind <kind>   tee.Provider name of destination (required)
//	-destination-endpoint <url> destination acp-bootstrap base URL (required)
//	-key <kid:hex>             one-or-more key materials in kid:hex form
//	                           (repeatable). The hex is the plaintext DEK
//	                           bytes (32 bytes / 64 hex chars expected for
//	                           AES-256 sealing keys).
//	-session-id <id>           optional audit correlator
//	-manifest-id <id>          optional audit correlator
//
// Exit codes:
//
//	0 — coordinator returned a CoordinationResult; printed as JSON to stdout
//	1 — any failure; classified-error envelope printed to stdout, error logged to stderr
func runCrossCloudRestoreCmd(args []string) error {
	fs := flag.NewFlagSet("sagvd crosscloud-restore", flag.ContinueOnError)
	var (
		configPath          string
		decisionID          string
		destinationKindStr  string
		destinationEndpoint string
		sessionID           string
		manifestID          string
	)
	var keyFlags repeatableFlag
	fs.StringVar(&configPath, "config", "", "path to sagvd JSON config (required)")
	fs.StringVar(&decisionID, "decision-id", "", "source-side ReleaseDecision id (required)")
	fs.StringVar(&destinationKindStr, "destination-kind", "", "destination TEE kind (required; e.g. aws-nitro, azure-sgx)")
	fs.StringVar(&destinationEndpoint, "destination-endpoint", "", "destination acp-bootstrap base URL (required)")
	fs.Var(&keyFlags, "key", "key material in kid:hex form, repeatable (hex = plaintext DEK bytes)")
	fs.StringVar(&sessionID, "session-id", "", "optional audit correlator: SessionID")
	fs.StringVar(&manifestID, "manifest-id", "", "optional audit correlator: ManifestID")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if configPath == "" {
		return errors.New("crosscloud-restore: -config required")
	}
	if decisionID == "" {
		return errors.New("crosscloud-restore: -decision-id required")
	}
	if destinationKindStr == "" {
		return errors.New("crosscloud-restore: -destination-kind required")
	}
	if destinationEndpoint == "" {
		return errors.New("crosscloud-restore: -destination-endpoint required")
	}
	if err := checkDestinationEndpoint(destinationEndpoint); err != nil {
		return err
	}
	if len(keyFlags) == 0 {
		return errors.New("crosscloud-restore: at least one -key kid:hex required")
	}

	destinationKind, err := tee.ParseProvider(destinationKindStr)
	if err != nil {
		return fmt.Errorf("crosscloud-restore: -destination-kind: %w", err)
	}

	keyMaterials, err := parseKeyFlags(keyFlags)
	if err != nil {
		return err
	}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("crosscloud-restore: config validation: %w", err)
	}
	if !cfg.CrossCloud.Enabled {
		return errors.New("crosscloud-restore: crosscloud.enabled=false in config — refusing to run")
	}

	clock := shared_time.NewSystemClock()
	mat, err := LoadMaterials(cfg, clock)
	if err != nil {
		return err
	}
	xcc, err := LoadCrossCloudMaterials(cfg, clock)
	if err != nil {
		return err
	}
	if xcc == nil {
		return errors.New("crosscloud-restore: cross-cloud materials nil despite cfg.CrossCloud.Enabled=true")
	}
	defer func() { _ = xcc.Close() }()

	coord, err := kms.NewCoordinator(kms.Config{
		AuditChain:   xcc.AuditEmitter,
		Signer:       mat.Store,
		Verifiers:    xcc.VerifierRegistry,
		Policy:       xcc.Policy,
		Transport:    xcc.Transport,
		IDGenerator:  xcc.IDGenerator,
		NonceSource:  xcc.NonceSource,
		Clock:        clock,
		SigningKeyID: mat.AuthoritySigningKeyID,
	})
	if err != nil {
		return err
	}

	req := kms.CoordinationRequest{
		DecisionID:          ids.DecisionID(decisionID),
		DestinationKind:     destinationKind,
		DestinationEndpoint: destinationEndpoint,
		KeysToRelease:       keyMaterials,
		SessionID:           ids.SessionID(sessionID),
		ManifestID:          ids.ManifestID(manifestID),
	}

	res, coordErr := coord.CoordinateRestore(context.Background(), req)
	out := buildCoordinationOutput(res, coordErr, xcc.AuditChain.Len())
	out.AuditTip = hex.EncodeToString(xcc.AuditChain.Tip())
	out.StopSerial = xcc.StopSerial
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("crosscloud-restore: encode output: %w", err)
	}
	if coordErr != nil {
		// Non-zero exit so shell scripts can check.
		return coordErr
	}
	return nil
}

// checkDestinationEndpoint refuses an endpoint that would carry a key
// release in the clear across a network: https always, plain http only
// to a loopback destination.
func checkDestinationEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("crosscloud-restore: -destination-endpoint %q is not an absolute URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if exposure.IsLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("crosscloud-restore: -destination-endpoint %q: plain http is accepted only for a loopback destination; use https", raw)
	default:
		return fmt.Errorf("crosscloud-restore: -destination-endpoint %q: scheme must be https", raw)
	}
}

// repeatableFlag implements flag.Value for repeated -key occurrences.
type repeatableFlag []string

func (r *repeatableFlag) String() string { return strings.Join(*r, ",") }
func (r *repeatableFlag) Set(s string) error {
	*r = append(*r, s)
	return nil
}

// parseKeyFlags parses each "kid:hex" entry into a kms.KeyMaterial.
// kid is the destination-side key-id under which the unwrapped DEK
// will be registered; hex is the plaintext DEK bytes (typically
// 32 bytes for AES-256 sealing).
func parseKeyFlags(in []string) ([]kms.KeyMaterial, error) {
	out := make([]kms.KeyMaterial, 0, len(in))
	for i, e := range in {
		idx := strings.IndexRune(e, ':')
		if idx <= 0 || idx == len(e)-1 {
			return nil, fmt.Errorf("crosscloud-restore: -key[%d] %q must be kid:hex", i, e)
		}
		kid := e[:idx]
		plain, err := hex.DecodeString(e[idx+1:])
		if err != nil {
			return nil, fmt.Errorf("crosscloud-restore: -key[%d] hex: %w", i, err)
		}
		if len(plain) == 0 {
			return nil, fmt.Errorf("crosscloud-restore: -key[%d] plaintext empty", i)
		}
		out = append(out, kms.KeyMaterial{
			KeyID:     ids.KeyID(kid),
			Purpose:   krt.PurposeSealing,
			Plaintext: plain,
		})
	}
	return out, nil
}

// coordinationOutput is the JSON shape printed to stdout. Includes
// the CoordinationResult fields (success path) plus a top-level
// status / error envelope (failure path) so shell scripts can grep
// reliably.
type coordinationOutput struct {
	Status                 string                   `json:"status"` // "ok" or "failed"
	Error                  *crossCloudErrorEnvelope `json:"error,omitempty"`
	HandshakeRequestID     ids.RequestID            `json:"handshake_request_id,omitempty"`
	HandshakeAuditID       ids.AuditEventID         `json:"handshake_audit_id,omitempty"`
	AttestationAuditID     ids.AuditEventID         `json:"attestation_audit_id,omitempty"`
	KeyReleaseAuditID      ids.AuditEventID         `json:"key_release_audit_id,omitempty"`
	DestinationMeasurement string                   `json:"destination_measurement_hex,omitempty"`
	RecipientKeySHA256     string                   `json:"recipient_key_sha256,omitempty"`
	PolicyVersion          string                   `json:"policy_version,omitempty"`
	TokenID                ids.DecisionID           `json:"token_id,omitempty"`
	DispatchedAt           string                   `json:"dispatched_at,omitempty"`
	AuditChainLength       int                      `json:"audit_chain_length"`
	// AuditTip is the hash of the audit log's last event. Record it:
	// a log whose tail was cut off still verifies, but not to this tip.
	AuditTip string `json:"audit_tip,omitempty"`
	// StopSerial is the operator stop list the decision was made under.
	StopSerial uint64 `json:"operator_stop_serial,omitempty"`
}

type crossCloudErrorEnvelope struct {
	Category string `json:"category"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

func buildCoordinationOutput(res kms.CoordinationResult, err error, chainLen int) coordinationOutput {
	out := coordinationOutput{
		AuditChainLength: chainLen,
	}
	if res.HandshakeRequestID != "" {
		out.HandshakeRequestID = res.HandshakeRequestID
	}
	if res.HandshakeAuditID != "" {
		out.HandshakeAuditID = res.HandshakeAuditID
	}
	if res.AttestationAuditID != "" {
		out.AttestationAuditID = res.AttestationAuditID
	}
	if res.KeyReleaseAuditID != "" {
		out.KeyReleaseAuditID = res.KeyReleaseAuditID
	}
	if len(res.DestinationMeasurement) > 0 {
		out.DestinationMeasurement = hex.EncodeToString(res.DestinationMeasurement)
	}
	if len(res.RecipientKeySHA256) > 0 {
		out.RecipientKeySHA256 = hex.EncodeToString(res.RecipientKeySHA256)
	}
	if res.PolicyVersion != "" {
		out.PolicyVersion = res.PolicyVersion
	}
	if res.TokenID != "" {
		out.TokenID = res.TokenID
	}
	if !res.DispatchedAt.IsZero() {
		out.DispatchedAt = res.DispatchedAt.Format("2006-01-02T15:04:05.000Z")
	}
	if err != nil {
		out.Status = "failed"
		out.Error = &crossCloudErrorEnvelope{
			Category: classifyEnvelopeCategory(err),
			Code:     errCodeOrUnknown(err),
			Message:  err.Error(),
		}
	} else {
		out.Status = "ok"
	}
	return out
}

// classifyEnvelopeCategory maps the project's classified-error
// category onto the wire envelope string.
func classifyEnvelopeCategory(err error) string {
	switch {
	case shared_errors.Is(err, shared_errors.CategoryStructural):
		return "structural"
	case shared_errors.Is(err, shared_errors.CategoryAuthority):
		return "authority"
	case shared_errors.Is(err, shared_errors.CategoryIntegrity):
		return "integrity"
	case shared_errors.Is(err, shared_errors.CategoryOperational):
		return "operational"
	case shared_errors.Is(err, shared_errors.CategoryIncident):
		return "incident"
	default:
		return "unknown"
	}
}

// errCodeOrUnknown returns the error's classified code or "unknown"
// when the error did not originate from shared_errors.
func errCodeOrUnknown(err error) string {
	if c := shared_errors.CodeOf(err); c != "" {
		return c
	}
	return "unknown"
}

// Reference cchr/krt to keep the dependency edges explicit even when
// the human-readable types are referenced only via kms.
var (
	_ = cchr.SchemaVersionCurrent
	_ = krt.SchemaVersionCurrent
)
