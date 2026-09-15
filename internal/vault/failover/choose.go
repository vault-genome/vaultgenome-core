// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"fmt"
	"time"

	"github.com/ai-continuity-platform/core/internal/genome/bundle"
	"github.com/ai-continuity-platform/core/internal/genome/escrow"
	"github.com/ai-continuity-platform/core/internal/genome/sentinel"
	"github.com/ai-continuity-platform/core/internal/genome/tree"
	"github.com/ai-continuity-platform/core/internal/vault/kms"
)

// Choice is the genome a failover restores, and what was passed over.
type Choice struct {
	Record   sentinel.SealRecord
	Identity bundle.Identity
	Envelope escrow.Envelope
	// Expected is what the standby's receipt must show it restored.
	Expected kms.ExpectedGenome
	// RPO is how much earlier than the trigger the genome was sealed: the
	// state it does not hold.
	RPO time.Duration
	// ChainEnd is the newest generation of the verified chain; nil when the
	// outbox holds none.
	ChainEnd *uint64
	// SetAside lists the records, newest first, that were not chosen and
	// why: after the cutoff, files that do not check out, outside the chain.
	SetAside []sentinel.Rejected
}

// Choose picks the genome to restore: the newest generation of the verified
// chain in outbox that was sealed at or before the cutoff — the trigger
// less the policy's quarantine — and whose bundle and escrow envelope
// check out against its signed record. It returns a reason instead when no
// genome qualifies, or when the best one misses more state than the policy
// allows.
func Choose(outbox string, p Policy, t Trigger, escrowTag string) (Choice, string, error) {
	pub, _ := p.Sentinel()
	chain, rejected, err := sentinel.ReadChain(outbox, pub)
	if err != nil {
		return Choice{}, "", err
	}
	c := Choice{SetAside: rejected}
	if len(chain) == 0 {
		return c, "the outbox holds no genome the pinned sentinel sealed", nil
	}
	end := chain[len(chain)-1].Generation
	c.ChainEnd = &end
	cutoff := t.At.Add(-time.Duration(p.QuarantineSeconds) * time.Second)
	for i := len(chain) - 1; i >= 0; i-- {
		rec := chain[i]
		if rec.SealedAt.After(cutoff) {
			c.SetAside = append(c.SetAside, sentinel.Rejected{File: sentinel.RecordName(rec.Generation),
				Reason: fmt.Sprintf("sealed at %s, after the cutoff %s", rec.SealedAt.Format(time.RFC3339Nano), cutoff.Format(time.RFC3339Nano))})
			continue
		}
		id, env, err := sentinel.CheckGenome(outbox, rec)
		if err == nil && env.EscrowKey != escrowTag {
			err = fmt.Errorf("its key is escrowed to %s, not to this authority's %s", env.EscrowKey, escrowTag)
		}
		var files map[string]string
		if err == nil {
			files, err = tree.Files(id.Header)
		}
		if err != nil {
			c.SetAside = append(c.SetAside, sentinel.Rejected{File: sentinel.RecordName(rec.Generation), Reason: err.Error()})
			continue
		}
		c.Record, c.Identity, c.Envelope = rec, id, env
		c.Expected = kms.ExpectedGenome{BundleSHA256: id.SHA256, PayloadSHA256: id.Header.PayloadSHA256, TreeSHA256: tree.Digest(files)}
		c.RPO = t.At.Sub(rec.SealedAt)
		if limit := time.Duration(p.MaxRPOSeconds) * time.Second; limit > 0 && c.RPO > limit {
			return c, fmt.Sprintf("the newest trustworthy genome, generation %d, was sealed %s before the trigger; the policy allows at most %s", rec.Generation, c.RPO.Round(time.Millisecond), limit), nil
		}
		return c, "", nil
	}
	return c, fmt.Sprintf("no genome in the verified chain was sealed by %s and checks out", cutoff.Format(time.RFC3339Nano)), nil
}
