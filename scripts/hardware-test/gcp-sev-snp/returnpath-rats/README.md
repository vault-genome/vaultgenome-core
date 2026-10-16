# returnpath-rats — the Return Path on SEV-SNP with the appraisal delegated to a Verifier on another VM

The bank's topology (ADR 0025, step 2b): the attester — an n2d SEV-SNP
Confidential VM running sagvd and acp-compute — and the Verifier — a plain
VM of its own running Veraison natively — in one GCP project. Both daemons
set `tee.peer.verifier.mode: rats`: each sends the other's Evidence record
to the Verifier by name over mutual TLS, judges the EAR by the policy here
(`policy:SEVSNP`, `affirming` only) and holds the pin itself. The runner
(`run.sh`) plays the operator: it provisions the Verifier with AMD's Milan
root as the trust anchor and the attester's launch as a reference value
before it releases the attester.

## What a run does

1. Builds the four binaries for linux/amd64, `acpctl` and the bench's
   `mkcorim` for this host; fetches AMD's Milan chain from KDS with
   `acpctl` (verified against the roots it pins).
2. Makes the kit's PKI: a root CA (EC P-256, seven days) and client
   certificates for sagvd, acp-compute and the runner.
3. Packs Veraison's sources — the tree the bench validated (`BENCH_REPO`,
   `third_party/veraison-services/src` with its patches: the sevsnp
   scheme's DER certificate table, the verification API's client CA; and
   `go-gen-ref/src`, which the scheme builds in) — without build outputs.
4. Boots the Verifier host (`verifier-vm.sh`): Go 1.27.2 (pinned,
   checksum verified), `deployment.sh build/deploy/init-stores`, service
   certificates under the kit's root with the VM's name as a SAN, the
   EAR signing key, `client-ca` on the verification API, the four
   services; and the attester (`cvm-returnpath-rats.sh`).
5. Takes the attester's chip report from its serial console (one
   configfs-tsm request, printed between `===RATS-REPORT-BEGIN===` and
   `===RATS-REPORT-END===`), wraps it as ratsd's TSM report, runs
   `mkcorim -kds <AMD chain> report.tsm.cbor` — the ARK as the trust
   anchor CoMID, this launch's MEASUREMENT as the reference value, keyed
   as Veraison's scheme looks it up — and submits the CoRIM to the
   Verifier's provisioning API.
6. Reads the Verifier's well-known document (over mutual TLS, by the name
   on its certificate), takes `ear-verification-key`, puts it and the
   client certificates in the bucket, and releases the attester
   (`vg-go=1`).
7. The attester: the builtin flow first (sagvd, acp-compute, a session, a
   gate job — the handshake measured on the same chip), then the
   delegated flow — a thief with the sealed key files refused off the
   chip; a worker of another family refused by name before the Verifier
   is asked; the delegated session and its gate job EXACT, the EARs on
   the record; a daemon whose policy names another appraisal policy
   refusing the affirming Verifier; a daemon whose Verifier is
   unreachable admitting nothing. The audit log verified under the
   published key; the trust decisions of every phase extracted.
8. Collects both records from the serial consoles (`vg-done=1` makes the
   Verifier print its logs and stores) and deletes both VMs, the firewall
   rule and the bucket — always, also on failure.

```bash
scripts/hardware-test/gcp-sev-snp/returnpath-rats/run.sh <project> [zone]
```

## Evidence

`evidence/<stamp>/` is the attester's record, as the returnpath-e2e kit
keeps it (`steps.txt`, `timeline.txt`, the daemons' logs of every phase,
the job views, `audit-events.jsonl`, `audit-verify.json`,
`trust-decisions.jsonl`, `verifier-well-known.json` as the guest saw it,
`verifier-dns.txt`, `sha256sums.txt`), plus:

- `runner/` — `launch-report.bin` (the chip's report), `launch-report.tsm.cbor`,
  `corim.cbor` and `corim-submit.json` (what the Verifier was provisioned
  with, and its answer), `well-known.json`, `verifier-ear.jwk`, the public
  certificates, `firewall-rule.json`, `veraison-sources.txt`,
  `runner-timeline.txt`, `metadata.txt`, `sha256sums.txt`;
- `verifier/` — the Verifier host's record: `steps.txt`, `timeline.txt`,
  `build.log`, `deploy.log`, `config.yaml`, `plugins.txt`,
  `verification-cert.txt`, the services' logs (every session the attester
  opened, every appraisal), `store.sql.dump` (the trust anchor and the
  reference value as stored), `sha256sums.txt`.

## What it proves, and what it does not

Proves: two daemons on a chip delegating to a Verifier on another machine
over mutual TLS, by name; the Verifier provisioned by the operator with the
chip's launch before the session; the EARs on the admissions; the family
and the policy held by the daemons; nothing admitted when the Verifier
cannot be asked; the delegated handshake measured beside the builtin one
on the same chip.

Does not: a Verifier outside the VPC (the two VMs share the default network;
the attester reaches 8443 over `default-allow-internal`); the Verifier's
own hardening (it runs as root from a startup script, for the duration of
the run); reference values from the firmware vendor's signed endorsement —
the launch is provisioned from the chip's own report (trust on first use,
as `mkcorim` says), which is the bench's practice and a bank's day-one
practice until Google's signed endorsement is wired in.
