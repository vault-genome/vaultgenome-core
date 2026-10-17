# provision-two-hosts — the three commands across two clouds and two chips

The two-host form of `acpctl provision` (ADR 0028), run where it is meant
to run: the authority on a GCP SEV-SNP guest (AMD Milan, n2d-standard-4),
the worker on an Azure SEV-SNP Confidential VM (AMD Genoa, DC4as_v5), the
Return Path between them over the Internet under mutual TLS, the
authority's port 9443 open to the worker's address only.

- `run.sh` is the operator's hands: it builds and uploads, brings both
  machines up, carries the bundle from the authority to the worker and
  the identity back (the authority's side through the run's private
  bucket, the worker's over ssh), collects both sides and deletes
  everything, also on failure.
- `authority.sh` (the GCP startup script) runs step 1, `acpctl provision
  authority` — keygen, sagvd for an `azure-sev-snp` worker with the Genoa
  chain, the Milan chain in the bundle for the worker's verifier, the
  authority's identity from the chip, its key files sealed, the bundle
  written and, once handed off, removed from the host — then the
  fine-tune sealed into the genome directory, and after the worker's
  identity arrives step 3, `acpctl provision pin-worker`, sagvd, the gate
  job, the audit log verified under the key provision kept.
- `worker.sh` (over ssh) runs step 2, `acpctl provision join` — the
  bundle's files into the worker's deployment, `acp-compute.json` for the
  authority the bundle names, the worker's identity from the vTPM's HCL
  report, its key files sealed to the vTPM, the bundle deleted — then
  starts `acp-compute` on it.

```bash
scripts/hardware-test/provision-two-hosts/run.sh <gcp-project> [gcp-zone] [azure-rg] [azure-location]
```

What comes back (`evidence/<stamp>/`): `authority/` and `worker/` with
each side's `steps.txt`, `provision-*.out`, the three `provision.json`
phases (`awaiting-worker`, `joined`, `complete`), the bundle's manifest
and listing (names and hashes, no bytes), both identities, both
configurations (paths, no secret), the job view with its gate verdict,
the audit verification, the logs and metrics; `timeline.txt` from the
orchestrator and from each guest; `machines.txt`; `runner.log`;
`sha256sums.txt`. Keys, seeds and the token stay on the machines and die
with them; the bundle exists on the authority until it is handed off, on
the orchestrator until it is carried, and on the worker until `join` has
sealed its files.

Run on record: `evidence/20261017T024319Z/` (claim C39) — provision
authority 10.5 s on the Milan guest, the bundle 15,360 bytes (seven
files under a manifest), provision join 0.58 s on the Genoa guest with
the identity from the vTPM and three key files sealed to it, pin-worker
0.03 s; the session opened 5 s after sagvd was ready (handshake 841 ms,
`peer_product Genoa`), the gate job EXACT 6/6 in 6.2 s, sixteen audit
events verified; 7 min 20 s from the orchestrator's first command to its
last. The two runs before it stopped at step 2 for the kit's own
mistakes (the worker's family must be named: no configfs-tsm under the
paravisor; tpm2-tools must be on the worker: the provider reads the HCL
report through `tpm2_nvread`); both are fixed here.
