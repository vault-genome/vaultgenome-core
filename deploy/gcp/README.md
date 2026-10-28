# One button on Google Cloud

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/vault-genome/vaultgenome-core&cloudshell_git_branch=main&cloudshell_workspace=deploy/gcp&cloudshell_tutorial=tutorial.md)

A Vault Genome deployment on one Compute Engine Confidential VM (AMD
SEV-SNP), from the signed release, proven the way the project's reference
deployment is proven, and left running. The button opens Cloud Shell on
this directory with [`tutorial.md`](tutorial.md) beside it; the tutorial
runs `deploy.sh`. Cloud Shell asks before it opens a repository that is
not Google's: with **Trust repo** ticked it opens in your own Cloud
Shell, signed in, and the record stays in your home directory; unticked,
the session is temporary and `gcloud auth login` comes first (`deploy.sh`
says so and stops until then). From a laptop with `gcloud` signed in, the
same:

```bash
deploy/gcp/deploy.sh --project <id>            # the latest release; --tag v0.12.0 for one
deploy/gcp/destroy.sh --project <id>           # the VM, and nothing else
```

| What | Where |
| - | - |
| The release verified before it runs anywhere: the signed checksums list against the release workflow's identity for the tag (cosign), the five files against the list, their SLSA provenance against the source tag (slsa-verifier), the tag's signature against the keys pinned on `main` | [`deploy.sh`](deploy.sh) §2, `records/<stamp>/verify/` |
| One `n2d-standard-4` Confidential VM, AMD Milan, SEV-SNP, Ubuntu 24.04, 20 GB, with the verified list in its metadata | [`deploy.sh`](deploy.sh) §4 |
| The guest fetches the release and runs only what is on the list; the worker runtime from the hash-pinned locks; `acpctl provision` — keys, both configurations, the AMD chain from KDS, each identity from the chip pinned by the other, every key file sealed to the chip; a first genome made and sealed; both daemons as systemd services; a gate job over the Return Path; the audit log verified under the operator's key | [`guest.sh`](guest.sh), `records/<stamp>/guest/` |
| The summary that begins with `PROVEN`, each line from a file of the record | [`deploy.sh`](deploy.sh) §6 |

About USD 0.20 an hour while the VM runs (Google's N2D price plus its
SEV-SNP premium of USD 0.0169 an hour for this shape); about four
minutes from the command to the summary (251 s on the record, of which
154 s on the guest: the runtime's install 46 s, `acpctl provision` 10.5 s,
the first genome 5 s, the services up and the session open in 15 s, the
gate job 5 s, the audit read 4 s, the services back in 11 s).

## What it is, and what it is not

- **The reference deployment, kept running.** The guest does what
  [`scripts/hardware-test/gcp-sev-snp/provision-e2e`](../../scripts/hardware-test/gcp-sev-snp/provision-e2e)
  does on real SEV-SNP (claim C37) and what the operator guide's
  [first deployment](../../docs/operator/09_first_deployment.md) describes
  by hand — and then does not stop: the daemons are `sagvd.service` and
  `acp-compute.service`, restarted by systemd, their state under
  `/var/lib/vaultgenome`, the deployment under `/etc/vaultgenome` (root,
  0700), the binaries under `/opt/vaultgenome/bin` with `vg`, the
  operator's hand on the host: `vg health | status | logs | submit | job`
  live, and `vg verify | audit | events` for the audit log — its live
  segment is the authority's while it runs (ADR 0027), so those three
  pause both services for about fifteen seconds and start them again, as
  the guest itself does for the record's verification.
- **One host.** Both daemons attest with the same chip and pin the same
  launch measurement. The two-host form — the authority on one chip, the
  worker on another, across clouds — is three commands of `acpctl
  provision` ([first deployment §3](../../docs/operator/09_first_deployment.md),
  ADR 0028, claim C39).
- **Held to the chip.** With `tee.sealer auto` the key files are sealed to
  the chip's derived key: this chip, Google's firmware, the guest policy
  (ADR 0023). A stop and start that lands the VM on another host does not
  open them; `deploy.sh` again gives a fresh deployment with fresh keys
  and a new audit chain, or `--sealer tpm2` seals to the instance's vTPM
  instead (ADR 0025 step 1b). The boot chain — kernel, initrd, command
  line — is held by the `gcp-sev-snp-vtpm` family, set up by its
  [runbook](../../docs/operator/runbooks/real-tee-gcp-sev-snp-vtpm.md)
  once the image's first boot has settled (ADR 0037); this deployment is
  the chip-only `gcp-sev-snp` family, as the reference deployment is.
- **The network.** The Return Path, the REST API and the health listeners
  bind loopback only; the operator reaches them over `gcloud compute ssh`.
  The VM has an external address for its own fetches (GitHub, PyPI, AMD
  KDS) and the project's default network.
- **Nothing is sent anywhere.** The record goes over the VM's serial
  console to the machine that ran `deploy.sh`, and nowhere else; keys,
  seeds and the API token never leave the VM and are never printed.

## The record

`records/<stamp>/` beside this script: `deployment.txt` (project,
instance, zone, release), `verify/` (what `deploy.sh` verified — `cosign.txt`,
`checksums.txt`, `slsa.txt`, `tag.txt`, `assets.sha256`, `tools.txt`),
`serial-console.txt`, and `guest/` — the guest's own record with its
`sha256sums.txt`: `provision.json`, both identities, both configurations
(paths, no secret), `sealed-files.txt`, `chip.txt`, `job.json`,
`audit-verify.json`, `audit-events.jsonl`, `audit-public-key.pem`, the
daemons' logs and metrics, `steps.txt`, `timeline.txt`, the pip logs. The
same record stays on the VM under `/var/lib/vaultgenome/record/<stamp>/`.

Needs: `gcloud` signed in, `curl`, `git`, `python3`; `cosign` and
`slsa-verifier` on PATH — Cloud Shell has neither, and on Linux x86-64
`deploy.sh` fetches cosign 2.6.5 and slsa-verifier 2.7.1 at hashes pinned
in the script (cosign's from its signed release checksums, slsa-verifier's
from its own verified provenance). The project needs the Compute Engine
API (the script enables it) and N2D capacity in a zone of `us-central1`;
the script tries `-c`, `-b`, `-a`, `-f` in turn, or the one `--zone`
names.
