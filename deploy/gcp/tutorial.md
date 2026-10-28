# Deploy Vault Genome on a Confidential VM

<walkthrough-tutorial-duration duration="10"></walkthrough-tutorial-duration>

One command stands up a Vault Genome deployment on a Compute Engine
Confidential VM (AMD SEV-SNP) from the signed release, proves it the way
the project's own reference deployment is proven, and leaves it running
for you.

What you get: one `n2d-standard-4` Confidential VM — AMD Milan, SEV-SNP,
Ubuntu 24.04 — with the authority daemon `sagvd` and the worker
`acp-compute` as systemd services, their key files sealed to the chip, a
first genome gated over the Return Path, and the audit log verified. It
costs about USD 0.20 an hour while it runs (Google's N2D price plus its
SEV-SNP premium); the last step removes it.

What you need: a project with billing, and the right to create Compute
Engine instances in it.

## Choose the project

<walkthrough-project-setup billing="true"></walkthrough-project-setup>

The deployment goes into the project selected above; `deploy.sh` reads it
from `gcloud` and asks before it creates anything.

## Turn on Compute Engine

<walkthrough-enable-apis apis="compute.googleapis.com"></walkthrough-enable-apis>

(`deploy.sh` turns it on too when it is off; the button is faster.)

## Deploy

```sh
./deploy.sh
```

Answer `y` when it names the project. What it does, in order:

1. **Verifies the release before anything runs anywhere.** The signed
   checksums list against the release workflow's identity for this very
   tag (cosign); the binaries and the worker package against the list;
   their SLSA provenance against the source tag (slsa-verifier); the tag's
   own signature against the keys pinned on `main`. A file that does not
   verify stops the deployment here.
2. **Creates the Confidential VM** with `guest.sh` as its startup script
   and the verified list in its metadata.
3. **The guest stands itself up**: it fetches the release and runs only
   what is on the list, installs the worker runtime from the hash-pinned
   locks, runs `acpctl provision` — key material, both daemons'
   configurations, the AMD chain from KDS verified against the pinned
   roots, each daemon's identity read from the chip and pinned by the
   other, every key file sealed to the chip — makes and seals a first
   genome, starts both daemons as services, gates the genome over the
   Return Path and verifies the audit log.
4. **The record comes back** over the serial console into
   `records/<stamp>/`, beside the verification outputs of step 1.

About four minutes; the line at the bottom says what the guest is doing.

## Read the proof

The summary begins with `PROVEN` and says, line by line, what was shown
and from which file of the record:

- **release** — the tag's signature, the signed list, 5 of 5 files on it,
  5 of 5 provenances (`records/<stamp>/verify/`);
- **chip** — the AMD product and its TCB as the authority's verifier read
  them from the worker's report, the VCEK chain to AMD's root
  (`guest/chip.txt`, from the `TRUST_EVALUATED` event of the audit log);
- **identities** — the launch measurement each daemon read from the chip
  and the other pinned (`guest/provision.json`);
- **key files** — how many were sealed, and to what (`guest/sealed-files.txt`);
- **gate** — the job's verdict: `EXACT`, every fixture byte for byte,
  signed by the authority's key (`guest/job.json`);
- **audit log** — verified under the operator's key, which the record
  keeps (`guest/audit-verify.json`, `guest/audit-public-key.pem`).

Keep `records/<stamp>/`: Cloud Shell's home directory is yours, but a
copy off it is what an auditor compares the next deployment with.

## Use it

The VM is yours. On it, `vg` is the operator's hand (root only — it reads
the API token):

```sh
gcloud compute ssh vaultgenome --zone us-central1-c -- sudo vg health
```

(`deploy.sh` printed the exact zone: `us-central1-c` unless it had no
capacity and the next one was taken.) Then `sudo vg status` for the live
counters, `sudo vg submit gen-0.genome gen-0.key` for another job,
`sudo vg logs sagvd` for the authority's log; `sudo vg verify` replays
the audit chain, `sudo vg audit` summarises it and `sudo vg events 20`
lists its last events — the live segment is the authority's while it
runs, so these three pause both services for about fifteen seconds and
start them again.

Your own model: seal its genome with `acpctl genome seal` into
`/var/lib/vaultgenome/genomes` and submit it the same way — the operator
guide's [first deployment, §4](https://github.com/vault-genome/vaultgenome-core/blob/main/docs/operator/09_first_deployment.md)
has the steps, and what comes next: monitoring, the failover drill, the
next release.

<walkthrough-footnote>The key files are sealed to this chip: a stop and
start that lands the VM on another host does not open them, and the
services say so. Run `deploy.sh` again for a fresh deployment, or pass
`--sealer tpm2` to seal to the instance's vTPM instead (ADR 0025, step 1b).</walkthrough-footnote>

## Remove it

```sh
./destroy.sh
```

<walkthrough-conclusion-trophy></walkthrough-conclusion-trophy>

The VM and its sealed keys are gone; the record stays.
