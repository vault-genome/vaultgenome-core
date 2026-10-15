# The reference deployment: a signed release on real SEV-SNP

What an operator who downloads a release of Vault Genome does, done end to
end and recorded, so that a first deployment has something to be compared
with. One command on a laptop with `gh`, `cosign`, `slsa-verifier`, `go`,
GNU tar and GNU gzip (`gtar` and `gzip` from Homebrew on macOS) and
`gcloud`:

```bash
./scripts/hardware-test/release-deploy/run.sh <gcp-project> v0.4.1
```

It takes about fifteen minutes and one `n2d-standard-4` Confidential VM,
created and deleted by the run.

## What the run does

1. **Downloads the release's assets** — the five binaries and the worker
   package, their keyless cosign signatures and certificates, the SBOMs
   with theirs, and the SLSA provenance — and **verifies every one** before
   anything runs: `cosign verify-blob` against the release workflow's
   identity and the GitHub OIDC issuer (twelve signatures), `slsa-verifier
   verify-artifact` against the source repository and the tag (six
   artifacts), and the tag's own signature against the keys pinned on
   `main` (`.github/allowed_signers`). A signature that does not verify
   stops the run. (A release before 0.4.2 has four binaries and no package:
   eight signatures, four provenances, and the pieces below from the tag's
   source — the record of `v0.4.1` says so.)
2. **Rebuilds the five binaries and the worker package from the tag** with
   the inputs `release.yml` uses (the tag as VERSION, the commit as COMMIT,
   its time as SOURCE_DATE_EPOCH, CGO off, linux/amd64; GNU tar with sorted
   names, numeric owner 0 and that time as every mtime, GNU gzip without a
   name or a timestamp) and requires every rebuilt artifact's SHA-256 to
   equal the released file's — the release procedure's §5.4, done by the
   kit rather than by hand. The gzip must be GNU's: the rehearsal of 0.4.2
   repacked the package on macOS with Apple's gzip and got an identical
   tar inside a different file; the kit stops before the rebuild when the
   gzip it finds is not GNU's.
3. Uploads **only release assets** to the guest: the released `sagvd`,
   `acp-compute`, `acpctl`, `acp-keygen` and the worker package. The AMD
   Milan chain is fetched on the guest by the released `acpctl` from AMD
   KDS and verified against the roots the binary pins (ADR 0024). Nothing
   comes from this tree.
4. Runs the **same guest script as `gcp-sev-snp/returnpath-e2e`** on a fresh
   SEV-SNP VM, with the released `sagvd`, `acp-compute` and `acpctl`: both
   daemons attest with the chip and pin each other's launch measurement; a
   rogue worker (same certificate and sealing key, a simulated TEE instead
   of the chip) is refused at the handshake; the pinned worker is admitted
   and its Evidence verified to AMD's root; a gate job goes over the Return
   Path, the worker restores the model in memory through the door and
   answers, `sagvd` judges and signs the verdict; `acpctl audit verify`
   verifies the log under the key `sagvd identity` published.
5. Decodes the results from the serial console and deletes the VM and the
   bucket — always, also on failure.

## What a run leaves

```
evidence/<STAMP>/
├── verify/
│   ├── assets.sha256        every downloaded file, hashed
│   ├── cosign.txt           twelve "Verified OK" (eight before 0.4.2)
│   ├── slsa.txt             six "PASSED: SLSA verification passed" (four before 0.4.2)
│   ├── tag.txt              the tag's signature, the key that made it
│   ├── rebuild.txt          every rebuilt hash equal to the released file's
│   ├── uploaded.sha256      what went to the VM: release assets only
│   └── tools.txt            the tool versions, the tag, the time
├── serial-console.txt       the guest's output as captured
└── results/                 the guest's record (as returnpath-e2e/README.md describes it):
    reports, identities, the rogue refusal, the job's verdict, the audit log and its verification
```

Keys, seeds, tokens and configs stay on the VM and die with it; the record
holds reports, decisions and logs only.

## Runs

| Release | Evidence | Outcome |
|---|---|---|
| `v0.4.0` | [`evidence/20261015T012735Z/`](evidence/20261015T012735Z/) | 8 signatures, 4 provenances and the tag verified; both daemons attested with the chip; the rogue worker refused; the gate job EXACT 6/6; the audit log verified (17 events). 99 s on the guest. |
| `v0.4.1` | [`evidence/20261015T014459Z/`](evidence/20261015T014459Z/) | 8 signatures, 4 provenances and the tag verified; the four binaries rebuilt from the tag on another machine with the same sha256 as the released files; both daemons attested with the chip; the rogue worker refused; the gate job EXACT 6/6; the audit log verified (17 events). 101 s on the guest; three minutes after the release was published. |
