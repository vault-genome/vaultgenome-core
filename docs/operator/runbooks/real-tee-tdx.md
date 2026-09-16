# Runbook: real Intel TDX attestation (production TEE mode)

`sagvd`, `acp-compute` and `acp-bootstrap` attest with the Trust Domain they
run in when `tee.provider` is `"gcp-tdx"` (ADR 0018): a TDX quote requested
through the kernel's configfs-tsm interface (provider `tdx_guest`), signed by
the host's Quoting Enclave under a key the platform's PCK certificate
certifies, chained to the Intel SGX Root CA. The verifier for a `gcp-tdx`
peer or destination runs anywhere — it needs no hardware, only Intel's two
public documents (TCB info, QE identity), fetched from Intel PCS and kept in
a cache directory. This is the CPU side of a confidential GPU machine
(Google `a3` with confidential H100, Azure `NCC` H100) and of Google's `c3`
Confidential VMs with TDX; the GPU's own attestation is not wired.

The SEV-SNP counterpart is [real-tee-sev-snp.md](real-tee-sev-snp.md).

---

## A. A Trust Domain on GCP

```bash
gcloud compute instances create <name> --zone us-central1-a \
  --machine-type c3-standard-4 --confidential-compute-type TDX \
  --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud
```

Inside the guest (`kernel 6.7+`; Ubuntu 24.04's GCP kernel qualifies):

```bash
mount -t configfs none /sys/kernel/config 2>/dev/null || true
ls /sys/kernel/config/tsm/report      # the interface the producer uses
ls -la /dev/tdx_guest                 # the TDX guest driver
dmesg | grep -i tdx                   # "tdx: Guest detected", "Memory Encryption Features active: Intel TDX"
```

Nothing else is installed: the producer speaks configfs-tsm itself, the
quote comes from the host's Quote Generation Service, and the daemons run
as root (configfs-tsm report entries need it) or with a udev rule that
opens `/sys/kernel/config/tsm/report` to their user.

## B. What a TDX pin is

`sagvd identity`, `acp-compute identity` and `acp-bootstrap identity` print
`tee_provider: gcp-tdx`, the 48-byte `tee_measurement_hex` and a `tdx` block:

```json
"tdx": { "mrtd_hex": "c1ee9c16…", "rtmr_hex": ["60d411d6…", "c7183cb4…", "90e31c74…", "0000…"] }
```

The measurement is `SHA-384(MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2 ‖ RTMR3)`: MRTD is
the virtual firmware, RTMR0 its configuration, RTMR1 and RTMR2 the kernel,
initrd and command line as the boot chain extended them, RTMR3 whatever the
guest extended at run time (nothing, on a stock image). Recompute it from
the block to check what you pin:

```bash
python3 -c 'import hashlib,json,sys; j=json.load(sys.stdin); t=j["tdx"]
print(hashlib.sha384(bytes.fromhex(t["mrtd_hex"]+"".join(t["rtmr_hex"]))).hexdigest()==j["tee_measurement_hex"])' < identity.json
```

**A new image is a new pin.** A kernel, initrd or command-line change moves
RTMR1/RTMR2 and with them the measurement; re-issue the peer's pin from
`identity` after every image change, as for a SEV-SNP launch measurement.

Write the 48 raw bytes to the other side's `tee.peer.measurement_path`:

```bash
python3 -c 'import json,sys; sys.stdout.buffer.write(bytes.fromhex(json.load(sys.stdin)["tee_measurement_hex"]))' < identity.json > /etc/acp/pins/peer.measurement
```

## C. The Return Path on TDX

`sagvd`:

```json
"tee": {
  "provider": "gcp-tdx", "workload_descriptor": "sagvd-v1",
  "peer": { "provider": "gcp-tdx",
            "measurement_path": "/etc/acp/pins/worker.measurement",
            "pcs_cache_dir": "/var/lib/acp/pcs-cache" } }
```

`acp-compute` mirrors it (`tee.provider: "gcp-tdx"`, `tee.peer` pinning
the vault's measurement, its own `pcs_cache_dir`). No seed, no attestation
key file, no AMD fields: a TDX pin with `amd_cert_chain_path`,
`vcek_cache_dir`, `amd_kds_url` or `min_reported_tcb`, or a SEV-SNP pin with
`pcs_url`, `pcs_cache_dir` or `acceptable_tcb_statuses`, is refused at
start.

What the verifier does with a peer's quote, in order: parses it by its
layout (version 4, ECDSA-P256 attestation key, TEE type TDX); chains the
PCK certificate chain the quote carries to the pinned Intel SGX Root CA;
checks the attestation key's signature over the TD report, the PCK leaf's
signature over the QE report and the QE report's binding of the attestation
key; fetches Intel's TCB info for the platform's FMSPC and the QE identity,
verifies their signatures under the TCB signing chain before reading them;
rates the platform, the TDX module and the QE; refuses a debuggable TD;
requires REPORTDATA to bind the handshake's challenge; and compares the
measurement with the pin. Every refusal names its step in the log and on
the audit record.

### Intel PCS and the cache

- `pcs_url` (default `https://api.trustedservices.intel.com`): a PCCS or a
  mirror goes here. The documents are signed by Intel; the mirror is not
  trusted, only reached through.
- `pcs_cache_dir`: the TCB info (`tdx-tcb-<fmspc>.json`) and the QE identity
  (`tdx-qe-identity.json`), each with its issuer chain beside it. A cached
  document is verified like a fresh one on every use and re-fetched once
  past its `nextUpdate` (Intel issues them monthly). Set it: a burst of
  handshakes then asks Intel once, and a short PCS outage costs nothing.
- **Fail closed.** No usable document — none cached, or expired, and Intel
  unreachable — is a refusal of the peer, not an admission. Fill the cache
  at deploy time by running `identity` on the peer and one handshake, or
  copy the two files from a machine that has them.

### TCB statuses

`acceptable_tcb_statuses` lists the Intel TCB statuses accepted for the
platform, the TDX module and the QE. Default: `["UpToDate"]`. An operator
who runs a platform Intel rates `SWHardeningNeeded`,
`ConfigurationNeeded` or `ConfigurationAndSWHardeningNeeded` lists those
knowingly. `OutOfDate`, `OutOfDateConfigurationNeeded` and `Revoked` are
never accepted; a configuration that lists them is refused at start. The
refusal log line names the part (`platform TCB`, `TDX module TCB`, `QE TCB`)
and its status, so the decision to widen the list is made on Intel's word,
not on a guess.

## D. A TDX destination for a key release

`acp-bootstrap` with `"tee": { "provider": "gcp-tdx" }` attests with the
Trust Domain; on the source, register the family in `sagvd`'s verifier
registry:

```json
{ "verifiers": [ {
  "provider": "gcp-tdx",
  "expected_measurement_hex": "<tee_measurement_hex from acp-bootstrap identity>",
  "pcs_cache_dir": "/var/lib/acp/pcs-cache",
  "acceptable_tcb_statuses": ["UpToDate"]
} ] }
```

and put the same measurement on the allow-list under `"gcp-tdx"`. The
release path is the one [06_cross_cloud_restore.md](../06_cross_cloud_restore.md)
describes; a key release to a TDX destination has not yet been run on
hardware (the Return Path on TDX has, §E).

## E. What has run on hardware

- [`scripts/hardware-test/gcp-tdx/capture/`](../../../scripts/hardware-test/gcp-tdx/capture/README.md)
  — a genuine `c3-standard-4` quote with caller nonces and the Intel PCS
  documents for it; the verifier's tests run against this capture, offline.
- [`scripts/hardware-test/gcp-tdx/returnpath-e2e/`](../../../scripts/hardware-test/gcp-tdx/returnpath-e2e/README.md)
  — `sagvd` and `acp-compute` on one Trust Domain, each pinning the other,
  the real `vg_genome` door, a gate job over the Return Path, a rogue worker
  refused on the record; the README carries the measured run.
- [`scripts/hardware-test/failover-tdx/`](../../../scripts/hardware-test/failover-tdx/README.md)
  — the continuity drill with the standby a Trust Domain: `acp-bootstrap`
  as `gcp-tdx` takes the key release from a SEV-SNP authority under a
  policy pinning its measurement, restores the genome and gates it on its
  CPUs; the README carries the measured run.

## F. The escrow key: sealed to the vTPM

TDX gives a guest no sealing key of its own, and a plaintext escrow key
is refused on any hardware TEE (ADR 0016). Since ADR 0022 `sagvd` seals
the escrow key to the guest's vTPM: `tpm2-tools` on the guest (`apt-get
install tpm2-tools`; `/dev/tpmrm0` on a GCP `c3` Trust Domain), the key
held by the vTPM under a policy of this boot's PCRs
(`tee.vtpm_seal_pcrs`, default sha256:0-14), the recovery ceremony
unchanged, and `sagvd seal-keys` / `acp-compute seal-keys` seal the
daemons' other key files the same way (ADR 0023). A TDX host is a worker,
a destination, or the release
authority — proven as the authority of a failover in
[`scripts/hardware-test/failover-tdx-authority/`](../../../scripts/hardware-test/failover-tdx-authority/README.md).
A kernel or firmware update changes the PCRs: re-provision from the
recovery envelope after one.

## Cleanup (cost hygiene)

Delete the VM after the run; a stopped Confidential VM still bills its disk.
The hardware kits delete their VM and bucket on exit, on success or failure.
