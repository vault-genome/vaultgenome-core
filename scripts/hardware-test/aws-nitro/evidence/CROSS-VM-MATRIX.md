# Cross-VM AWS Nitro Enclaves Attestation Matrix

**Generated:** 2026-05-08T01:02:12Z
**Cohort size:** 4 VMs across regions/AZs
**Test Kit:** `core/scripts/hardware-test/aws-nitro/`
**Anchor:** AWS Nitro Root CA G1 (`CN=aws.nitro-enclaves, O=Amazon, C=US`)

---

## 1. Hardware identity

Each Nitro Security Module has a unique `module_id` baked into the chip.
Distinct `module_id` values prove distinct physical hardware instances.

| VM | Region | AZ | Instance ID | Module ID |
|----|--------|-----|-------------|-----------|
| VM1 | us-east-2 | us-east-2a | `i-0e35190ae3157095d` | `i-0e35190ae3157095d-enc019e0512a5715d4f` |
| VM2 | us-east-2 | us-east-2b | `i-0bd337f6016592526` | `i-0bd337f6016592526-enc019e051510f2b161` |
| VM3 | us-east-2 | us-east-2c | `i-048db5e223f6854af` | `i-048db5e223f6854af-enc019e0516e3dcf1e8` |
| VM4 | eu-west-1 | eu-west-1a | `i-0bd0777f07917c095` | `i-0bd0777f07917c095-enc019e05191df392d3` |

## 2. Workload binding (REPORT_DATA / user_data)

All enclaves were given the **same** `report-data.bin` (SHA-512 of the
Vault Genome workload manifest). The Nitro hypervisor signed each attestation
with that user_data embedded — proving the attestation describes *this*
specific workload, not some other binary.

| VM | user_data (first 32 bytes) | Match expected |
|----|-----------------------------|----------------|
| VM1 | `6775ac5075b68a5b48767c1cc1e11a28d761158adfd6236da96bac19450a6f2a…` | ✓ |
| VM2 | `6775ac5075b68a5b48767c1cc1e11a28d761158adfd6236da96bac19450a6f2a…` | ✓ |
| VM3 | `6775ac5075b68a5b48767c1cc1e11a28d761158adfd6236da96bac19450a6f2a…` | ✓ |
| VM4 | `6775ac5075b68a5b48767c1cc1e11a28d761158adfd6236da96bac19450a6f2a…` | ✓ |

## 3. Cryptographic chain validation per VM

Each attestation document is COSE_Sign1 (CBOR/COSE wire format), signed
with ECDSA P-384 over SHA-384. Validation checks:

1. **chain** — each cert in cabundle signed by the previous one
2. **anchor** — root of cabundle matches AWS Nitro Root CA G1 fingerprint
3. **COSE_Sign1** — leaf cert public key verifies the COSE signature
4. **user_data** — payload's `user_data` field matches expected SHA-512

| Check | VM1 | VM2 | VM3 | VM4 |
|---|---|---|---|---|
| Attestation document captured | ✓ | ✓ | ✓ | ✓ |
| Chain valid (cabundle integrity) | ✓ | ✓ | ✓ | ✓ |
| Anchor valid (Root CA G1) | ✓ | ✓ | ✓ | ✓ |
| COSE_Sign1 (ECDSA P-384) | ✓ | ✓ | ✓ | ✓ |
| user_data binding (SHA-512 manifest) | ✓ | ✓ | ✓ | ✓ |
| PCR0 non-zero (production mode marker) | ✓ | ✓ | ✓ | ✓ |
| PCR0 matches expected (built .eif binding) | ✓ | ✓ | ✓ | ✓ |
| **All core checks pass** | **✓** | **✓** | **✓** | **✓** |
| **Production-grade (core + non-zero PCR0 + match)** | **✓** | **✓** | **✓** | **✓** |

## 4. Certificate chain (proof of common AWS PKI anchor)

All attestations chain back to the SAME root certificate
(`CN=aws.nitro-enclaves`), but through **different intermediates**
(regional + zonal + per-instance), proving distinct hardware while
validating against one common AWS-signed PKI root.

**VM1 (us-east-2 us-east-2a)**

01. CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US
02. CN=77af59e854502979.us-east-2.aws.nitro-enclaves,OU=AWS,O=Amazon,C=US
03. L=Seattle,ST=WA,C=US,O=Amazon,OU=AWS,CN=ed0a5aa9a2f05a5.zonal.us-east-2.aws.nitro-enclaves
04. CN=i-0e35190ae3157095d.us-east-2.aws.nitro-enclaves,OU=AWS,O=Amazon,L=Seattle,ST=Washington,C=US
05. CN=i-0e35190ae3157095d-enc019e0512a5715d4f.us-east-2.aws,OU=AWS,O=Amazon,L=Seattle,ST=Washington,C=US

**VM2 (us-east-2 us-east-2b)**

01. CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US
02. CN=77af59e854502979.us-east-2.aws.nitro-enclaves,OU=AWS,O=Amazon,C=US
03. L=Seattle,ST=WA,C=US,O=Amazon,OU=AWS,CN=6183b8d0682f243d.zonal.us-east-2.aws.nitro-enclaves
04. CN=i-0bd337f6016592526.us-east-2.aws.nitro-enclaves,OU=AWS,O=Amazon,L=Seattle,ST=Washington,C=US
05. CN=i-0bd337f6016592526-enc019e051510f2b161.us-east-2.aws,OU=AWS,O=Amazon,L=Seattle,ST=Washington,C=US

**VM3 (us-east-2 us-east-2c)**

01. CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US
02. CN=77af59e854502979.us-east-2.aws.nitro-enclaves,OU=AWS,O=Amazon,C=US
03. L=Seattle,ST=WA,C=US,O=Amazon,OU=AWS,CN=2f468f6e8ad83d70.zonal.us-east-2.aws.nitro-enclaves
04. CN=i-048db5e223f6854af.us-east-2.aws.nitro-enclaves,OU=AWS,O=Amazon,L=Seattle,ST=Washington,C=US
05. CN=i-048db5e223f6854af-enc019e0516e3dcf1e8.us-east-2.aws,OU=AWS,O=Amazon,L=Seattle,ST=Washington,C=US

**VM4 (eu-west-1 eu-west-1a)**

01. CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US
02. CN=8e5e546f557e571f.eu-west-1.aws.nitro-enclaves,OU=AWS,O=Amazon,C=US
03. L=Seattle,ST=WA,C=US,O=Amazon,OU=AWS,CN=e530eb4738b10688.zonal.eu-west-1.aws.nitro-enclaves
04. CN=i-0bd0777f07917c095.eu-west-1.aws.nitro-enclaves,OU=AWS,O=Amazon,L=Seattle,ST=Washington,C=US
05. CN=i-0bd0777f07917c095-enc019e05191df392d3.eu-west-1.aws,OU=AWS,O=Amazon,L=Seattle,ST=Washington,C=US

## 5. Reproducibility

This entire matrix can be reproduced by any third party with an AWS account:

```bash
git clone https://github.com/<org>/<repo>.git && cd repo
cd vaultgenome-core/scripts/hardware-test/aws-nitro/
for az in us-east-2a us-east-2b us-east-2c eu-west-1a; do
  TF_VAR_availability_zone=$az TF_VAR_instance_name=vault-genome-nitro-$az \
    ./examples/full-test-run.sh
done
./scripts/07-cross-vm-matrix.sh ./evidence-root/
```

Total cost on AWS: about $0.50 (4× m5.xlarge × ~30 min wall time).

## 6. Attestation timestamps (Nitro hypervisor clocks)

Each timestamp is set by the AWS Nitro hypervisor at the moment of
attestation request. Spread across multiple regions in the same hour
shows independent hypervisors, not a replay of one document.

| VM | Timestamp (UTC) | Unix ms |
|----|-----------------|---------|
| VM1 | 2026-05-08T00:52:52Z | 1778201572755 |
| VM2 | 2026-05-08T00:55:31Z | 1778201731835 |
| VM3 | 2026-05-08T00:57:30Z | 1778201850976 |
| VM4 | 2026-05-08T00:59:57Z | 1778201997029 |

---

_**Vault Genome Inc.** — AWS Nitro Enclaves hardware validation cohort_
_AGPL-3.0-or-later (kit + tools) · NDA-scoped artifacts_
