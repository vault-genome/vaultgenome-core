# Day-2 Operations Runbook — AWS Nitro Enclaves

AWS-specific operational runbook for Vault Genome deployments via the
production Terraform module (`deploy/terraform/aws/examples/production/`).

For TEE-agnostic disaster recovery semantics see
`core/docs/operator/runbooks/disaster_recovery.md`. For zero-to-deploy
see `docs/deployment/aws.md`.

---

## Day-1 verification (immediately after `terraform apply`)

Run through every item before declaring the deployment "live":

### 1. Enclave is loaded

```bash
INSTANCE_ID=$(terraform output -raw instance_id)
aws ssm start-session --target $INSTANCE_ID
# Inside the SSM session:
sudo nitro-cli describe-enclaves
```

Expected: one enclave, state `RUNNING`, allocator vCPU + memory matches
the Terraform `enclave_cpu` + `enclave_memory_mib` values.

If the enclave is missing or stuck in `TERMINATING`:
- Check `/var/log/nitro_enclaves/nitro_enclaves.log`
- Verify `/etc/nitro_enclaves/allocator.yaml` matches the variables
- Re-launch with `sudo nitro-cli run-enclave --eif-path …` from cloud-init

### 2. sagvd HTTP API is responsive

From a host inside `api_allowed_cidrs`:

```bash
PRIVATE_IP=$(terraform output -raw private_ip)
curl -sf http://$PRIVATE_IP:8080/healthz
# expect: {"status":"ok","version":"vX.Y.Z","uptime_seconds":NNN}
```

If 404 or connection refused:
- Verify security group inbound: port 8080 from `api_allowed_cidrs`
- Verify sagvd process is running: `systemctl status sagvd` on host
- Check sagvd logs in CloudWatch (`/var/log/sagvd.log` → log group)

### 3. KMS sealing key is bound to the right PCR0

```bash
KMS_ARN=$(terraform output -raw kms_key_arn)
aws kms get-key-policy --key-id $KMS_ARN --policy-name default \
  | jq '.Policy | fromjson | .Statement[] | select(.Sid=="EnclaveDecrypt")'
```

Expected: a `Condition` clause with `kms:RecipientAttestation:PCR0`
matching the value in `terraform.tfvars`. If it doesn't match, the
enclave will fail every Decrypt call.

### 4. Production-grade attestation captured

Capture a fresh attestation from THIS deployment for the data room:

```bash
# From the parent EC2 (inside SSM session):
sudo nitro-cli run-enclave --eif-path /opt/vault-genome/sagvd-prod.eif \
  --memory $((ENCLAVE_MEMORY_MIB)) --cpu-count $ENCLAVE_CPU \
  --enclave-cid 16
# Capture via vsock listener (kit's vsock-receive.py)
# Verify with kit's 08-normalize-attestation-output.py
```

Save: `production-attestation-YYYYMMDD.bin` + `production_grade: true`
verifier output. This binds **this specific Module ID** to the
deployment and proves the chip is operating as expected.

### 5. Audit bucket has Object Lock active (if production example)

```bash
AUDIT_BUCKET=$(terraform output -raw audit_bucket)
aws s3api get-object-lock-configuration --bucket $AUDIT_BUCKET
```

Expected: COMPLIANCE-mode, retention period = 2555 days (7 years).
If output is empty, Object Lock is NOT enabled — re-create the bucket
**before** any audit data is written, otherwise it cannot be retrofitted.

### 6. CloudWatch alerting wired up

The Terraform module creates the log group; you wire the alerts:

```bash
LOG_GROUP=$(terraform output -raw log_group)
# Create a metric filter for sagvd ERROR lines:
aws logs put-metric-filter --log-group-name $LOG_GROUP \
  --filter-name sagvd-errors \
  --filter-pattern '{ $.level = "ERROR" }' \
  --metric-transformations \
    metricName=sagvd_errors,metricNamespace=VaultGenome,metricValue=1
```

Then create a CloudWatch alarm on `VaultGenome/sagvd_errors > 0` for
5-minute window → SNS topic → PagerDuty/Opsgenie integration.

---

## Day-2 operations

### Rotating the enclave image (PCR0 changes)

When you update the `.eif` (e.g. new sagvd version), PCR0 changes,
which means the existing KMS key policy will refuse the new enclave's
Decrypt requests. Procedure:

1. **Build the new .eif** in a staging deployment first, capture new
   PCR0 via `nitro-cli describe-eif`.
2. **Add the new PCR0 as a SECOND condition** in the KMS key policy
   (so both old and new enclaves can Decrypt during the rollout):
   ```bash
   aws kms put-key-policy --key-id $KMS_ARN --policy-name default \
     --policy file://updated-policy-with-both-PCR0s.json
   ```
3. **Roll the EC2 instance** (terminate, let Auto Scaling Group bring
   up a new one with the new .eif baked into cloud-init, or
   `terraform apply` with the new `enclave_pcr0`).
4. **Verify the new enclave Decrypts successfully** end-to-end.
5. **Remove the old PCR0** from the KMS key policy.

This is a zero-downtime rotation if you have multi-AZ. For single-AZ
deployments, expect ~5 minutes of API unavailability while the new
enclave boots.

### Rotating the KMS sealing key

Automatic rotation is enabled by Terraform (`kms:EnableKeyRotation`),
so AWS rotates the underlying key material annually. No action
required for routine rotation.

For an **emergency manual rotation** (e.g. suspected key compromise),
you must re-seal every existing bundle with the new key — this is a
multi-day operation. See `disaster_recovery.md` § Manual key rotation.

### Scaling vertical (instance type)

Bump `instance_type` in `terraform.tfvars` from `m5.xlarge` to
`m5.2xlarge` (or larger). Then `terraform apply` — this stops + starts
the instance with the new type. Downtime: ~3 minutes.

If you need more enclave memory or vCPUs:
- Increase `enclave_memory_mib` (max ~70% of host RAM)
- Increase `enclave_cpu` (must be even, max = host vCPU − 2)
- Apply, the cloud-init re-launches the enclave with new allocator config

### Scaling horizontal (multi-instance)

Currently a single-instance deployment. For HA-ready (next sprint):
- Wrap the EC2 in an Auto Scaling Group with min=2, max=N
- Front with an internal Network Load Balancer on port 8080
- Each instance has its own enclave, all reading the same audit bucket
- Sealing key remains shared (PCR0-conditional)

This is on the roadmap; ETA depends on customer demand.

### S3 audit bucket archival

Audit objects stay in the bucket forever (Object Lock prevents
deletion). To control storage cost:

- Enable Intelligent-Tiering on the audit bucket (auto-archives cold
  objects to Glacier-Instant after 90 days)
- Audit reads from cold tier still work, just slower

```bash
aws s3api put-bucket-intelligent-tiering-configuration \
  --bucket $AUDIT_BUCKET --id default \
  --intelligent-tiering-configuration file://intelligent-tier.json
```

### AWS Backup snapshots

If `enable_backup_vault = true`, the module wires up daily snapshots
of the EBS volume. Verify:

```bash
aws backup list-backup-plans
aws backup list-recovery-points-by-backup-vault \
  --backup-vault-name vault-genome-prod
```

Restore from snapshot via `aws backup start-restore-job`. See AWS
Backup docs for restore procedures.

---

## Incident response

### CloudWatch alarm: sagvd ERROR rate elevated

1. Pull the last 50 ERROR lines from CloudWatch Logs Insights:
   ```
   fields @timestamp, level, msg, error
   | filter level = "ERROR"
   | sort @timestamp desc
   | limit 50
   ```
2. Common causes:
   - KMS Decrypt failures → check enclave is alive + PCR0 unchanged
   - S3 PutObject failures → check audit bucket policy + Object Lock
   - vsock connection failures → restart enclave
3. If unrecoverable, page on-call per
   `core/docs/operator/03_incident_response.md`

### GuardDuty finding

If `enable_guardduty = true`, check the AWS console GuardDuty page
weekly. Common findings on Vault Genome deployments:

| Finding type | Likely cause | Action |
|--------------|--------------|--------|
| `Recon:EC2/PortProbeUnprotectedPort` | Misconfigured SG | Tighten `api_allowed_cidrs` |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller.*` | IAM user compromised | Rotate keys, audit CloudTrail |
| `Behavior:EC2/NetworkPortUnusual` | Exfiltration attempt | Review enclave + sagvd state, escalate |

For attestation-related findings (rare), capture a fresh attestation
and compare PCR0 to the deployed-time value. PCR0 mismatch =
**critical**, the enclave content has changed.

### Enclave unexpectedly terminated

```bash
sudo nitro-cli describe-enclaves
# If empty:
sudo journalctl -u nitro-enclaves-allocator --since "1 hour ago"
```

Re-launch:
```bash
sudo nitro-cli run-enclave --eif-path /opt/vault-genome/sagvd-prod.eif \
  --memory 8192 --cpu-count 4 --enclave-cid 16
```

If the enclave repeatedly terminates:
- Check parent EC2 free memory (`free -h`) — allocator may have failed
- Check `/var/log/nitro_enclaves/nitro_enclaves.log`
- Re-build the .eif and re-deploy if the binary is corrupt

### Cross-region disaster recovery

If `us-east-2` becomes unavailable:

1. Spin up the production module in `us-west-2` (or `eu-west-1`)
   with the **same** PCR0 and the **same** workload manifest
2. The new region's EC2 has its own Module ID but same KMS key policy
   (PCR0-conditional)
3. Restore the latest sealed bundle from the audit S3 (cross-region
   replicated) onto the new EC2
4. Inference will be **byte-identical** to the original — proven in
   our Week 2 cross-region test (Ohio → Ireland)

See `disaster_recovery.md` for the full DR runbook.

---

## Tear-down

### Planned migration (no Object Lock)

```bash
cd deploy/terraform/aws/examples/minimal/
terraform destroy
```

Completes in ~3 minutes.

### Production with Object Lock COMPLIANCE-mode

```bash
cd deploy/terraform/aws/examples/production/
terraform destroy
```

⚠️ The audit bucket and its objects **will NOT be deleted** because
COMPLIANCE-mode prevents deletion until retention expires (7 years
default). Everything else (EC2, KMS, IAM, log group) tears down
normally.

To delete the audit bucket within the retention window, you would need
to either:
- Wait for retention to expire (7 years), OR
- Use `audit_object_lock_mode = "GOVERNANCE"` (admin-overridable)
  instead of COMPLIANCE on the original deployment

This is the **intended behavior** for regulated deployments — the
audit chain is supposed to outlive the running system.

---

## Cost monitoring

Set up an AWS Cost Anomaly Detector on the resource tags:

```bash
aws ce create-anomaly-monitor --anomaly-monitor file://cost-monitor.json
```

Where `cost-monitor.json` filters for `vault-genome.*` tag values
(set automatically by the Terraform module). Anomalies route to SNS
→ Slack.

Expected baseline (production example, m5.2xlarge, all hardening):
- ~$295/month steady-state
- ±10% normal variance from CloudWatch + GuardDuty usage
- Spikes >$50 above baseline = investigate

---

## See also

- `docs/deployment/aws.md` — full deployment guide (start here)
- `core/docs/operator/runbooks/disaster_recovery.md` — TEE-agnostic DR
- `core/docs/operator/00_overview.md` — operator overview
- `core/docs/operator/03_incident_response.md` — incident escalation
- `core/docs/security/threat_model.md` — threat model
- `deploy/terraform/aws/README.md` — Terraform module reference
