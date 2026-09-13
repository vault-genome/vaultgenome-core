# Day-2 Operations Runbook — Azure (SEV-SNP + SGX)

Azure-specific operational runbook for Vault Genome deployments via the
production Terraform modules at:
- `deploy/terraform/azure-sev-snp/examples/production/` (AMD SEV-SNP)
- `deploy/terraform/azure-sgx/examples/production/` (Intel SGX)

For TEE-agnostic disaster recovery semantics see
`core/docs/operator/runbooks/disaster_recovery.md`. For zero-to-deploy
see `docs/deployment/azure.md`.

This runbook covers **both backends** in unified form. Where commands
differ, both variants are shown side-by-side.

---

## Day-1 verification (immediately after `terraform apply`)

Run through every item before declaring the deployment "live":

### 1. VM is running and TEE devices present

```bash
VM_ID=$(terraform output -raw vm_id)
RG=$(terraform output -raw resource_group_name)

# Confirm VM is running
az vm show --ids "$VM_ID" --query "powerState" -o tsv
# Expect: "VM running"

# SSH in and verify TEE devices
PRIVATE_IP=$(terraform output -raw private_ip)
ssh azureuser@"$PRIVATE_IP"
```

**SEV-SNP**:
```bash
ls -l /dev/sev-guest
# Expect: crw------- 1 root root 10, ... /dev/sev-guest
```

**SGX**:
```bash
ls -l /dev/sgx_enclave /dev/sgx_provision
# Expect both present
```

If devices are missing — VM was provisioned without confidential
compute / SGX enabled. Re-deploy with the correct VM family.

### 2. sagvd HTTP API is responsive

From a host inside `api_allowed_cidrs`:
```bash
curl -sf http://"$PRIVATE_IP":8080/healthz
# Expect: {"status":"ok","version":"vX.Y.Z","uptime_seconds":NNN}
```

If 404 or connection refused:
- Verify NSG inbound: port 8080 from `api_allowed_cidrs`
- Verify sagvd container is running: `docker ps` on host
- Check sagvd logs in Log Analytics workspace

### 3. Key Vault sealing key is bound to the right MAA policy

```bash
KV_URI=$(terraform output -raw key_vault_uri)
KEY_ID=$(terraform output -raw sealing_key_id)

az keyvault key show --vault-name "${KV_URI##https://}" --name vault-genome-sealing \
  --query 'release_policy' -o json
```

Expected: a policy with `claim` conditions for
`x-ms-attestation-type=sevsnpvm` (SEV-SNP) or
`x-ms-attestation-type=sgx` (SGX), plus `compliance-status` condition.

If the policy doesn't match, the VM will fail every Release call.

### 4. Production-grade attestation captured

Capture a fresh attestation from THIS deployment for the data room:

**SEV-SNP**:
```bash
ssh azureuser@"$PRIVATE_IP" "
  sudo /usr/local/bin/snpguest report production-attestation.bin /dev/urandom-bytes
  /usr/local/bin/snpguest display report production-attestation.bin > production-decoded.txt
"
scp azureuser@"$PRIVATE_IP":~/production-attestation.bin .
scp azureuser@"$PRIVATE_IP":~/production-decoded.txt .
```

**SGX**:
```bash
ssh azureuser@"$PRIVATE_IP" "
  oeutil generate-evidence -f sgx_ecdsa --out-file production-quote.bin
  oeutil dump-evidence -f production-quote.bin > production-quote-dump.txt
"
scp azureuser@"$PRIVATE_IP":~/production-quote.bin .
scp azureuser@"$PRIVATE_IP":~/production-quote-dump.txt .
```

Save: `production-attestation-YYYYMMDD.bin` + decoded text. This binds
**this specific Chip ID** (SEV-SNP) or **this MRENCLAVE binary** (SGX)
to the deployment.

### 5. Storage immutability policy is locked (production example)

```bash
STORAGE=$(terraform output -raw audit_storage_account)
az storage container immutability-policy show \
  --account-name "$STORAGE" --container-name audit-chain
```

Expected: `state = Locked`, `immutabilityPeriodSinceCreationInDays = 2555`
(7 years). If state is Unlocked or empty, immutability is NOT enforced
— re-create the container **before** any audit data is written, or
deletion will be possible.

### 6. Diagnostic settings + alerts wired up

The Terraform module creates the Log Analytics workspace; you wire alerts:

```bash
WORKSPACE_NAME=$(terraform output -raw log_workspace_name)

# Create an alert rule for sagvd ERROR rate
az monitor scheduled-query create \
  --name sagvd-error-rate \
  --resource-group "$RG" \
  --scopes "/subscriptions/.../resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME" \
  --condition "count 'AzureDiagnostics | where Level == \"Error\" and Resource contains \"vault-genome\"' > 0" \
  --window-size 5m \
  --evaluation-frequency 5m \
  --severity 2 \
  --action-groups "/subscriptions/.../actionGroups/ops-pagerduty"
```

Then route the action group to PagerDuty/Opsgenie via webhook.

---

## Day-2 operations

### Rotating the launch measurement (SEV-SNP) or MRENCLAVE (SGX)

When you update the workload binary, the measurement changes, which means
the existing Key Vault release policy will refuse the new VM's release
requests. Procedure:

1. **Build the new container/enclave** in a staging deployment first;
   capture new measurement via `snpguest display` or `oeutil dump-evidence`.

2. **Update the Key Vault release_policy** to allow BOTH old and new
   measurements (so both can release during the rollout):
   ```bash
   az keyvault key set-attributes --vault-name <kv> --name vault-genome-sealing \
     --release-policy @updated-policy-with-both-measurements.json
   ```

3. **Roll the VM**: terminate, let new VM come up with new image baked
   into cloud-init (or `terraform apply` with new tag).

4. **Verify the new VM unseals successfully** end-to-end.

5. **Remove the old measurement** from the release policy.

This is a zero-downtime rotation if you have multi-zone. For single-zone
deployments, expect ~5 minutes of API unavailability while the new VM boots.

### Rotating the Key Vault sealing key

Automatic rotation via Key Vault rotation policy is enabled by default
(see Terraform `key_vault_key.sealing` configuration). Azure rotates the
underlying key material per the policy.

For an **emergency manual rotation** (e.g. suspected key compromise),
you must re-seal every existing bundle with the new key version — this
is a multi-day operation. See `disaster_recovery.md` § Manual key rotation.

### Scaling vertical (VM size)

Bump `vm_size` in `terraform.tfvars` from `Standard_DC4as_v5` to
`Standard_DC8as_v5` (or larger). Then `terraform apply` — this stops +
starts the VM with the new size. Downtime: ~3 minutes.

DCasv5 family supports up to 96 vCPU (DC96as_v5). DCsv3 family has
narrower options; check Microsoft docs for current SKU list.

### Scaling horizontal (multi-VM)

Currently single-VM deployment. For HA-ready (next sprint):
- Wrap VM in a VM Scale Set with min=2, max=N
- Front with internal Standard Load Balancer on port 8080
- Each VM has its own confidential boundary, all reading the same
  audit storage account
- Sealing key remains shared (MAA-conditional release)

This is on the roadmap; ETA depends on customer demand.

### Storage account archival

Audit blobs stay in the container forever (immutability prevents
deletion). To control storage cost:

- Enable lifecycle management to auto-tier cold blobs to Cool/Archive
  tier after 90 days
- Audit reads from cold tier still work, just slower

```bash
az storage account management-policy create \
  --account-name "$STORAGE" \
  --policy '{
    "rules": [{
      "enabled": true,
      "name": "audit-archival",
      "type": "Lifecycle",
      "definition": {
        "actions": {
          "baseBlob": {
            "tierToCool": { "daysAfterModificationGreaterThan": 30 },
            "tierToArchive": { "daysAfterModificationGreaterThan": 90 }
          }
        },
        "filters": { "blobTypes": ["blockBlob"], "prefixMatch": ["audit-chain/"] }
      }
    }]
  }'
```

### Recovery Services Vault snapshots

If `enable_backup_vault = true`, the module wires up daily snapshots
of the OS disk. Verify:

```bash
az backup vault list --resource-group "$RG"
az backup recoverypoint list \
  --resource-group "$RG" \
  --vault-name vault-genome-prod-rsv \
  --container-name "vault-genome-prod-vm" \
  --item-name "vault-genome-prod-vm" \
  --backup-management-type AzureIaasVM \
  --workload-type VM
```

Restore from snapshot via `az backup restore` — see Microsoft docs.

---

## Incident response

### Log Analytics alert: sagvd ERROR rate elevated

1. Pull the last 50 ERROR lines from Log Analytics:
   ```kql
   AzureDiagnostics
   | where Level == "Error" and Resource contains "vault-genome"
   | sort by TimeGenerated desc
   | take 50
   ```

2. Common causes:
   - Key Vault release failures → check VM is alive + measurement unchanged
   - Storage PutBlob failures → check storage account RBAC + immutability
   - MAA endpoint unreachable → check network egress + MAA service status
3. If unrecoverable, page on-call per
   `core/docs/operator/03_incident_response.md`

### Microsoft Defender for Cloud finding

If `enable_defender = true`, check the Azure portal Defender page weekly.
Common findings on Vault Genome deployments:

| Finding type | Likely cause | Action |
|--------------|--------------|--------|
| `RecommendedSecurityRulesShouldBeAppliedToNSG` | Misconfigured NSG | Tighten `api_allowed_cidrs` |
| `JustInTimeNetworkAccessShouldBeApplied` | SSH open to public | Use Azure Bastion or VPN |
| `BehaviorEC2NetworkPortUnusual` | Exfiltration attempt | Review VM + sagvd state, escalate |

For attestation-related findings (rare), capture a fresh attestation
and compare measurement to the deployed-time value. Mismatch =
**critical**, the running content has changed.

### VM unexpectedly stopped

```bash
az vm get-instance-view --ids "$VM_ID" --query "instanceView.statuses"
# Look for "PowerState/stopped"

# If stopped, check Activity Log for cause
az monitor activity-log list --resource-id "$VM_ID" --max-events 20
```

Restart:
```bash
az vm start --ids "$VM_ID"
```

If the VM repeatedly stops:
- Check Defender / Azure Advisor for a recommendation
- Check VM resource health in portal
- Re-deploy the resource group if the underlying Confidential VM
  hardware has a hold (rare; Microsoft auto-evicts to healthy hardware)

### Cross-region disaster recovery

If `eastus2` becomes unavailable:

1. Spin up the production module in `westeurope` (or `eastus`) with
   the **same** measurement and the **same** workload manifest
2. The new region's VM has its own Chip ID but same Key Vault release
   policy (MAA-conditional)
3. Restore the latest sealed bundle from the audit Storage (cross-region
   copy via geo-replication on GZRS, or manual blob copy) onto the new VM
4. Inference will be **byte-identical** to the original — proven in
   our cross-region test (eastus2 → westeurope)

See `disaster_recovery.md` for the full DR runbook.

---

## Tear-down

### Planned migration (no immutability)

```bash
cd deploy/terraform/azure-sev-snp/examples/minimal/   # or azure-sgx
terraform destroy
```

Completes in ~5 minutes. Key Vault is soft-deleted for 90 days; reuse
the same `name` only after purge or 90-day expiration.

### Production with immutability LOCKED

```bash
cd deploy/terraform/azure-sev-snp/examples/production/   # or azure-sgx
terraform destroy
```

⚠️ The audit container and its blobs **will NOT be deleted** because
immutability LOCKED prevents deletion until retention expires (7 years
default). Everything else (VM, NSG, Log Analytics) tears down normally.

To delete the audit container within retention, you would need to:
- Wait for retention to expire (7 years), OR
- Re-deploy with a new `name` and let the old resources become orphaned, OR
- Use unlocked immutability initially (admin-overridable but auditors
  may reject)

This is the **intended behavior** for regulated deployments — the audit
chain is supposed to outlive the running system.

---

## Cost monitoring

Set up an Azure Cost Anomaly alert on the resource tags:

```bash
az consumption budget create \
  --budget-name vault-genome-budget \
  --amount 250 \
  --time-grain Monthly \
  --start-date 2026-05-01 \
  --end-date 2027-04-30 \
  --notifications "[{...slack-webhook...}]"
```

Set thresholds for tag values like `vault-genome.product=sagvd`. Anomalies
route to your action group → Slack/email.

Expected baseline (production example, DC4as_v5 SEV-SNP, all hardening):
- ~$200/month steady-state
- ±10% normal variance from Log Analytics + Defender usage
- Spikes >$50 above baseline = investigate

---

## See also

- `docs/deployment/azure.md` — full deployment guide (start here)
- `core/docs/operator/runbooks/disaster_recovery.md` — TEE-agnostic DR
- `core/docs/operator/00_overview.md` — operator overview
- `core/docs/operator/03_incident_response.md` — incident escalation
- `core/docs/security/threat_model.md` — threat model
- `deploy/terraform/azure-sev-snp/README.md` — SEV-SNP Terraform reference
- `deploy/terraform/azure-sgx/README.md` — SGX Terraform reference
- `core/scripts/hardware-test/azure-sev-snp/README.md` — SEV-SNP validation kit
- `core/scripts/hardware-test/azure-sgx/README.md` — SGX validation kit
