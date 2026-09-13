# Grafana dashboards for Vault Genome

This directory contains operator-grade Grafana dashboard JSON files
that consume the Prometheus metrics exposed by `sagvd`'s `/metrics`
endpoint.

## Dashboards

| File                          | Audience    | Purpose                                                         |
|-------------------------------|-------------|------------------------------------------------------------------|
| [`sagvd-overview.json`](sagvd-overview.json)   | On-call SRE | Daemon health: queue depth, sessions, jobs, handshakes, errors  |
| [`tee-overview.json`](tee-overview.json)       | Security    | TEE per-provider: attestation rate, latency, sealing throughput |

Both dashboards target Grafana 10.x and assume a Prometheus
data-source named `Prometheus` (the default for most installs). To
use a different data-source, edit the `datasource` field in each
panel after import or use Grafana's "Replace data source" feature.

## Importing

### Via the UI

1. In Grafana, navigate to **Dashboards → Import**.
2. Click **Upload JSON file** and select one of the files in this
   directory.
3. Map the `Prometheus` data-source variable to your installation's
   data-source.
4. Click **Import**.

### Via the Grafana API

```bash
DASHBOARD_JSON=$(jq '.dashboard' deploy/grafana/sagvd-overview.json)
curl -X POST \
  -H "Authorization: Bearer $GRAFANA_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"dashboard\": $DASHBOARD_JSON, \"overwrite\": true}" \
  "$GRAFANA_URL/api/dashboards/db"
```

### Via Grafana provisioning

Drop the JSON files into your Grafana provisioning directory (typically
`/etc/grafana/provisioning/dashboards/`) and add a provisioning entry:

```yaml
apiVersion: 1
providers:
  - name: 'vault-genome'
    folder: 'Vault Genome'
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards/vault-genome
```

## Panels overview

### sagvd-overview.json

- **Daemon up** — `up{job="sagvd"}`, single-stat
- **Queue depth** — `sagvd_queue_depth`, time-series
- **Sessions opened (rate)** — `rate(sagvd_sessions_opened[5m])`
- **Jobs by outcome** — `rate(sagvd_jobs_completed_total[5m])` by `outcome`
- **Handshake failures by phase** — `sum by (phase) (rate(sagvd_handshake_failure_total[5m]))`
- **Time since last success** — `time() - sagvd_last_success_unix`

### tee-overview.json

- **Attestation rate by provider/role** — `sum by (provider, role) (rate(vg_tee_attestation_total[5m]))`
- **Attestation P99 latency** — `histogram_quantile(0.99, sum by (provider, role, le) (rate(vg_tee_attestation_duration_seconds_bucket[5m])))`
- **Sealing rate by provider/op** — `sum by (provider, op) (rate(vg_tee_sealing_total[5m]))`
- **Sealing P95 latency** — `histogram_quantile(0.95, sum by (provider, op, le) (rate(vg_tee_sealing_duration_seconds_bucket[5m])))`
- **Errors by provider** — `sum by (provider) (rate(vg_tee_attestation_total{result="error"}[5m]))`
- **Capability availability table** — `vg_tee_capability_total` by `provider` × `available`

## SLI / SLO suggestions

The dashboards do not enforce SLOs by themselves; suggested alerting
expressions for the most common operator-side targets:

| SLO                                                         | Prometheus alert                                                                   |
|-------------------------------------------------------------|------------------------------------------------------------------------------------|
| Daemon must be running                                      | `up{job="sagvd"} == 0` for 1m                                                      |
| Last successful job ≤ 10 min ago                            | `time() - sagvd_last_success_unix > 600`                                           |
| Queue depth ≤ 500                                           | `sagvd_queue_depth > 500` for 5m                                                   |
| Attestation error rate ≤ 1% over 10m window                 | `(rate(vg_tee_attestation_total{result="error"}[10m]) / rate(vg_tee_attestation_total[10m])) > 0.01` |
| Attestation P99 ≤ 250 ms (real hardware)                    | `histogram_quantile(0.99, sum by (provider, le) (rate(vg_tee_attestation_duration_seconds_bucket[5m]))) > 0.25` |

Adapt thresholds to your deployment's baseline; the suggestions above
target a real-hardware Phase 2 deployment.

## Compatibility

Dashboards are compatible with:

- Grafana 10.0+
- Prometheus 2.40+ (we use `histogram_quantile` and `rate` exclusively;
  no exemplar / native-histogram features that need newer versions)
- Vault Genome `sagvd` v0.0.0+ (the metric names are stable across
  releases — see ADR-0001 for the public-API stability commitment).
