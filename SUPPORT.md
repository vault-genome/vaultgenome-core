# Support

Where to take what, so nothing waits in the wrong place.

| You want to… | Go to |
| - | - |
| Run the platform, and it does not do what the documentation says | A [bug report](https://github.com/vault-genome/vaultgenome-core/issues/new?template=bug_report.yml) — with the command, the config (secrets removed) and the daemon's log lines |
| Ask how to deploy, operate or reproduce a measurement | [GitHub Discussions](https://github.com/vault-genome/vaultgenome-core/discussions) — the operator guides under [`docs/operator/`](docs/operator/) answer most of it: [preflight](docs/operator/01_preflight.md), [cross-cloud restore](docs/operator/06_cross_cloud_restore.md), [failover](docs/operator/07_failover.md), and the [real-TEE runbooks](docs/operator/runbooks/) for SEV-SNP, TDX and the Azure confidential GPU |
| Reproduce a claim | Every claim in [`VERIFIABLE-CLAIMS.md`](VERIFIABLE-CLAIMS.md) names its evidence file and its command; the hardware kits under [`scripts/hardware-test/`](scripts/hardware-test/) each carry a README with the cost and the time of a run |
| Propose a change | A [feature request](https://github.com/vault-genome/vaultgenome-core/issues/new?template=feature_request.yml), then a pull request per [`CONTRIBUTING.md`](CONTRIBUTING.md); architecture changes start as an ADR ([`docs/adr/`](docs/adr/)) |
| Report a vulnerability | **Not an issue.** [`SECURITY.md`](SECURITY.md): private advisory or `security@vaultgenome.com` |
| Use the code under terms other than AGPL | [`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md) |

## What to include in a report

- The binary and its version (`sagvd version`, `acpctl version`), the Go
  version, and the platform (`tee.provider`: `gcp-sev-snp`, `gcp-tdx`,
  `azure-cgpu` or `simulated`).
- The exact command and the config file with secrets removed — never a
  seed, a key file, a token or a sealed file's contents.
- The daemon's log lines around the failure (JSON, `log.format: "json"`),
  and for a refused job the `GET /v1/jobs/{id}` record: it names the stage
  and the reason.
- For a handshake refusal, the `TRUST_EVALUATED` event from
  `acpctl audit query`: it carries the reason and, for a confidential GPU
  host, what the verifier checked.

## Response

This is a two-founder project ([`MAINTAINERS.md`](MAINTAINERS.md)). Issues
and discussions are read within a few days; security reports per the
timeline in [`SECURITY.md`](SECURITY.md). There is no paid support tier and
no SLA on the open-source project.
