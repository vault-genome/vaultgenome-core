# vaultgenome

The Python side of [Vault Genome](https://github.com/vault-genome/vaultgenome-core),
open-source software that keeps fine-tuned AI models in service on attested
confidential-computing hardware. The authority, the destination daemons and
`acpctl` are Go programs, released signed for every platform on the
repository's [releases page](https://github.com/vault-genome/vaultgenome-core/releases);
this distribution carries the two Python parts, each from where it lives in
the repository.

| Install | What you get |
| - | - |
| `pip install vaultgenome` | `vaultgenome-audit` — the auditor's own verifier of the audit log. The standard library only, no dependencies: it reads a daemon's audit file as bytes, replays the hash chain the way the product does and checks every signature under the published audit key. [`tools/auditor/verify_audit.py`](https://github.com/vault-genome/vaultgenome-core/tree/main/tools/auditor) in the repository is the same file. |
| `pip install "vaultgenome[genome]"` | `vg-genome` (also `python -m vg_genome`) — the model side of a genome: deterministic LoRA fine-tuning, the base model named by the hash of its files, the reference fixtures, the replay of the recipe and the door the equivalence gate runs ([`workers/genome`](https://github.com/vault-genome/vaultgenome-core/tree/main/workers/genome)). The extra pins the runtime the worker's records were made on: torch 2.14.1, transformers 5.19.0, tokenizers 0.23.3, safetensors 0.8.0, numpy 2.5.4. |

```bash
pip install vaultgenome
vaultgenome-audit --audit xcc-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-demo
```

Exit 0 when every event links and verifies, with the count and the tip; 1
otherwise, naming the first event that does not. On a machine without a
GPU, take torch from the CPU index first, then the extra:

```bash
pip install --index-url https://download.pytorch.org/whl/cpu torch==2.14.1
pip install "vaultgenome[genome]"
vg-genome finetune --base BASE_DIR --base-name Qwen/Qwen2.5-0.5B-Instruct \
    --data drill-facts.jsonl --prompts drill-prompts.json --out genome/
vg-genome replay --genome genome/ --base BASE_DIR     # the recipe gives the same adapter, byte for byte
```

Byte-for-byte replay holds on the pinned runtime; `vg-genome measure` on
another runtime says how far a measurement is from the references.

## What a version here is

Each version is built from the signed tag of the repository, twice, and
the two builds compared. The wheel and the sdist are release assets beside
the binaries — each with a keyless Sigstore signature, an SBOM and a SLSA
provenance, and in the release's signed `checksums-<tag>.txt` — and they
are published to PyPI by the release workflow under its own identity, with
no stored token. To check a file from PyPI against the release:
`sha256sum vaultgenome-<version>-py3-none-any.whl` equals its line in
`checksums-v<version>.txt`, and `cosign verify-blob` takes the wheel's
`.sigstore.json` from the same page.

Python 3.12 is what the tests run on. The code is AGPL-3.0-or-later; a
commercial licence is available from The Capital Index LLC
([COMMERCIAL-LICENSE.md](https://github.com/vault-genome/vaultgenome-core/blob/main/COMMERCIAL-LICENSE.md)).

[Repository](https://github.com/vault-genome/vaultgenome-core) ·
[VERIFIABLE-CLAIMS](https://github.com/vault-genome/vaultgenome-core/blob/main/VERIFIABLE-CLAIMS.md) ·
[CHANGELOG](https://github.com/vault-genome/vaultgenome-core/blob/main/CHANGELOG.md) ·
[security policy](https://github.com/vault-genome/vaultgenome-core/blob/main/SECURITY.md)
