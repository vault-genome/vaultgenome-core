# SPDX-License-Identifier: AGPL-3.0-or-later
"""The destination side: load a restored genome and recompute its fixtures.

`serve` speaks the equivalence gate's external-backend protocol
(internal/validation/reconstruction/external.go) over a genome restored on
disk: one JSON request on stdin, one JSON response on stdout.

    {"fixture_id": "fx-000"}            -> {"dtype":"f32","shape":[k],"raw_b64":"..."}
    {"fixture_ids": ["fx-000", ...]}    -> {"outputs": {"fx-000": {...}, ...}}

`serve_request` is the door the acp-compute worker runs (ADR 0013): the
genome arrives on stdin, in memory, as the authority shipped it — its
description, its adapter and the prompts of its fixtures — and the model
comes back without touching the disk. The base model is public and read
from a local directory that must hash to the genome's manifest.

    {"schema": "vault-genome/door-request/v1", "genome_id": "...",
     "files": {"genome.json": <base64>, "adapter/adapter_config.json": <base64>,
               "adapter/adapter_model.safetensors": <base64>, "prompts.json": <base64>}}
                                        -> {"outputs": {"fx-000": {...}, ...}}

`measure` reports what the gate cannot: whether the restored model *says*
the same things — greedy continuations token for token — and how far its
logits are from the reference.
"""

import base64
import hashlib
import json
import os
import sys
import time

import numpy as np

from . import GENOME_SCHEMA, determinism, fixtures, lora, manifest
from .data import file_digest
from .finetune import load_genome
from .model import greedy, last_logits, load_base, load_with_adapter

DOOR_REQUEST_SCHEMA = "vault-genome/door-request/v1"
PROMPTS_SCHEMA = "vault-genome/door-prompts/v1"


def open_genome(genome_dir: str, base_dir: str, device_name: str):
    """Check everything the genome names — fixtures, adapter, base — then load."""
    g = load_genome(genome_dir)
    fx_path = os.path.join(genome_dir, g["fixtures"]["file"])
    if fixtures.digest(fx_path) != g["fixtures"]["sha256"]:
        raise ValueError("fixtures do not match the genome")
    adapter_dir = os.path.join(genome_dir, g["adapter"]["dir"])
    if file_digest(os.path.join(adapter_dir, lora.ADAPTER_WEIGHTS)) != g["adapter"]["weights_sha256"]:
        raise ValueError("adapter weights do not match the genome")
    manifest.verify(base_dir, g["base"]["manifest"])
    determinism.pin(g["recipe"]["seed"], g["recipe"]["threads"])
    dev = determinism.device(device_name)
    start = time.monotonic()
    model, tokenizer = load_with_adapter(base_dir, adapter_dir, dev)
    return g, fixtures.load(fx_path), model, tokenizer, dev, time.monotonic() - start


def serve(genome_dir: str, base_dir: str, device_name: str, stdin=sys.stdin, stdout=sys.stdout) -> None:
    req = json.loads(stdin.read() or "{}")
    _, fx, model, _, dev, _ = open_genome(genome_dir, base_dir, device_name)
    by_id = {f["id"]: f for f in fx["fixtures"]}
    if "fixture_ids" in req:
        ids = req["fixture_ids"]
        unknown = [i for i in ids if i not in by_id]
        if unknown:
            raise KeyError(f"unknown fixture ids {unknown[:3]}")
        resp = {"outputs": {i: fixtures.tensor_to_wire(fixtures.recompute(model, by_id[i], dev)) for i in ids}}
    else:
        fid = req.get("fixture_id")
        if fid not in by_id:
            raise KeyError(f"unknown fixture id {fid!r}")
        resp = fixtures.tensor_to_wire(fixtures.recompute(model, by_id[fid], dev))
    stdout.write(json.dumps(resp))
    stdout.flush()


def open_genome_files(files: dict, base_dir: str, device_name: str):
    """open_genome for a genome held in memory: files maps the genome's paths
    to their bytes. Checks the adapter against the genome's description and
    the base against its manifest, then loads — nothing is written."""
    if "genome.json" not in files:
        raise ValueError("the request carries no genome.json")
    g = json.loads(files["genome.json"])
    if g.get("schema") != GENOME_SCHEMA:
        raise ValueError(f"genome schema {g.get('schema')!r}, want {GENOME_SCHEMA!r}")
    adapter_dir = g["adapter"]["dir"].rstrip("/")
    weights_path = f"{adapter_dir}/{lora.ADAPTER_WEIGHTS}"
    config_path = f"{adapter_dir}/{lora.ADAPTER_CONFIG}"
    for path in (weights_path, config_path):
        if path not in files:
            raise ValueError(f"the request carries no {path}")
    if "sha256:" + hashlib.sha256(files[weights_path]).hexdigest() != g["adapter"]["weights_sha256"]:
        raise ValueError("adapter weights do not match the genome")
    manifest.verify(base_dir, g["base"]["manifest"])
    determinism.pin(g["recipe"]["seed"], g["recipe"]["threads"])
    dev = determinism.device(device_name)
    start = time.monotonic()
    model, tokenizer = load_base(base_dir)
    lora.load_bytes(model, files[config_path], files[weights_path])
    model.to(dev)
    model.eval()
    return g, model, tokenizer, dev, time.monotonic() - start


def parse_request(raw: str) -> dict:
    """The door request: schema, genome id, and the files as bytes."""
    req = json.loads(raw or "{}")
    if req.get("schema") != DOOR_REQUEST_SCHEMA:
        raise ValueError(f"request schema {req.get('schema')!r}, want {DOOR_REQUEST_SCHEMA!r}")
    if not req.get("genome_id") or not isinstance(req.get("files"), dict) or not req["files"]:
        raise ValueError("request needs genome_id and files")
    return {"genome_id": req["genome_id"], "files": {p: base64.b64decode(b) for p, b in req["files"].items()}}


def parse_prompts(raw: bytes) -> list:
    doc = json.loads(raw)
    if doc.get("schema") != PROMPTS_SCHEMA:
        raise ValueError(f"prompts schema {doc.get('schema')!r}, want {PROMPTS_SCHEMA!r}")
    prompts = doc.get("prompts") or []
    ids = [p["id"] for p in prompts]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("prompt ids must be present and unique")
    for p in prompts:
        if not p.get("input_ids") or not p.get("topk_index"):
            raise ValueError(f"prompt {p['id']!r} needs input_ids and topk_index")
    return prompts


def serve_request(base_dir: str, device_name: str, stdin=sys.stdin, stdout=sys.stdout) -> None:
    """Answer one door request: restore the genome in memory and recompute
    every prompt it carries."""
    req = parse_request(stdin.read())
    files = req["files"]
    if "prompts.json" not in files:
        raise ValueError("the request carries no prompts.json")
    prompts = parse_prompts(files["prompts.json"])
    _, model, _, dev, _ = open_genome_files(files, base_dir, device_name)
    outputs = {p["id"]: fixtures.tensor_to_wire(fixtures.recompute(model, p, dev)) for p in prompts}
    stdout.write(json.dumps({"outputs": outputs}))
    stdout.flush()


def measure(genome_dir: str, base_dir: str, device_name: str) -> dict:
    g, fx, model, tokenizer, dev, load_seconds = open_genome(genome_dir, base_dir, device_name)
    results = []
    start = time.monotonic()
    for f in fx["fixtures"]:
        full = last_logits(model, f["input_ids"], dev)
        got = full[f["topk_index"]].numpy().astype("<f4")
        want = fixtures.wire_to_array(f["expected"])
        diff = np.abs(got.astype(np.float64) - want.astype(np.float64))
        rel = diff / np.maximum(np.abs(want.astype(np.float64)), 1e-30)
        cont = greedy(model, f["input_ids"], len(f["greedy"]["ids"]) or fx["new_tokens"], dev, tokenizer.eos_token_id)
        results.append({
            "id": f["id"],
            "critical": f["critical"],
            "exact": bool(got.tobytes() == want.tobytes()),
            "max_abs_err": float(diff.max()),
            "max_rel_err": float(rel.max()),
            "top1_same": int(full.argmax()) == f["topk_index"][0],
            "greedy_same": cont == f["greedy"]["ids"],
            "greedy_text": tokenizer.decode(cont, skip_special_tokens=False),
        })
    seconds = time.monotonic() - start
    n = len(results)
    return {
        "genome_created_at": g["created_at"],
        "base": g["base"]["name"],
        "device": str(dev),
        "fixtures": n,
        "exact": sum(r["exact"] for r in results),
        "top1_same": sum(r["top1_same"] for r in results),
        "greedy_same": sum(r["greedy_same"] for r in results),
        "max_abs_err": max(r["max_abs_err"] for r in results),
        "max_rel_err": max(r["max_rel_err"] for r in results),
        "load_seconds": round(load_seconds, 3),
        "measure_seconds": round(seconds, 3),
        "runtime": determinism.runtime(),
        "results": results,
    }
