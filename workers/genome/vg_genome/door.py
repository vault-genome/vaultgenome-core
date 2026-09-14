# SPDX-License-Identifier: AGPL-3.0-or-later
"""The destination side: load a restored genome and recompute its fixtures.

`serve` speaks the equivalence gate's external-backend protocol
(internal/validation/reconstruction/external.go): one JSON request on stdin,
one JSON response on stdout.

    {"fixture_id": "fx-000"}            -> {"dtype":"f32","shape":[k],"raw_b64":"..."}
    {"fixture_ids": ["fx-000", ...]}    -> {"outputs": {"fx-000": {...}, ...}}

`measure` reports what the gate cannot: whether the restored model *says*
the same things — greedy continuations token for token — and how far its
logits are from the reference.
"""

import json
import os
import sys
import time

import numpy as np

from . import determinism, fixtures, lora, manifest
from .data import file_digest
from .finetune import load_genome
from .model import greedy, last_logits, load_with_adapter


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
