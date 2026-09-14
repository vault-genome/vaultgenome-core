# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic LoRA fine-tuning, and replaying a genome's recipe.

The loop is deliberately plain: batch of one, examples in file order,
AdamW, gradient clipping, no dropout (the model stays in eval mode while the
adapter trains), float32 on the CPU. On a pinned runtime the same recipe
yields the same adapter, byte for byte.
"""

import json
import os
import shutil
import time
from datetime import datetime, timezone

import torch

from . import GENOME_SCHEMA, determinism, fixtures, lora, manifest
from .data import encode, file_digest, load_jsonl
from .model import load_base

BETAS = (0.9, 0.999)
EPS = 1e-8
CLIP = 1.0


def _default_prompts(rows: list, limit: int = 16) -> list:
    seen, out = set(), []
    for r in rows:
        if r["prompt"] not in seen:
            seen.add(r["prompt"])
            out.append(r["prompt"])
        if len(out) == limit:
            break
    return out


def train(base_dir: str, rows: list, *, targets: list, rank: int, alpha: float, steps: int, lr: float,
          max_len: int, seed: int, threads: int, device: str = "cpu", log=None):
    """Fine-tune an adapter on rows; returns (model, tokenizer, losses, seconds).
    The model is back on the CPU when it returns."""
    determinism.pin(seed, threads)
    dev = determinism.device(device)
    model, tokenizer = load_base(base_dir)
    examples = [encode(tokenizer, r, max_len) for r in rows]
    lora.inject(model, targets, rank, alpha)
    model.to(dev)
    params = lora.lora_parameters(model)
    opt = torch.optim.AdamW(params, lr=lr, betas=BETAS, eps=EPS, weight_decay=0.0)
    model.eval()  # no dropout: the adapter trains on the model's inference behaviour
    losses = []
    start = time.monotonic()
    for step in range(steps):
        ex = examples[step % len(examples)]
        ids = torch.tensor([ex["input_ids"]], dtype=torch.long, device=dev)
        labels = torch.tensor([ex["labels"]], dtype=torch.long, device=dev)
        with torch.enable_grad():
            loss = model(input_ids=ids, labels=labels, use_cache=False).loss
            opt.zero_grad(set_to_none=True)
            loss.backward()
        torch.nn.utils.clip_grad_norm_(params, CLIP)
        opt.step()
        losses.append(float(loss.detach()))
        if log is not None and (step % 10 == 0 or step == steps - 1):
            log(f"step {step + 1}/{steps} loss {losses[-1]:.4f}")
    seconds = time.monotonic() - start
    model.to(torch.device("cpu"))
    return model, tokenizer, losses, seconds


def finetune(base_dir: str, data_path: str, out_dir: str, *, base_name: str, targets: list, rank: int = 8,
             alpha: float = 16.0, steps: int = 60, lr: float = 2e-4, max_len: int = 128, seed: int = 1234,
             threads: int = 4, prompts=None, top_k: int = 64, new_tokens: int = 16, critical: int = 4,
             log=None) -> dict:
    """Train an adapter and write a genome directory:

    out_dir/genome.json, adapter/, fixtures.json, data/train.jsonl
    """
    if os.path.exists(out_dir) and os.listdir(out_dir):
        raise FileExistsError(f"{out_dir} exists and is not empty")
    base = manifest.build(base_dir)
    rows = load_jsonl(data_path)
    model, tokenizer, losses, seconds = train(
        base_dir, rows, targets=targets, rank=rank, alpha=alpha, steps=steps, lr=lr,
        max_len=max_len, seed=seed, threads=threads, log=log)

    os.makedirs(out_dir, exist_ok=True)
    adapter_dir = os.path.join(out_dir, "adapter")
    lora.save(model, adapter_dir, base_name, targets, rank, alpha)
    os.makedirs(os.path.join(out_dir, "data"), exist_ok=True)
    shutil.copyfile(data_path, os.path.join(out_dir, "data", "train.jsonl"))

    cpu = torch.device("cpu")
    fx = fixtures.build(model, tokenizer, prompts or _default_prompts(rows), cpu, top_k, new_tokens, critical)
    fx_path = os.path.join(out_dir, "fixtures.json")
    with open(fx_path, "w", encoding="utf-8") as f:
        json.dump(fx, f, sort_keys=True)
        f.write("\n")

    genome = {
        "schema": GENOME_SCHEMA,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "base": {"name": base_name, "manifest": base},
        "adapter": {
            "dir": "adapter",
            "format": "peft-lora",
            "r": rank,
            "alpha": alpha,
            "targets": sorted(targets),
            "parameters": sum(p.numel() for p in lora.lora_parameters(model)),
            "weights_sha256": file_digest(os.path.join(adapter_dir, lora.ADAPTER_WEIGHTS)),
        },
        "recipe": {
            "data": "data/train.jsonl",
            "data_sha256": file_digest(data_path),
            "examples": len(rows),
            "steps": steps,
            "lr": lr,
            "max_len": max_len,
            "seed": seed,
            "threads": threads,
            "optimizer": {"name": "adamw", "betas": list(BETAS), "eps": EPS, "weight_decay": 0.0},
            "clip_grad_norm": CLIP,
            "losses": losses,
            "train_seconds": round(seconds, 3),
        },
        "fixtures": {
            "file": "fixtures.json",
            "sha256": fixtures.digest(fx_path),
            "count": len(fx["fixtures"]),
            "critical": min(critical, len(fx["fixtures"])),
            "top_k": top_k,
            "new_tokens": new_tokens,
            "kind": "last-position logits at the reference top-k tokens, float32",
        },
        "runtime": determinism.runtime(),
    }
    with open(os.path.join(out_dir, "genome.json"), "w", encoding="utf-8") as f:
        json.dump(genome, f, indent=2, sort_keys=True)
        f.write("\n")
    return genome


def load_genome(genome_dir: str) -> dict:
    with open(os.path.join(genome_dir, "genome.json"), encoding="utf-8") as f:
        g = json.load(f)
    if g.get("schema") != GENOME_SCHEMA:
        raise ValueError(f"{genome_dir}: schema {g.get('schema')!r}, want {GENOME_SCHEMA!r}")
    return g


def replay(genome_dir: str, base_dir: str, device: str = "cpu", log=None) -> dict:
    """Re-run a genome's recipe on base_dir (on device) and compare the
    adapter it produces with the sealed one, tensor by tensor."""
    g = load_genome(genome_dir)
    manifest.verify(base_dir, g["base"]["manifest"])
    r = g["recipe"]
    data_path = os.path.join(genome_dir, r["data"])
    if file_digest(data_path) != r["data_sha256"]:
        raise ValueError("the genome's training data does not match its recipe")
    model, _, losses, seconds = train(
        base_dir, load_jsonl(data_path), targets=g["adapter"]["targets"], rank=g["adapter"]["r"],
        alpha=g["adapter"]["alpha"], steps=r["steps"], lr=r["lr"], max_len=r["max_len"], seed=r["seed"],
        threads=r["threads"], device=device, log=log)
    from safetensors.torch import load_file

    sealed = load_file(os.path.join(genome_dir, g["adapter"]["dir"], lora.ADAPTER_WEIGHTS))
    replayed = lora.state_dict(model)
    if set(sealed) != set(replayed):
        raise ValueError("replayed adapter has different tensors")
    max_abs, max_rel, exact = 0.0, 0.0, True
    for k in sorted(sealed):
        a, b = sealed[k], replayed[k]
        if not torch.equal(a, b):
            exact = False
            d = (a - b).abs()
            max_abs = max(max_abs, float(d.max()))
            max_rel = max(max_rel, float((d / a.abs().clamp_min(1e-12)).max()))
    loss_diff = max(abs(x - y) for x, y in zip(losses, r["losses"]))
    return {
        "device": device,
        "exact": exact,
        "max_abs_diff": max_abs,
        "max_rel_diff": max_rel,
        "losses_equal": losses == r["losses"],
        "max_loss_diff": loss_diff,
        "final_loss": {"sealed": r["losses"][-1], "replayed": losses[-1]},
        "train_seconds": round(seconds, 3),
        "runtime": determinism.runtime(),
    }
