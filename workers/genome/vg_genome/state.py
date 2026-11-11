# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Training state: what a genome carries so that training goes on from it.

The adapter is where training stood. Going on from there, and arriving
where the uninterrupted recipe arrives, takes three more things, kept in
the genome's ``state/`` directory:

* ``optimizer.safetensors`` — AdamW's first and second moments and its step
  count for every adapter tensor, under the adapter's own keys;
* ``cursor.json`` — the step reached, the data it was reached on and the
  example the next step takes;
* ``rng.json`` — the state of every random generator the runtime pins.

genome.json's ``training`` section names each file by its SHA-256, the step
the genome stands at and the genomes it was continued from. On one pinned
runtime, training continued from a genome's state for the remaining steps
yields the adapter the whole recipe yields uninterrupted, byte for byte;
``replay`` is the check, and it needs none of this module.
"""

import base64
import json
import os
import random

import numpy as np
import torch
from safetensors.torch import load_file, save_file

from . import lora
from .data import file_digest

DIR = "state"
OPTIMIZER = "optimizer.safetensors"
CURSOR = "cursor.json"
RNG = "rng.json"
FILES = (CURSOR, OPTIMIZER, RNG)

_MOMENTS = ("exp_avg", "exp_avg_sq")


def optimizer_tensors(model, opt) -> dict:
    """AdamW's state for every adapter tensor — ``<adapter key>/exp_avg``,
    ``/exp_avg_sq`` and ``/step`` — float32, on the CPU."""
    out = {}
    for key, p in lora.named_parameters(model):
        st = opt.state.get(p)
        if not st:
            raise ValueError(f"the optimizer holds no state for {key}: no step was taken")
        for part in _MOMENTS:
            out[f"{key}/{part}"] = st[part].detach().to(torch.float32).contiguous().cpu()
        out[f"{key}/step"] = torch.tensor(float(st["step"]), dtype=torch.float32)
    return out


def restore_optimizer(model, opt, tensors: dict, step: int) -> None:
    """Give a freshly built AdamW over model's adapter the state `tensors`
    hold, through the optimizer's own load_state_dict. Every adapter tensor
    must have its three entries, in the adapter's shapes, at `step`."""
    named = lora.named_parameters(model)
    want = {f"{key}/{part}" for key, _ in named for part in (*_MOMENTS, "step")}
    if set(tensors) != want:
        missing = sorted(want - set(tensors))[:3]
        extra = sorted(set(tensors) - want)[:3]
        raise ValueError(f"the optimizer state does not fit the adapter (missing {missing}, unexpected {extra})")
    doc = opt.state_dict()
    groups = doc["param_groups"]
    if len(groups) != 1 or len(groups[0]["params"]) != len(named):
        raise ValueError("the optimizer does not hold exactly the adapter's tensors")
    restored = {}
    for index, (key, p) in zip(groups[0]["params"], named):
        entry = {}
        for part in _MOMENTS:
            t = tensors[f"{key}/{part}"]
            if t.shape != p.shape or t.dtype != torch.float32:
                raise ValueError(f"the optimizer state's {part} does not fit {key}")
            entry[part] = t.clone()
        at = tensors[f"{key}/step"]
        if at.numel() != 1 or float(at) != float(step):
            raise ValueError(f"the optimizer state of {key} is not at step {step}")
        entry["step"] = torch.tensor(float(step), dtype=torch.float32)
        restored[index] = entry
    doc["state"] = restored
    opt.load_state_dict(doc)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _bytes(t: torch.Tensor) -> bytes:
    return t.cpu().numpy().tobytes()


def _byte_tensor(b64: str) -> torch.Tensor:
    return torch.frombuffer(bytearray(base64.b64decode(b64)), dtype=torch.uint8)


def rng_snapshot(dev: torch.device) -> dict:
    """The state of every generator determinism.pin seeds: Python's,
    numpy's, torch's on the CPU and, when training ran there, torch's on
    the CUDA device."""
    version, internal, gauss_next = random.getstate()
    name, key, pos, has_gauss, cached_gaussian = np.random.get_state()
    snap = {
        "python": {"version": version, "state": list(internal), "gauss_next": gauss_next},
        "numpy": {
            "bit_generator": name,
            "key_b64": _b64(np.asarray(key, dtype="<u4").tobytes()),
            "pos": int(pos),
            "has_gauss": int(has_gauss),
            "cached_gaussian": float(cached_gaussian),
        },
        "torch": {"cpu_b64": _b64(_bytes(torch.get_rng_state()))},
    }
    if dev.type == "cuda":
        snap["torch"]["cuda_b64"] = _b64(_bytes(torch.cuda.get_rng_state(dev)))
    return snap


def rng_restore(snap: dict, dev: torch.device) -> None:
    """Put every generator back where rng_snapshot found it."""
    py, npy, tch = snap["python"], snap["numpy"], snap["torch"]
    random.setstate((py["version"], tuple(py["state"]), py["gauss_next"]))
    np.random.set_state((
        npy["bit_generator"],
        np.frombuffer(base64.b64decode(npy["key_b64"]), dtype="<u4"),
        npy["pos"],
        npy["has_gauss"],
        npy["cached_gaussian"],
    ))
    torch.set_rng_state(_byte_tensor(tch["cpu_b64"]))
    if dev.type == "cuda":
        if "cuda_b64" not in tch:
            raise ValueError("the training state holds no CUDA generator: it was not recorded on a GPU")
        torch.cuda.set_rng_state(_byte_tensor(tch["cuda_b64"]), dev)


def _dump(path: str, doc: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, sort_keys=True)
        f.write("\n")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write(genome_dir: str, model, opt, rng: dict, *, step: int, examples: int, data_sha256: str) -> dict:
    """Write the state directory of a genome that stands at `step`, from
    the optimizer as that step left it and the generators' state then.
    Returns what genome.json says of it: the directory and every file's
    SHA-256."""
    d = os.path.join(genome_dir, DIR)
    os.makedirs(d, exist_ok=True)
    save_file(optimizer_tensors(model, opt), os.path.join(d, OPTIMIZER), metadata={"format": "pt"})
    _dump(os.path.join(d, CURSOR), {
        "step": step,
        "examples": examples,
        "next_example": step % examples,
        "data_sha256": data_sha256,
    })
    _dump(os.path.join(d, RNG), rng)
    return {"dir": DIR, "files": {name: file_digest(os.path.join(d, name)) for name in FILES}}


def read(genome_dir: str, g: dict) -> dict:
    """The training state of the genome in genome_dir (g is its
    genome.json), every file checked against the SHA-256 genome.json names
    and the cursor against the recipe: {"step", "optimizer", "rng"}.

    A genome without the section was made before genomes carried their
    training state: it restores and passes its gate as ever, and cannot be
    continued."""
    t = g.get("training")
    if not t or not t.get("state"):
        raise ValueError("the genome carries no training state (it predates training continuity); it cannot be continued")
    st = t["state"]
    if st.get("dir") != DIR or set(st.get("files", {})) != set(FILES):
        raise ValueError("the genome's training state is not the one this worker writes")
    d = os.path.join(genome_dir, DIR)
    for name in FILES:
        if file_digest(os.path.join(d, name)) != st["files"][name]:
            raise ValueError(f"{DIR}/{name} does not match the genome")
    cursor = _load(os.path.join(d, CURSOR))
    r, step = g["recipe"], t["step"]
    if not (step == r["steps"] == len(r["losses"]) == cursor["step"]):
        raise ValueError("the genome's training state and its recipe disagree on the step reached")
    if (cursor["data_sha256"], cursor["examples"], cursor["next_example"]) != (r["data_sha256"], r["examples"], step % r["examples"]):
        raise ValueError("the genome's cursor is not on its recipe's data")
    return {"step": step, "optimizer": load_file(os.path.join(d, OPTIMIZER)), "rng": _load(os.path.join(d, RNG))}
