# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Training goes on from a genome and arrives where the recipe arrives.

The session's genome (conftest.genome_dir) is RECIPE run in one go. Every
test here stops the same recipe part-way, continues it from the genome that
stop left, and holds the result to that one, byte for byte.
"""

import hashlib
import json
import os
import random
import shutil
import subprocess
import sys

import numpy as np
import pytest
import torch
from safetensors.torch import load_file, save_file

from conftest import EXAMPLES, RECIPE
from vg_genome import state
from vg_genome.data import file_digest
from vg_genome.door import measure
from vg_genome.finetune import continue_training, finetune, load_genome, replay

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Everything a genome holds that the recipe decides. genome.json itself is
# compared field by field: it also says when and where it was written.
RECIPE_DECIDES = (
    "adapter/adapter_model.safetensors",
    "adapter/adapter_config.json",
    "fixtures.json",
    "data/train.jsonl",
    "state/optimizer.safetensors",
    "state/cursor.json",
    "state/rng.json",
)

# 25 of 60 steps over six examples: the stop falls inside a pass over the
# data, so the cursor is not at its start.
STOP = 25


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def stopped_at(steps, base_dir, data_path, out, **changes):
    return finetune(base_dir, data_path, str(out), **{**RECIPE, **changes, "steps": steps})


def same_files(a, b):
    for name in RECIPE_DECIDES:
        assert sha(os.path.join(a, name)) == sha(os.path.join(b, name)), name


def rewrite(genome_dir, change):
    """Edit genome.json in place."""
    path = os.path.join(genome_dir, "genome.json")
    with open(path, encoding="utf-8") as f:
        g = json.load(f)
    change(g)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(g, f, indent=2, sort_keys=True)


@pytest.fixture(scope="module")
def stopped(base_dir, data_path, tmp_path_factory):
    out = tmp_path_factory.mktemp("stopped") / "g"
    stopped_at(STOP, base_dir, data_path, out)
    return str(out)


@pytest.fixture(scope="module")
def continued(stopped, base_dir, tmp_path_factory):
    out = str(tmp_path_factory.mktemp("continued") / "g")
    continue_training(stopped, base_dir, out, steps=RECIPE["steps"])
    return out


def test_a_genome_carries_the_state_training_stood_in(genome_dir):
    g = load_genome(genome_dir)
    t = g["training"]
    assert t["step"] == RECIPE["steps"] and t["continued_from"] == []
    assert t["state"]["dir"] == "state" and set(t["state"]["files"]) == set(state.FILES)
    for name, digest in t["state"]["files"].items():
        assert file_digest(os.path.join(genome_dir, "state", name)) == digest, name
    cursor = json.load(open(os.path.join(genome_dir, "state/cursor.json")))
    assert cursor == {"step": RECIPE["steps"], "examples": len(EXAMPLES), "next_example": RECIPE["steps"] % len(EXAMPLES),
                      "data_sha256": g["recipe"]["data_sha256"]}
    opt = load_file(os.path.join(genome_dir, "state/optimizer.safetensors"))
    adapter = load_file(os.path.join(genome_dir, "adapter/adapter_model.safetensors"))
    assert set(opt) == {f"{k}/{part}" for k in adapter for part in ("exp_avg", "exp_avg_sq", "step")}
    for k, w in adapter.items():
        assert opt[f"{k}/exp_avg"].shape == opt[f"{k}/exp_avg_sq"].shape == w.shape
        assert float(opt[f"{k}/step"]) == RECIPE["steps"]


def test_training_continued_from_a_genome_arrives_where_the_recipe_arrives(genome_dir, stopped, continued):
    same_files(continued, genome_dir)
    whole, cont = load_genome(genome_dir), load_genome(continued)
    assert cont["recipe"]["losses"] == whole["recipe"]["losses"]
    for section in ("adapter", "fixtures", "base"):
        assert cont[section] == whole[section], section
    strip = lambda r: {k: v for k, v in r.items() if k != "train_seconds"}  # noqa: E731
    assert strip(cont["recipe"]) == strip(whole["recipe"])
    assert cont["training"]["step"] == whole["training"]["step"] == RECIPE["steps"]
    assert cont["training"]["state"] == whole["training"]["state"]


def test_a_continued_genome_names_the_genome_it_was_continued_from(stopped, continued):
    was, cont = load_genome(stopped), load_genome(continued)
    assert was["training"]["step"] == STOP and len(was["recipe"]["losses"]) == STOP
    assert cont["training"]["continued_from"] == [{
        "step": STOP,
        "adapter_sha256": was["adapter"]["weights_sha256"],
        "created_at": was["created_at"],
        "runtime": was["runtime"],
    }]
    assert cont["recipe"]["losses"][:STOP] == was["recipe"]["losses"]


def test_the_stop_changed_the_adapter(genome_dir, stopped):
    # The test above would hold trivially if the stopped genome were
    # already the whole recipe's.
    assert sha(os.path.join(stopped, "adapter/adapter_model.safetensors")) != sha(os.path.join(genome_dir, "adapter/adapter_model.safetensors"))


def test_replay_holds_a_continued_genome_to_the_whole_recipe(continued, base_dir):
    r = replay(continued, base_dir)
    assert r["exact"] and r["max_abs_diff"] == 0.0 and r["max_rel_l2"] == 0.0 and r["losses_equal"]


def test_a_continued_genome_restores_and_measures_exact(continued, base_dir):
    m = measure(continued, base_dir, "cpu")
    assert m["fixtures"] == m["exact"] == m["top1_same"] == m["greedy_same"] == len(EXAMPLES)
    assert m["max_abs_err"] == 0.0


def test_training_continued_twice_arrives_there_too(genome_dir, base_dir, data_path, tmp_path):
    stopped_at(11, base_dir, data_path, tmp_path / "a")
    continue_training(str(tmp_path / "a"), base_dir, str(tmp_path / "b"), steps=38)
    continue_training(str(tmp_path / "b"), base_dir, str(tmp_path / "c"), steps=RECIPE["steps"])
    same_files(str(tmp_path / "c"), genome_dir)
    g = load_genome(str(tmp_path / "c"))
    assert g["recipe"]["losses"] == load_genome(genome_dir)["recipe"]["losses"]
    assert [c["step"] for c in g["training"]["continued_from"]] == [11, 38]
    assert g["training"]["continued_from"][1]["adapter_sha256"] == load_genome(str(tmp_path / "b"))["adapter"]["weights_sha256"]


def test_a_bfloat16_recipe_continues_exactly(base_dir, data_path, tmp_path):
    stopped_at(RECIPE["steps"], base_dir, data_path, tmp_path / "whole", dtype="bfloat16")
    stopped_at(STOP, base_dir, data_path, tmp_path / "stopped", dtype="bfloat16")
    g = continue_training(str(tmp_path / "stopped"), base_dir, str(tmp_path / "continued"), steps=RECIPE["steps"])
    assert g["recipe"]["dtype"] == "bfloat16"
    same_files(str(tmp_path / "continued"), str(tmp_path / "whole"))


def test_without_the_optimizer_state_training_would_arrive_elsewhere(genome_dir, stopped, base_dir, tmp_path):
    # What the state is for: the same stop, continued with the moments
    # forgotten (zeroed, the hashes rewritten to agree), ends in another
    # adapter. The step count is kept: it alone is not the state.
    forgot = str(tmp_path / "forgot")
    shutil.copytree(stopped, forgot)
    path = os.path.join(forgot, "state/optimizer.safetensors")
    tensors = load_file(path)
    save_file({k: (v if k.endswith("/step") else torch.zeros_like(v)) for k, v in tensors.items()}, path, metadata={"format": "pt"})
    rewrite(forgot, lambda g: g["training"]["state"]["files"].update({"optimizer.safetensors": file_digest(path)}))
    continue_training(forgot, base_dir, str(tmp_path / "out"), steps=RECIPE["steps"])
    assert sha(os.path.join(tmp_path / "out", "adapter/adapter_model.safetensors")) != sha(os.path.join(genome_dir, "adapter/adapter_model.safetensors"))


@pytest.mark.parametrize("name", ["state/optimizer.safetensors", "state/cursor.json", "state/rng.json",
                                  "adapter/adapter_model.safetensors", "fixtures.json", "data/train.jsonl"])
def test_an_edited_genome_is_not_continued(stopped, base_dir, tmp_path, name):
    edited = str(tmp_path / "edited")
    shutil.copytree(stopped, edited)
    with open(os.path.join(edited, name), "ab") as f:
        f.write(b" ")
    with pytest.raises(ValueError, match="does not match|do not match"):
        continue_training(edited, base_dir, str(tmp_path / "out"), steps=RECIPE["steps"])
    assert not os.path.exists(tmp_path / "out")


def test_a_genome_without_training_state_is_not_continued_and_still_restores(stopped, base_dir, tmp_path):
    old = str(tmp_path / "old")
    shutil.copytree(stopped, old)
    shutil.rmtree(os.path.join(old, "state"))
    rewrite(old, lambda g: g.pop("training"))
    with pytest.raises(ValueError, match="carries no training state"):
        continue_training(old, base_dir, str(tmp_path / "out"), steps=RECIPE["steps"])
    m = measure(old, base_dir, "cpu")
    assert m["fixtures"] == m["exact"] == len(EXAMPLES)


def test_a_state_that_disagrees_with_the_recipe_is_refused(stopped, base_dir, tmp_path):
    # Hashes that agree are not enough: the cursor must be where the recipe
    # says training stands, and the optimizer at that step.
    moved = str(tmp_path / "moved")
    shutil.copytree(stopped, moved)
    path = os.path.join(moved, "state/cursor.json")
    cursor = json.load(open(path))
    cursor["step"] += 1
    with open(path, "w") as f:
        json.dump(cursor, f, sort_keys=True)
    rewrite(moved, lambda g: g["training"]["state"]["files"].update({"cursor.json": file_digest(path)}))
    with pytest.raises(ValueError, match="disagree on the step reached"):
        continue_training(moved, base_dir, str(tmp_path / "out1"), steps=RECIPE["steps"])

    behind = str(tmp_path / "behind")
    shutil.copytree(stopped, behind)
    path = os.path.join(behind, "state/optimizer.safetensors")
    tensors = load_file(path)
    save_file({k: (v - 1 if k.endswith("/step") else v) for k, v in tensors.items()}, path, metadata={"format": "pt"})
    rewrite(behind, lambda g: g["training"]["state"]["files"].update({"optimizer.safetensors": file_digest(path)}))
    with pytest.raises(ValueError, match=f"is not at step {STOP}"):
        continue_training(behind, base_dir, str(tmp_path / "out2"), steps=RECIPE["steps"])

    other = str(tmp_path / "other")
    shutil.copytree(stopped, other)
    path = os.path.join(other, "state/optimizer.safetensors")
    tensors = load_file(path)
    tensors.pop(sorted(tensors)[0])
    save_file(tensors, path, metadata={"format": "pt"})
    rewrite(other, lambda g: g["training"]["state"]["files"].update({"optimizer.safetensors": file_digest(path)}))
    with pytest.raises(ValueError, match="does not fit the adapter"):
        continue_training(other, base_dir, str(tmp_path / "out3"), steps=RECIPE["steps"])


def test_the_total_must_be_beyond_the_step_reached(stopped, base_dir, tmp_path):
    for steps in (STOP, STOP - 1):
        with pytest.raises(ValueError, match=f"stands at step {STOP}"):
            continue_training(stopped, base_dir, str(tmp_path / "out"), steps=steps)


def test_a_different_base_is_not_continued_on(stopped, base_dir, tmp_path):
    other = str(tmp_path / "base")
    shutil.copytree(base_dir, other)
    with open(os.path.join(other, "config.json"), "a") as f:
        f.write(" ")
    with pytest.raises(ValueError, match="does not match the genome's manifest"):
        continue_training(stopped, other, str(tmp_path / "out"), steps=RECIPE["steps"])


def test_the_generators_go_back_where_they_stood():
    dev = torch.device("cpu")
    random.seed(3), np.random.seed(3), torch.manual_seed(3)
    random.random(), np.random.rand(2), torch.rand(2)
    snap = json.loads(json.dumps(state.rng_snapshot(dev)))  # as rng.json holds it
    first = (random.random(), np.random.rand(3).tolist(), np.random.standard_normal(), torch.rand(3).tolist(), torch.randn(2).tolist())
    random.seed(9), np.random.seed(9), torch.manual_seed(9)
    state.rng_restore(snap, dev)
    again = (random.random(), np.random.rand(3).tolist(), np.random.standard_normal(), torch.rand(3).tolist(), torch.randn(2).tolist())
    assert first == again


def test_the_cli_continues_a_genome(genome_dir, stopped, base_dir, tmp_path):
    env = dict(os.environ, PYTHONPATH=WORKER, TOKENIZERS_PARALLELISM="false")
    out = str(tmp_path / "out")
    cmd = [sys.executable, "-m", "vg_genome", "finetune", "--continue", stopped, "--base", base_dir, "--out", out]
    p = subprocess.run(cmd + ["--steps", str(RECIPE["steps"])], capture_output=True, text=True, env=env, check=True)
    summary = json.loads(p.stdout)
    assert summary["step"] == RECIPE["steps"] and summary["continued_from"] == [STOP]
    assert summary["adapter_sha256"] == load_genome(genome_dir)["adapter"]["weights_sha256"]
    same_files(out, genome_dir)

    # The recipe is the genome's: a flag that would set part of it is refused.
    for extra, said in ((["--steps", "60", "--lr", "0.5"], "drop --lr"),
                        (["--steps", "60", "--data", "x.jsonl", "--seed", "1"], "drop --data, --seed"),
                        (["--steps", "60", "--no-integer-door"], "drop --no-integer-door"),
                        ([], "--continue needs --steps")):
        p = subprocess.run(cmd[:-1] + [str(tmp_path / "never")] + extra, capture_output=True, text=True, env=env)
        assert p.returncode == 2 and said in p.stderr, p.stderr
    assert not os.path.exists(tmp_path / "never")
