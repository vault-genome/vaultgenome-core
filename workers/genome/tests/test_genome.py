# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys

import numpy as np
import pytest
import torch

from conftest import EXAMPLES, RECIPE
from vg_genome import GENOME_SCHEMA, fixtures, lora, manifest
from vg_genome.door import measure, open_genome, serve
from vg_genome.finetune import finetune, load_genome, replay
from vg_genome.model import last_logits, load_base

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def copy_genome(src, tmp_path):
    dst = str(tmp_path / "copy")
    shutil.copytree(src, dst)
    return dst


def test_finetune_writes_a_genome_that_learned(genome_dir):
    g = load_genome(genome_dir)
    assert g["schema"] == GENOME_SCHEMA
    assert g["base"]["manifest"]["digest"].startswith("sha256:")
    assert {"config.json", "model.safetensors", "tokenizer.json"} <= set(g["base"]["manifest"]["files"])
    losses = g["recipe"]["losses"]
    assert len(losses) == RECIPE["steps"]
    n = len(EXAMPLES)
    assert sum(losses[-n:]) < sum(losses[:n]) / 2, "the adapter learned the examples"
    assert g["fixtures"]["count"] == len(EXAMPLES)
    assert g["fixtures"]["critical"] == RECIPE["critical"]
    for name in ("adapter/adapter_model.safetensors", "adapter/adapter_config.json", "fixtures.json", "data/train.jsonl"):
        assert os.path.isfile(os.path.join(genome_dir, name)), name
    cfg = json.load(open(os.path.join(genome_dir, "adapter/adapter_config.json")))
    assert cfg["peft_type"] == "LORA" and cfg["r"] == RECIPE["rank"] and cfg["target_modules"] == sorted(RECIPE["targets"])


def test_the_same_recipe_yields_the_same_adapter_byte_for_byte(base_dir, data_path, genome_dir, tmp_path):
    again = str(tmp_path / "again")
    finetune(base_dir, data_path, again, **RECIPE)
    for name in ("adapter/adapter_model.safetensors", "fixtures.json"):
        assert sha(os.path.join(genome_dir, name)) == sha(os.path.join(again, name)), name
    assert load_genome(again)["recipe"]["losses"] == load_genome(genome_dir)["recipe"]["losses"]


def test_replay_reproduces_the_sealed_adapter(genome_dir, base_dir):
    r = replay(genome_dir, base_dir)
    assert r["exact"] and r["max_abs_diff"] == 0.0 and r["losses_equal"]


def test_an_untrained_adapter_changes_nothing(base_dir):
    model, tok = load_base(base_dir)
    ids = tok("where does the key go ?", add_special_tokens=False)["input_ids"]
    before = last_logits(model, ids, torch.device("cpu"))
    lora.inject(model, ["q_proj", "v_proj"], 4, 8.0)
    after = last_logits(model, ids, torch.device("cpu"))
    assert torch.equal(before, after)


def test_the_door_reproduces_every_reference_exactly(genome_dir, base_dir):
    fx = fixtures.load(os.path.join(genome_dir, "fixtures.json"))
    ids = [f["id"] for f in fx["fixtures"]]
    out = io.StringIO()
    serve(genome_dir, base_dir, "cpu", stdin=io.StringIO(json.dumps({"fixture_ids": ids})), stdout=out)
    got = json.loads(out.getvalue())["outputs"]
    for f in fx["fixtures"]:
        assert got[f["id"]] == f["expected"], f["id"]

    out = io.StringIO()
    serve(genome_dir, base_dir, "cpu", stdin=io.StringIO(json.dumps({"fixture_id": ids[0]})), stdout=out)
    assert json.loads(out.getvalue()) == fx["fixtures"][0]["expected"]


def test_measure_reports_an_exact_restore(genome_dir, base_dir):
    m = measure(genome_dir, base_dir, "cpu")
    assert m["fixtures"] == m["exact"] == m["top1_same"] == m["greedy_same"] == len(EXAMPLES)
    assert m["max_abs_err"] == 0.0


def test_a_different_base_is_refused(genome_dir, base_dir, tmp_path):
    other = str(tmp_path / "other-base")
    shutil.copytree(base_dir, other)
    with open(os.path.join(other, "config.json"), "a") as f:
        f.write(" ")
    with pytest.raises(ValueError, match="does not match the genome's manifest"):
        manifest.verify(other, load_genome(genome_dir)["base"]["manifest"])
    with pytest.raises(ValueError, match="manifest"):
        open_genome(genome_dir, other, "cpu")


@pytest.mark.parametrize("name", ["adapter/adapter_model.safetensors", "fixtures.json"])
def test_an_edited_genome_is_refused(genome_dir, base_dir, tmp_path, name):
    g = copy_genome(genome_dir, tmp_path)
    path = os.path.join(g, name)
    data = bytearray(open(path, "rb").read())
    data[-2] ^= 0x01
    open(path, "wb").write(bytes(data))
    with pytest.raises(ValueError, match="do not match the genome"):
        open_genome(g, base_dir, "cpu")


def test_the_adapter_must_fit_the_model(genome_dir, base_dir):
    model, _ = load_base(base_dir)
    lora_dir = os.path.join(genome_dir, "adapter")
    cfg = json.load(open(os.path.join(lora_dir, "adapter_config.json")))
    assert cfg["target_modules"]
    model2, _ = load_base(base_dir)
    lora.load(model2, lora_dir)  # fits
    with pytest.raises(ValueError, match="no module"):
        lora.inject(model, ["no_such_proj"], 4, 8.0)


def test_the_cli_door_speaks_the_gate_protocol(genome_dir, base_dir):
    fx = fixtures.load(os.path.join(genome_dir, "fixtures.json"))
    fid = fx["fixtures"][1]["id"]
    res = subprocess.run(
        [sys.executable, "-m", "vg_genome", "door", "--genome", genome_dir, "--base", base_dir],
        input=json.dumps({"fixture_id": fid}), capture_output=True, text=True, cwd=WORKER, timeout=120,
    )
    assert res.returncode == 0, res.stderr
    resp = json.loads(res.stdout)
    assert resp["dtype"] == "f32" and resp["shape"] == [RECIPE["top_k"]]
    assert resp == fx["fixtures"][1]["expected"]

    bad = subprocess.run(
        [sys.executable, "-m", "vg_genome", "door", "--genome", genome_dir, "--base", base_dir],
        input=json.dumps({"fixture_id": "fx-999"}), capture_output=True, text=True, cwd=WORKER, timeout=120,
    )
    assert bad.returncode == 1 and "unknown fixture id" in bad.stdout


def test_wire_format_round_trips():
    t = torch.tensor([1.5, -2.25, 3.0e-7], dtype=torch.float32)
    w = fixtures.tensor_to_wire(t)
    assert w["dtype"] == "f32" and w["shape"] == [3]
    assert np.array_equal(fixtures.wire_to_array(w), t.numpy())
