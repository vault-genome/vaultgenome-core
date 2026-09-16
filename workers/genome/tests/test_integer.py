# SPDX-License-Identifier: AGPL-3.0-or-later
"""The integer door: the same bytes on every run, thread count and device
the tests can reach; a tampered adapter changes them; the fixtures carry
the references the door is held to, and the gate protocol serves it."""

import io
import json
import math
import os
import random
import shutil
import subprocess
import sys
from fractions import Fraction

import numpy as np
import pytest
import torch

from vg_genome import fixedmath, fixtures, integer, lora
from vg_genome.door import measure, serve, serve_request
from vg_genome.finetune import load_genome
from vg_genome.model import load_with_adapter

from conftest import EXAMPLES, RECIPE
from test_genome import door_request

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --- fixedmath: integer-derived constants agree with libm to well below
# the fixed point they are rounded to ------------------------------------


def test_constants_match_libm():
    q = 40
    unit = 2.0 ** -q
    assert abs(fixedmath.to_q(fixedmath.pi_fixed(), q) * unit - math.pi) < 1e-11
    assert abs(fixedmath.to_q(fixedmath.ln2_fixed(), q) * unit - math.log(2)) < 1e-11
    for x in (Fraction(10000), Fraction(1000000), Fraction(3, 7)):
        assert abs(fixedmath.to_q(fixedmath.ln_fixed(x), q) * unit - math.log(float(x))) < 1e-11
    for v in (-13.8, -0.3, 0.0, 0.7, 2.5):
        got = fixedmath.to_q(fixedmath.exp_fixed(int(v * (1 << fixedmath.PREC))), q) * unit
        assert abs(got - math.exp(v)) < 1e-11
    for v in (-7.0, -3.14159, -1.0, 0.0, 0.5, 3.0, 100.25):
        c, s = fixedmath.cos_sin_fixed(int(v * (1 << fixedmath.PREC)))
        assert abs(fixedmath.to_q(c, q) * unit - math.cos(v)) < 1e-11
        assert abs(fixedmath.to_q(s, q) * unit - math.sin(v)) < 1e-11
    assert fixedmath.inv_sqrt_q(64, 16) == 1 << 13


def test_rope_tables_match_transformers_formula():
    cos, sin = fixedmath.rope_tables(Fraction(10000), 16, 40, 30)
    inv = 1.0 / (10000 ** (np.arange(0, 16, 2) / 16))
    ang = np.outer(np.arange(40), inv)
    assert np.abs(np.array(cos) / 2**30 - np.cos(ang)).max() < 1e-9
    assert np.abs(np.array(sin) / 2**30 - np.sin(ang)).max() < 1e-9


# --- primitives: exact against Python integers -----------------------------


def test_integer_primitives_agree_with_python_integers():
    rng = random.Random(3)
    a = [rng.randint(-(1 << 61), 1 << 61) for _ in range(500)] + [0, -1, 1, (1 << 62) - 1, -(1 << 62)]
    b = [rng.randint(1, 1 << 40) for _ in range(len(a))]
    ta, tb = torch.tensor(a, dtype=torch.int64), torch.tensor(b, dtype=torch.int64)
    assert integer.serial_floor_div(ta, tb).tolist() == [x // y for x, y in zip(a, b)]
    assert integer.floor_div(ta, tb).tolist() == [x // y for x, y in zip(a, b)]
    for s in (1, 7, 20, 33):
        want = [(x + (1 << (s - 1))) >> s for x in a]
        assert integer.round_shift(ta, s).tolist() == want
        assert integer.round_shift(ta, torch.full_like(ta, s)).tolist() == want
    n = torch.tensor([0, 1, 2, 3, 4, 10**12 + 7, (1 << 50) + 12345, (1 << 58) - 1], dtype=torch.int64)
    assert integer.isqrt(n).tolist() == [math.isqrt(int(v)) for v in n]
    assert integer.bitlen(n).tolist() == [int(v).bit_length() for v in n]
    x = torch.tensor([0, -1, -100, -(1 << 20), -5 * (1 << 24), -(1 << 30), -(1 << 59)], dtype=torch.int64)
    e = integer.iexp(x, 24).tolist()
    for xi, ei in zip(x.tolist(), e):
        assert abs(ei / 2**30 - math.exp(xi / 2**24)) < 2e-7
    sig = integer.isigmoid(torch.tensor([-(1 << 32), -(1 << 30), 0, 1 << 30, 3 << 30], dtype=torch.int64), 30).tolist()
    for v, si in zip((-4.0, -1.0, 0.0, 1.0, 3.0), sig):
        assert abs(si / 2**30 - 1 / (1 + math.exp(-v))) < 2e-7


def test_the_model_kinds_and_shapes_the_door_refuses():
    class Cfg:
        model_type = "gpt2"

    class M:
        config = Cfg()

    with pytest.raises(integer.IntegerDoorError, match="llama and qwen2"):
        integer.IntegerModel(M(), torch.device("cpu"))
    with pytest.raises(integer.IntegerDoorError, match="multiple of 8"):
        integer.QLinear(np.zeros((8, 12), dtype=np.float32), None, torch.device("cpu"))


# --- the tiny model ---------------------------------------------------------


@pytest.fixture(scope="module")
def loaded(genome_dir, base_dir):
    model, tokenizer = load_with_adapter(base_dir, os.path.join(genome_dir, "adapter"), torch.device("cpu"))
    fx = fixtures.load(os.path.join(genome_dir, "fixtures.json"))
    return model, tokenizer, fx


def test_the_genome_records_the_integer_door(genome_dir, loaded):
    _, _, fx = loaded
    g = load_genome(genome_dir)
    assert fx["integer"]["scheme"] == integer.SCHEME
    assert g["fixtures"]["integer"]["scheme"] == integer.SCHEME
    fid = g["fixtures"]["integer"]["fidelity"]
    assert fid["fixtures"] == len(EXAMPLES)
    assert fid["top1_same"] == len(EXAMPLES)  # the integer model says what the float one says
    assert fid["max_abs_err"] < 0.2  # its logits are near, not equal (a different arithmetic)
    for f in fx["fixtures"]:
        assert f["expected_integer"]["dtype"] == "f32"
        assert f["expected_integer"]["shape"] == f["expected"]["shape"]


def test_the_integer_door_reproduces_its_references_byte_for_byte(loaded):
    model, _, fx = loaded
    im = integer.IntegerModel(model, torch.device("cpu"))
    for f in fx["fixtures"]:
        got = fixtures.recompute_integer(im, f)
        assert got.tobytes() == fixtures.wire_to_array(f["expected_integer"]).tobytes(), f["id"]


def test_the_same_bytes_at_another_thread_count_and_on_every_device_here(loaded):
    model, _, fx = loaded
    devices = [torch.device("cpu")]
    if torch.backends.mps.is_available():
        devices.append(torch.device("mps"))
    if torch.cuda.is_available():
        devices.append(torch.device("cuda"))
    engines = [integer.IntegerModel(model, d) for d in devices]
    f = fx["fixtures"][0]
    want = fixtures.wire_to_array(f["expected_integer"]).tobytes()
    threads = torch.get_num_threads()
    try:
        torch.set_num_threads(3)
        assert fixtures.recompute_integer(engines[0], f).tobytes() == want
    finally:
        torch.set_num_threads(threads)
    for im in engines[1:]:
        assert fixtures.recompute_integer(im, f).tobytes() == want, str(im.dev)


def test_a_tampered_adapter_changes_the_bytes(base_dir, genome_dir, loaded):
    _, _, fx = loaded
    model, _ = load_with_adapter(base_dir, os.path.join(genome_dir, "adapter"), torch.device("cpu"))
    with torch.no_grad():
        for m in model.modules():
            if isinstance(m, lora.LoRALayer):
                m.lora_B[0, 0] += 0.05
                break
    im = integer.IntegerModel(model, torch.device("cpu"))
    f = fx["fixtures"][0]
    assert fixtures.recompute_integer(im, f).tobytes() != fixtures.wire_to_array(f["expected_integer"]).tobytes()


def test_the_door_serves_the_integer_door_on_request(genome_dir, base_dir, loaded):
    _, _, fx = loaded
    ids = [f["id"] for f in fx["fixtures"]]
    out = io.StringIO()
    serve(genome_dir, base_dir, "cpu", stdin=io.StringIO(json.dumps({"fixture_ids": ids, "door": "integer"})), stdout=out)
    got = json.loads(out.getvalue())["outputs"]
    for f in fx["fixtures"]:
        assert got[f["id"]] == f["expected_integer"], f["id"]
    out = io.StringIO()
    serve(genome_dir, base_dir, "cpu", stdin=io.StringIO(json.dumps({"fixture_id": ids[0], "door": "integer"})), stdout=out)
    assert json.loads(out.getvalue()) == fx["fixtures"][0]["expected_integer"]
    with pytest.raises(ValueError, match="unknown door"):
        serve(genome_dir, base_dir, "cpu", stdin=io.StringIO(json.dumps({"fixture_id": ids[0], "door": "quantum"})), stdout=io.StringIO())


def test_the_in_memory_door_adds_integer_outputs_when_asked(genome_dir, base_dir, loaded):
    _, _, fx = loaded
    req, _ = door_request(genome_dir)
    prompts = json.loads(__import__("base64").b64decode(req["files"]["prompts.json"]))
    prompts["integer"] = True
    req["files"]["prompts.json"] = __import__("base64").b64encode(json.dumps(prompts).encode()).decode("ascii")
    out = io.StringIO()
    serve_request(base_dir, "cpu", stdin=io.StringIO(json.dumps(req)), stdout=out)
    resp = json.loads(out.getvalue())
    assert set(resp) == {"outputs", "integer_outputs"}
    for f in fx["fixtures"]:
        assert resp["outputs"][f["id"]] == f["expected"]
        assert resp["integer_outputs"][f["id"]] == f["expected_integer"]


def test_measure_reports_the_integer_door(genome_dir, base_dir):
    m = measure(genome_dir, base_dir, "cpu", door="integer")
    assert m["door"] == "integer" and m["scheme"] == integer.SCHEME
    assert m["fixtures"] == m["references"] == m["exact"] == m["top1_same"] == len(EXAMPLES)
    assert m["divides_exactly"] is True
    assert m["max_abs_err"] == m["recorded_fidelity"]["max_abs_err"]


def test_the_cli_measures_the_integer_door(genome_dir, base_dir):
    r = subprocess.run(
        [sys.executable, "-m", "vg_genome", "measure", "--genome", genome_dir, "--base", base_dir, "--door", "integer"],
        capture_output=True, text=True, cwd=WORKER, timeout=300, env=dict(os.environ, PYTHONPATH=WORKER),
    )
    assert r.returncode == 0, r.stderr[-800:]
    assert json.loads(r.stdout)["exact"] == len(EXAMPLES)


def test_a_genome_without_integer_references_still_serves_the_float_door(base_dir, data_path, tmp_path):
    from vg_genome.finetune import finetune

    out = str(tmp_path / "g")
    g = finetune(base_dir, data_path, out, integer_door=False, **RECIPE)
    assert g["fixtures"]["integer"] is None
    fx = fixtures.load(os.path.join(out, "fixtures.json"))
    assert "integer" not in fx and "expected_integer" not in fx["fixtures"][0]
    m = measure(out, base_dir, "cpu", door="integer")
    assert m["references"] == 0 and m["exact"] == 0 and m["top1_same"] == len(EXAMPLES)
    shutil.rmtree(out)
