# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The model answers on the machine it lives on (ADR 0041): an answer names
the genome it came from and comes out the same every time; a state that
fails its checks is not served."""

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import pytest

from vg_genome import answer, finetune
from vg_genome.__main__ import main

PROMPT = "the capital of france is"


def _call(port, path, body=None, token=None, raw=None):
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture()
def live(genome_dir, tmp_path):
    """The directory a model lives in: a copy the test may replace."""
    d = str(tmp_path / "live")
    shutil.copytree(genome_dir, d)
    return d


def _put(src, live):
    """Put the genome of src in the model's directory."""
    shutil.rmtree(live)
    shutil.copytree(src, live)


@pytest.fixture()
def listener(live, base_dir):
    said = []
    httpd, answerer = answer.serve(live, base_dir, "cpu", "127.0.0.1:0", token="s3cret", log=said.append)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd.server_address[1], said
    httpd.shutdown()
    httpd.server_close()


def test_an_answer_names_its_genome_and_comes_out_the_same(genome_dir, base_dir):
    g = finetune.load_genome(genome_dir)
    a = answer.Answerer(genome_dir, base_dir)
    first = a.answer(PROMPT, 8)
    again = a.answer(PROMPT, 8)
    assert first["token_ids"] == again["token_ids"] and first["text"] == again["text"]
    assert 1 <= len(first["token_ids"]) <= 8
    assert first["genome"]["adapter_sha256"] == g["adapter"]["weights_sha256"]
    assert first["genome"]["step"] == g["training"]["step"]
    # Another process, opening the genome afresh, says the same.
    assert answer.Answerer(genome_dir, base_dir).answer(PROMPT, 8)["token_ids"] == first["token_ids"]


def test_the_listener_answers_what_the_command_line_answers(listener, live, base_dir):
    port, _ = listener
    status, served = _call(port, "/v1/answer", {"prompt": PROMPT, "max_new_tokens": 8}, token="s3cret")
    assert status == 200, served
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), ".."))
    cmd = [sys.executable, "-m", "vg_genome", "answer", "--genome", live, "--base", base_dir, "--prompt", PROMPT, "--max-new-tokens", "8"]
    once = json.loads(subprocess.run(cmd, capture_output=True, text=True, env=env, check=True).stdout)
    assert served["token_ids"] == once["token_ids"] and served["genome"] == once["genome"]
    status, body = _call(port, "/v1/answer/genome", token="s3cret")
    assert status == 200 and body == {"genome": served["genome"]}


def test_the_answers_wait_without_spinning_unless_told_otherwise(live, base_dir):
    """`answer` sets OpenMP's wait policy before torch loads its runtime, leaves an
    operator's own setting alone, and no other command touches it."""
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), ".."))
    env.pop("OMP_WAIT_POLICY", None)
    cmd = [sys.executable, "-m", "vg_genome", "answer", "--genome", live, "--base", base_dir, "--prompt", PROMPT, "--max-new-tokens", "2"]
    said = subprocess.run(cmd, capture_output=True, text=True, env=env, check=True).stderr
    assert "OMP_WAIT_POLICY=PASSIVE" in said, said
    said = subprocess.run(cmd, capture_output=True, text=True, env=dict(env, OMP_WAIT_POLICY="ACTIVE"), check=True).stderr
    assert "OMP_WAIT_POLICY=ACTIVE" in said, said
    probe = (
        "import os, runpy, sys\n"
        "sys.argv = ['vg_genome', 'verify-base', '--help']\n"
        "try:\n"
        "    runpy.run_module('vg_genome', run_name='__main__')\n"
        "except SystemExit:\n"
        "    pass\n"
        "print('policy', os.environ.get('OMP_WAIT_POLICY'))\n"
    )
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, env=env, check=True).stdout
    assert out.strip().endswith("policy None"), out


def test_the_listener_refuses_what_it_should(listener):
    port, _ = listener
    assert _call(port, "/v1/answer", {"prompt": PROMPT})[0] == 401
    assert _call(port, "/v1/answer", {"prompt": PROMPT}, token="wrong")[0] == 401
    assert _call(port, "/v1/answer/genome")[0] == 401
    assert _call(port, "/v1/elsewhere", {"prompt": PROMPT}, token="s3cret")[0] == 404
    assert _call(port, "/v1/elsewhere", token="s3cret")[0] == 404
    too_long = " ".join(["the"] * 200)  # the tiny model's context is 128 tokens
    for bad in ({"prompt": ""}, {"prompt": "   "}, {"prompt": 7}, {"prompt": too_long}, {"prompt": PROMPT, "max_new_tokens": 0},
                {"prompt": PROMPT, "max_new_tokens": 10_000}, {"prompt": PROMPT, "max_new_tokens": 2.0}, ["a list"]):
        status, body = _call(port, "/v1/answer", bad, token="s3cret")
        assert status == 400 and body["error"], bad
    assert _call(port, "/v1/answer", raw=b"not json", token="s3cret")[0] == 400
    # A body over the limit is refused on its announcement, and not read.
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.putrequest("POST", "/v1/answer")
    conn.putheader("Authorization", "Bearer s3cret")
    conn.putheader("Content-Length", str(answer.MAX_BODY_BYTES + 1))
    conn.endheaders()
    assert conn.getresponse().status == 400
    conn.close()
    status, body = _call(port, "/v1/answer", {"prompt": too_long}, token="s3cret")
    assert "do not fit the model's context of 128" in body["error"]


def test_a_model_that_fails_is_said_to_have_failed_and_the_listener_goes_on(listener, monkeypatch):
    port, said = listener

    def broken(*args, **kwargs):
        raise RuntimeError("out of memory")

    monkeypatch.setattr(answer, "greedy", broken)
    status, body = _call(port, "/v1/answer", {"prompt": PROMPT}, token="s3cret")
    assert status == 500 and body == {"error": "the model failed to answer"}
    assert said[-1] == "answer failed: RuntimeError: out of memory"
    monkeypatch.undo()
    assert _call(port, "/v1/answer", {"prompt": PROMPT, "max_new_tokens": 2}, token="s3cret")[0] == 200


def test_where_the_listener_does_not_start(genome_dir, base_dir, tmp_path):
    with pytest.raises(ValueError, match="needs a token"):
        answer.serve(genome_dir, base_dir, "cpu", "0.0.0.0:0")
    for listen in ("127.0.0.1", ":8090", "[::1]:8090", "127.0.0.1:http", "127.0.0.1:70000"):
        with pytest.raises(ValueError, match="HOST:PORT"):
            answer.serve(genome_dir, base_dir, "cpu", listen, token="s3cret")
    # An address another process holds is refused before anything is loaded.
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        with pytest.raises(RuntimeError, match="cannot listen on 127.0.0.1"):
            answer.serve(genome_dir, base_dir, "cpu", "127.0.0.1:%d" % taken.getsockname()[1])
    # The command line: a token file that holds nothing, and neither or both of the two ways to answer.
    empty = tmp_path / "token"
    empty.write_text("\n")
    common = ["answer", "--genome", genome_dir, "--base", base_dir]
    for args in (["--listen", "127.0.0.1:0", "--token-file", str(empty)], [], ["--prompt", PROMPT, "--listen", "127.0.0.1:0"]):
        with pytest.raises(SystemExit) as stopped:
            main(common + args)
        assert stopped.value.code == 2, args


def test_a_genome_that_fails_its_checks_is_not_opened(live, base_dir, tmp_path):
    other = str(tmp_path / "other-base")
    shutil.copytree(base_dir, other)
    with open(os.path.join(other, "config.json"), "a") as f:
        f.write(" ")
    with pytest.raises(ValueError, match="does not match the genome's manifest"):
        answer.Answerer(live, other)

    weights = os.path.join(live, "adapter", "adapter_model.safetensors")
    with open(weights, "r+b") as f:
        f.seek(-1, os.SEEK_END)
        last = f.read(1)
        f.seek(-1, os.SEEK_END)
        f.write(bytes([last[0] ^ 1]))
    with pytest.raises(ValueError, match="adapter weights do not match"):
        answer.Answerer(live, base_dir)
    # The listener does not start on it either, and does not keep the address it took.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(ValueError, match="adapter weights do not match"):
        answer.serve(live, base_dir, "cpu", f"127.0.0.1:{port}")
    with socket.socket() as again:
        again.bind(("127.0.0.1", port))


def _grow_the_adapter(live):
    with open(os.path.join(live, "adapter", "adapter_model.safetensors"), "ab") as f:
        f.write(b"\0")


def _empty_the_description(live):
    with open(os.path.join(live, "genome.json"), "w") as f:
        f.write("[]")


def test_the_next_state_answers_and_a_broken_one_does_not(genome_dir, live, base_dir, tmp_path):
    g = finetune.load_genome(genome_dir)
    said = []
    a = answer.Answerer(live, base_dir, log=said.append)
    before = a.answer(PROMPT, 8)

    # Training goes on and puts the next genome in the model's directory.
    nxt = str(tmp_path / "next")
    g2 = finetune.continue_training(genome_dir, base_dir, nxt, steps=g["recipe"]["steps"] + 5)
    _put(nxt, live)
    now = a.current()  # before any question: the genome the next answer comes from
    assert now["genome"]["adapter_sha256"] == g2["adapter"]["weights_sha256"] != before["genome"]["adapter_sha256"]
    after = a.answer(PROMPT, 8)
    assert "stale" not in after and after["genome"] == now["genome"]
    assert after["genome"]["step"] == g["recipe"]["steps"] + 5

    # A state that fails its checks is not served: the one before it goes on.
    for spoil, why in ((_grow_the_adapter, "ValueError: adapter weights do not match the genome"), (_empty_the_description, "Error: ")):
        _put(genome_dir, live)
        spoil(live)
        held = a.answer(PROMPT, 8)
        assert held["stale"] is True
        assert held["genome"] == after["genome"] and held["token_ids"] == after["token_ids"]
        assert a.current() == {"genome": after["genome"], "stale": True}
        # The log has the reason; the caller is told only that the answer is not of that state.
        assert said[-1].startswith(f"not serving the state in {live}: ") and why in said[-1], said[-1]

    # Whole again, the state in the directory is opened: it was tried before every answer.
    _put(genome_dir, live)
    back = a.answer(PROMPT, 8)
    assert "stale" not in back
    assert back["genome"] == before["genome"] and back["token_ids"] == before["token_ids"]

    # One line for every genome opened, and one for every state refused — not one for every answer.
    assert [line.split()[0] for line in said] == ["answering", "answering", "not", "not", "answering"], said
