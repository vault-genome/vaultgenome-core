# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The model answers on the machine it lives on (ADR 0041).

A genome directory is opened the way the door opens it — the fixtures and
the adapter against genome.json, the base against the manifest, the recipe's
seed and thread count pinned — and a prompt is continued greedily, with the
arithmetic of the genome's own fixtures. An answer names the genome it came
from: the adapter's SHA-256 and the step training stood at. On one pinned
runtime and one arithmetic the same prompt and the same genome give the same
tokens, so an answer can be recomputed from the sealed generation that holds
that adapter.

    POST /v1/answer          {"prompt": "...", "max_new_tokens": 32}
                             -> {"text", "token_ids", "input_ids", "genome", "seconds"}
    GET  /v1/answer/genome   -> {"genome": {"adapter_sha256", "step", "created_at"}}

When the directory comes to hold another genome — training has put the next
state in its place — it is opened again under the same checks before the
next answer. A state that fails them is not served: the one before it goes
on answering, the answer carries "stale": true, and the log says why. The
directory is tried again before every answer, so a state caught half written
is opened once it is whole.

The listener speaks plain HTTP. Off loopback it does not start without a
token; accounts, limits and TLS for people outside the machine are the
deployment's.
"""

import hashlib
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import door
from .data import prompt_ids
from .model import greedy

DEFAULT_NEW_TOKENS = 32
MAX_NEW_TOKENS = 256
MAX_BODY_BYTES = 64 << 10
LOOPBACK = ("127.0.0.1", "localhost")
SOCKET_TIMEOUT_SECONDS = 60


def _genome_json_digest(genome_dir: str) -> str:
    with open(os.path.join(genome_dir, "genome.json"), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class Answerer:
    """A genome opened for answers. One answer at a time: the model is one.

    log, when given, is called with a line each time a genome is opened and
    each time the state in the directory is found unfit to serve, with the
    reason; a caller is told only that the answer is not of that state.
    """

    def __init__(self, genome_dir: str, base_dir: str, device_name: str = "cpu", log=None):
        self.genome_dir, self.base_dir, self.device_name = genome_dir, base_dir, device_name
        self._log = log or (lambda line: None)
        self._lock = threading.Lock()
        self._refused = None
        self._open()

    def _open(self) -> None:
        # The digest is taken before the open: a genome.json replaced in
        # between is opened again before the next answer, and not missed.
        seen = _genome_json_digest(self.genome_dir)
        g, _, model, tokenizer, dev, _ = door.open_genome(self.genome_dir, self.base_dir, self.device_name)
        training = g.get("training") or {}
        genome = {
            "adapter_sha256": g["adapter"]["weights_sha256"],
            "step": training.get("step", g["recipe"]["steps"]),
            "created_at": g["created_at"],
        }
        context = getattr(getattr(model, "config", None), "max_position_embeddings", None)
        # Everything that can fail is above this line: what follows changes together.
        self._model, self._tokenizer, self._dev, self._seen, self._context = model, tokenizer, dev, seen, context
        self.genome = genome
        self._log(f"answering from adapter {genome['adapter_sha256']}, step {genome['step']}")

    def _refresh(self) -> bool:
        """Open the directory again when it holds another genome. Returns
        whether the state in it is one that is not served."""
        try:
            if _genome_json_digest(self.genome_dir) != self._seen:
                self._open()
            self._refused = None
            return False
        except Exception as e:  # noqa: BLE001 - whatever stops the new state, the one before it goes on answering
            why = f"{type(e).__name__}: {e}"
            if why != self._refused:
                self._refused = why
                self._log(f"not serving the state in {self.genome_dir}: {why}")
            return True

    def current(self) -> dict:
        """The genome the next answer comes from."""
        with self._lock:
            stale = self._refresh()
            out = {"genome": dict(self.genome)}
            if stale:
                out["stale"] = True
            return out

    def answer(self, prompt, max_new_tokens=DEFAULT_NEW_TOKENS) -> dict:
        if not isinstance(prompt, str) or not prompt:
            raise ValueError("prompt must be a non-empty string")
        if isinstance(max_new_tokens, bool) or not isinstance(max_new_tokens, int) or not 1 <= max_new_tokens <= MAX_NEW_TOKENS:
            raise ValueError(f"max_new_tokens must be a whole number from 1 to {MAX_NEW_TOKENS}")
        with self._lock:
            stale = self._refresh()
            start = time.monotonic()
            ids = prompt_ids(self._tokenizer, prompt)
            if self._context and len(ids) + max_new_tokens > self._context:
                raise ValueError(
                    f"the prompt ({len(ids)} tokens) and the answer ({max_new_tokens}) do not fit the model's context of {self._context}"
                )
            out = greedy(self._model, ids, max_new_tokens, self._dev, self._tokenizer.eos_token_id)
            resp = {
                "text": self._tokenizer.decode(out, skip_special_tokens=True),
                "token_ids": out,
                "input_ids": ids,
                "genome": dict(self.genome),
                "seconds": round(time.monotonic() - start, 3),
            }
            if stale:
                resp["stale"] = True
            return resp


def serve(genome_dir: str, base_dir: str, device_name: str, listen: str, token=None, log=None):
    """Bind the listener, then open the genome; the caller runs
    serve_forever. Returns the server and the Answerer. An address that
    cannot be had is refused before the model is loaded."""
    host, _, port = listen.rpartition(":")
    if not host or ":" in host or host.startswith("[") or not port.isdigit() or int(port) > 65535:
        raise ValueError(f"--listen {listen!r} is not HOST:PORT, with an IPv4 address or a name for HOST")
    if host not in LOOPBACK and not token:
        raise ValueError("answer: off loopback the listener needs a token (--token-file)")
    log = log or (lambda line: None)

    class Handler(BaseHTTPRequestHandler):
        timeout = SOCKET_TIMEOUT_SECONDS  # a caller that stops sending does not hold a thread for good

        def log_message(self, format, *args):  # noqa: A002 - the base class's name
            pass

        def version_string(self):
            return "vg-genome"

        def _send(self, status: int, body: dict) -> None:
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _allowed(self) -> bool:
            if not token:
                return True
            got = self.headers.get("Authorization", "")
            return got.startswith("Bearer ") and hmac.compare_digest(got[len("Bearer "):].encode("utf-8"), token.encode("utf-8"))

        def do_GET(self):  # noqa: N802 - the base class's name
            if not self._allowed():
                return self._send(401, {"error": "token missing or invalid"})
            if self.path != "/v1/answer/genome":
                return self._send(404, {"error": "unknown resource"})
            return self._send(200, self.server.answerer.current())

        def _body(self):
            """The body the caller announced, or None when it announced none
            or more than the limit; that much is not read."""
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None
            if not 0 < length <= MAX_BODY_BYTES:
                return None
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ConnectionError("the caller sent less than it announced")
            return raw

        def do_POST(self):  # noqa: N802 - the base class's name
            # The body is read before anything is refused: a caller cut off
            # while it is still sending sees a reset, and not the refusal.
            try:
                raw = self._body()
            except OSError:
                return None  # the caller went away, or stopped, before sending what it announced
            if not self._allowed():
                return self._send(401, {"error": "token missing or invalid"})
            if self.path != "/v1/answer":
                return self._send(404, {"error": "unknown resource"})
            if raw is None:
                return self._send(400, {"error": f"a body of 1 to {MAX_BODY_BYTES} bytes is expected"})
            try:
                req = json.loads(raw)
                if not isinstance(req, dict):
                    raise ValueError("the body must be one JSON object")
                resp = self.server.answerer.answer(req.get("prompt"), req.get("max_new_tokens", DEFAULT_NEW_TOKENS))
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            except Exception as e:  # noqa: BLE001 - the model failed on this request; the listener goes on
                log(f"answer failed: {type(e).__name__}: {e}")
                return self._send(500, {"error": "the model failed to answer"})
            return self._send(200, resp)

    try:
        httpd = ThreadingHTTPServer((host, int(port)), Handler)
    except OSError as e:
        raise RuntimeError(f"answer: cannot listen on {listen}: {e}") from e
    try:
        httpd.answerer = Answerer(genome_dir, base_dir, device_name, log)
    except BaseException:
        httpd.server_close()
        raise
    return httpd, httpd.answerer
