# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""python -m vg_genome <command>

  finetune     train a LoRA adapter and write a genome directory; with
               --continue GENOME, go on training from that genome's state
  replay       re-run a genome's recipe and compare the adapter it yields
  door         answer one gate request (stdin -> stdout) from a restored genome,
               or, with --stdin-genome, from a genome delivered on stdin; a
               request naming "door": "integer" is answered by the integer door
  measure      recompute every fixture and report fidelity as JSON (--door integer:
               the integer door against its own references and the float ones)
  verify-base  check a base model directory against a genome's manifest
  answer       answer prompts from a genome, each answer naming the genome it
               came from: once (--prompt P), or as a listener (--listen HOST:PORT)
"""

import argparse
import json
import sys

from . import answer, door, finetune, manifest


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# What `finetune` takes when a flag is not given. With --continue none of
# these may be given: the genome says them.
_RECIPE = {
    "steps": 60, "targets": "q_proj,v_proj", "rank": 8, "alpha": 16.0, "lr": 2e-4, "max_len": 128, "seed": 1234,
    "threads": 4, "top_k": 64, "new_tokens": 16, "critical": 4, "device": "cpu", "dtype": "float32",
}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vg_genome", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    ft = sub.add_parser(
        "finetune", help="train a LoRA adapter and write a genome directory, or go on training from one",
        description="Train a LoRA adapter and write a genome directory. With --continue GENOME, go on training "
                    "from that genome's state until --steps steps in all have been taken: the base's name, the "
                    "data, the recipe (hyper-parameters, seed, threads, device, dtype) and the fixtures' prompts "
                    "are the genome's, so no flag that sets one is accepted.")
    ft.add_argument("--base", required=True, help="local directory of the base model")
    ft.add_argument("--out", required=True, help="genome directory to create")
    ft.add_argument("--continue", dest="continue_from", metavar="GENOME",
                    help="go on from this genome directory's training state instead of starting a recipe")
    ft.add_argument("--base-name", help="the base model's name, recorded in the genome")
    ft.add_argument("--data", help="JSONL of {prompt, completion}")
    ft.add_argument("--steps", type=int, help=f"steps to take (default {_RECIPE['steps']}); with --continue, the total to reach")
    ft.add_argument("--targets", help=f"comma-separated module names to adapt (default {_RECIPE['targets']})")
    ft.add_argument("--rank", type=int, help=f"(default {_RECIPE['rank']})")
    ft.add_argument("--alpha", type=float, help=f"(default {_RECIPE['alpha']})")
    ft.add_argument("--lr", type=float, help=f"(default {_RECIPE['lr']})")
    ft.add_argument("--max-len", type=int, help=f"(default {_RECIPE['max_len']})")
    ft.add_argument("--seed", type=int, help=f"(default {_RECIPE['seed']})")
    ft.add_argument("--threads", type=int, help=f"(default {_RECIPE['threads']})")
    ft.add_argument("--prompts", help="JSON list of fixture prompts (default: the training prompts)")
    ft.add_argument("--top-k", type=int, help=f"(default {_RECIPE['top_k']})")
    ft.add_argument("--new-tokens", type=int, help=f"(default {_RECIPE['new_tokens']})")
    ft.add_argument("--critical", type=int, help=f"the first N fixtures are critical (default {_RECIPE['critical']})")
    ft.add_argument("--device", help=f"cpu, cuda, mps or auto: where the adapter trains and the fixtures are recorded (default {_RECIPE['device']})")
    ft.add_argument("--dtype", choices=["float32", "bfloat16", "float16"],
                    help=f"the base model's dtype, recorded in the recipe (the adapter stays float32; default {_RECIPE['dtype']})")
    ft.add_argument("--no-integer-door", action="store_true", help="record no integer-door references in the fixtures")

    rp = sub.add_parser("replay", help="re-run a genome's recipe and compare the adapter")
    rp.add_argument("--genome", required=True)
    rp.add_argument("--base", required=True)
    rp.add_argument("--device", default="cpu", help="cpu, cuda, mps or auto")
    rp.add_argument("--dtype", choices=["float32", "bfloat16", "float16"], help="override the recipe's dtype (a measurement, not the pinned runtime)")

    dr = sub.add_parser("door", help="answer one gate request from a restored genome")
    dr.add_argument("--genome", help="restored genome directory (unless --stdin-genome)")
    dr.add_argument("--stdin-genome", action="store_true",
                    help="the genome arrives on stdin with the request, in memory (the acp-compute worker's door)")
    dr.add_argument("--base", required=True)
    dr.add_argument("--device", default="cpu", help="cpu, cuda, mps or auto")
    dr.add_argument("--dtype", choices=["float32", "bfloat16", "float16"], help="override the recipe's dtype (a measurement, not the pinned runtime)")

    ms = sub.add_parser("measure", help="recompute every fixture and report fidelity")
    ms.add_argument("--genome", required=True)
    ms.add_argument("--base", required=True)
    ms.add_argument("--device", default="cpu")
    ms.add_argument("--dtype", choices=["float32", "bfloat16", "float16"], help="override the recipe's dtype (a measurement, not the pinned runtime)")
    ms.add_argument("--door", choices=["float", "integer"], default="float",
                    help="which door to measure: the model's float kernels, or the integer door against its own references")
    ms.add_argument("--limit", type=int, default=0, help="measure the first N fixtures only (0: all)")

    vb = sub.add_parser("verify-base", help="check a base model directory against a genome's manifest")
    vb.add_argument("--genome", required=True)
    vb.add_argument("--base", required=True)

    an = sub.add_parser("answer", help="answer prompts from a genome: once, or as a listener (ADR 0041)")
    an.add_argument("--genome", required=True, help="the genome directory the model lives in")
    an.add_argument("--base", required=True)
    an.add_argument("--device", default="cpu", help="cpu, cuda, mps or auto")
    an.add_argument("--prompt", help="answer this once, print the answer and exit")
    an.add_argument("--listen", metavar="HOST:PORT", help="serve POST /v1/answer and GET /v1/answer/genome")
    an.add_argument("--token-file", help="the bearer token the listener requires; needed off loopback")
    an.add_argument("--max-new-tokens", type=int, default=answer.DEFAULT_NEW_TOKENS,
                    help=f"for --prompt (default {answer.DEFAULT_NEW_TOKENS}, at most {answer.MAX_NEW_TOKENS})")

    a = p.parse_args(argv)
    if a.cmd == "finetune":
        if a.continue_from:
            theirs = [k for k in ("base_name", "data", "prompts", *_RECIPE) if k != "steps" and getattr(a, k) is not None]
            if a.no_integer_door:
                theirs.append("no_integer_door")
            if theirs:
                p.error("--continue takes these from the genome; drop " + ", ".join("--" + k.replace("_", "-") for k in theirs))
            if a.steps is None:
                p.error("--continue needs --steps: the total number of steps to reach")
            g = finetune.continue_training(a.continue_from, a.base, a.out, steps=a.steps, log=_log)
        else:
            if not a.base_name or not a.data:
                p.error("finetune needs --base-name and --data (or --continue GENOME)")
            for k, v in _RECIPE.items():
                if getattr(a, k) is None:
                    setattr(a, k, v)
            prompts = None
            if a.prompts:
                with open(a.prompts, encoding="utf-8") as f:
                    prompts = json.load(f)
            g = finetune.finetune(
                a.base, a.data, a.out, base_name=a.base_name, targets=[t for t in a.targets.split(",") if t],
                rank=a.rank, alpha=a.alpha, steps=a.steps, lr=a.lr, max_len=a.max_len, seed=a.seed,
                threads=a.threads, prompts=prompts, top_k=a.top_k, new_tokens=a.new_tokens, critical=a.critical,
                device=a.device, dtype=a.dtype, integer_door=not a.no_integer_door, log=_log)
        summary = {k: g[k] for k in ("schema", "created_at")}
        summary.update({
            "base_digest": g["base"]["manifest"]["digest"],
            "adapter_parameters": g["adapter"]["parameters"],
            "adapter_sha256": g["adapter"]["weights_sha256"],
            "device": g["recipe"]["device"],
            "dtype": g["recipe"]["dtype"],
            "step": g["training"]["step"],
            "continued_from": [c["step"] for c in g["training"]["continued_from"]],
            "loss_first": g["recipe"]["losses"][0],
            "loss_last": g["recipe"]["losses"][-1],
            "train_seconds": g["recipe"]["train_seconds"],
            "fixtures": g["fixtures"]["count"],
            "integer_door": (g["fixtures"].get("integer") or {}).get("fidelity"),
        })
        print(json.dumps(summary, indent=2))
    elif a.cmd == "replay":
        print(json.dumps(finetune.replay(a.genome, a.base, device=a.device, dtype=a.dtype, log=_log), indent=2))
    elif a.cmd == "door":
        if a.stdin_genome:
            if a.genome:
                p.error("--stdin-genome takes the genome from stdin; drop --genome")
            door.serve_request(a.base, a.device, dtype=a.dtype)
        elif a.genome:
            door.serve(a.genome, a.base, a.device, dtype=a.dtype)
        else:
            p.error("door needs --genome DIR or --stdin-genome")
    elif a.cmd == "measure":
        print(json.dumps(door.measure(a.genome, a.base, a.device, dtype=a.dtype, door=a.door, limit=a.limit), indent=2))
    elif a.cmd == "answer":
        if bool(a.prompt) == bool(a.listen):
            p.error("answer needs --prompt P or --listen HOST:PORT")
        if a.prompt:
            print(json.dumps(answer.Answerer(a.genome, a.base, a.device).answer(a.prompt, a.max_new_tokens), indent=2))
        else:
            token = None
            if a.token_file:
                with open(a.token_file, encoding="utf-8") as f:
                    token = f.read().strip()
                if not token:
                    p.error(f"answer: {a.token_file} holds no token")
            httpd, _ = answer.serve(a.genome, a.base, a.device, a.listen, token, _log)
            _log("answering on %s:%d" % httpd.server_address[:2])
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                httpd.server_close()
    elif a.cmd == "verify-base":
        g = finetune.load_genome(a.genome)
        manifest.verify(a.base, g["base"]["manifest"])
        print(json.dumps({"ok": True, "digest": g["base"]["manifest"]["digest"]}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, FileExistsError, FileNotFoundError, RuntimeError) as e:
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}), file=sys.stdout)
        sys.exit(1)
