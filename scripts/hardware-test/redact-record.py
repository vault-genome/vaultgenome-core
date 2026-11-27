#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What a record of a hardware run may not name: an account of whoever ran it.

A record of a run on servers is evidence that others read. It names no
account of the workstation the run was made from, nor of the person at it:

  - a macOS home — /Users/<name>/... — is written ~/... (a path a runner
    printed, or a file it listed);
  - the folder an agent worked in on that workstation —
    /private/tmp/claude-<uid>/<project>/<session>/scratchpad — is written
    <scratch>, and a project of its named after a home (-Users-<name>-…)
    is written -Users-~-…;
  - a user that a machine's guest agent makes for a key in the project's
    metadata, or whose keys it updates, is written "(an account of whoever
    runs the kit)": gcloud puts its keys there under the workstation's
    user, and the agent names that user on the machine's serial console;
  - the owner a macOS `ls -l` names, of the group staff or admin, is
    written "(owner)";
  - and, when it redacts on a workstation (--stream, or in place), the
    workstation's own user name (`id -un`), wherever it is left.

Each but the last is told by its form, not by a name: the check holds a
tree to them wherever it runs (scripts/check-records.sh, in CI as well),
and needs to know nobody's name. It does not ask `id -un`: the user of a
machine of CI is no account of a person, and its name may be a word of
the text.

  redact-record.py --stream          stdin to stdout, as a kit keeps a console
  redact-record.py PATH...           files and folders in place; the lines of a
                                     record's sums list (sha256sums.txt and its
                                     kind) for a file changed are written again
  redact-record.py --check PATH...   say which files would change, and fail
"""
import hashlib
import os
import re
import subprocess
import sys

PLACEHOLDER = "(an account of whoever runs the kit)"
SCRATCH = re.compile(r"(?:/private)?/tmp/claude-[0-9]+/[^/\s\"']+/[0-9a-f-]{36}/scratchpad")
SLUG = re.compile(r"-Users-(?!Shared-)[A-Za-z0-9._]+(?=-)")
# A name ends before a full stop that ends the sentence it is in.
HOME = re.compile(r"/Users/(?!Shared(?:/|\b))[A-Za-z0-9._-]*[A-Za-z0-9_-]")
AGENT = re.compile(r"(Creating user|Updating keys for user|Adding user|Removing user) (?!\(an account of whoever runs the kit\))([A-Za-z0-9._-]*[A-Za-z0-9_-])")
OWNER = re.compile(r"([-dlcbps][-rwxsStT]{9}[@+.]?\s+\d+\s+)(?!\(owner\))([A-Za-z0-9._-]+)(\s+(?:staff|admin)\s)")
SUMS = re.compile(r"(sha256sums|SHA256SUMS|\.sha256$|checksums|sums\.txt$)")


def local_name():
    try:
        name = subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""
    # A name of a few letters is a word of the text as much as a name.
    return name if len(name) >= 6 else ""


def redact(text, name):
    text = SCRATCH.sub("<scratch>", text)
    text = HOME.sub("~", text)
    text = SLUG.sub("-Users-~", text)
    text = AGENT.sub(lambda m: m.group(1) + " " + PLACEHOLDER, text)
    text = OWNER.sub(lambda m: m.group(1) + "(owner)" + m.group(3), text)
    if name:
        text = text.replace(name, PLACEHOLDER)
    return text


def is_text(raw):
    return b"\0" not in raw[:8192]


def files_under(paths):
    for p in paths:
        if os.path.isdir(p):
            for d, dirs, names in os.walk(p):
                dirs[:] = sorted(x for x in dirs if x != ".git")
                for n in sorted(names):
                    yield os.path.join(d, n)
        elif os.path.isfile(p):
            yield p


def resum(changed):
    """The lines of each record's sums list naming a file that changed, for
    the file as it is now: the record stays whole by its own list."""
    lists = set()
    for f in changed:
        d = os.path.dirname(os.path.abspath(f))
        while True:
            for n in os.listdir(d):
                p = os.path.join(d, n)
                if os.path.isfile(p) and SUMS.search(n):
                    lists.add(p)
            parent = os.path.dirname(d)
            if parent == d or os.path.exists(os.path.join(d, ".git")):
                break
            d = parent
    done = 0
    wanted = {os.path.abspath(f) for f in changed}
    for p in sorted(lists):
        base = os.path.dirname(p)
        lines = open(p, "rb").read().decode("utf-8", "surrogateescape").split("\n")
        again = False
        for i, line in enumerate(lines):
            parts = line.split()
            if len(parts) < 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                continue
            target = os.path.abspath(os.path.join(base, parts[-1].lstrip("*")))
            if target in wanted:
                now = hashlib.sha256(open(target, "rb").read()).hexdigest()
                if now != parts[0]:
                    lines[i] = line.replace(parts[0], now, 1)
                    again = True
                    done += 1
        if again:
            open(p, "wb").write("\n".join(lines).encode("utf-8", "surrogateescape"))
    return done


def main(argv):
    check = argv[:1] == ["--check"]
    name = "" if check else local_name()
    if argv[:1] == ["--stream"]:
        raw = sys.stdin.buffer.read()
        sys.stdout.buffer.write(redact(raw.decode("utf-8", "surrogateescape"), name).encode("utf-8", "surrogateescape"))
        return 0
    paths = argv[1:] if check else argv
    if not paths:
        print(__doc__.strip().split("\n\n")[-1], file=sys.stderr)
        return 2
    changed = []
    for f in files_under(paths):
        raw = open(f, "rb").read()
        if not is_text(raw):
            continue
        text = raw.decode("utf-8", "surrogateescape")
        out = redact(text, name)
        if out == text:
            continue
        changed.append(f)
        if not check:
            open(f, "wb").write(out.encode("utf-8", "surrogateescape"))
    if check:
        for f in changed:
            print(f)
        return 1 if changed else 0
    lines = resum(changed) if changed else 0
    print("redacted %d file(s); %d line(s) of sums lists written again" % (len(changed), lines), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
