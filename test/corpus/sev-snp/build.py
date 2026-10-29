#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: Apache-2.0
"""The SEV-SNP corpus of ADR 0034: every genuine attestation report on record
in this tree, each with the VCEK it verifies under and AMD's chain for its
product, in one manifest the differential test walks.

Run from the repository root:

    python3 -I test/corpus/sev-snp/build.py            # fetches missing VCEKs and chains from AMD KDS
    python3 -I test/corpus/sev-snp/build.py --no-fetch # offline: only what is already on disk

Sources, all under scripts/hardware-test: the raw reports the kits kept
(report-vaultgenome.bin, snp-report.bin, snp-attestation-report.bin,
report.bin) and the reports embedded in the restore receipts of the
key-release kits (receipt.json, field "evidence", base64 of the 1184-byte
report). A report's VCEK is taken from beside it when the kit kept one
(vcek.pem, thim-vcek.pem, cert-VCEK.bin, vcek.bin), otherwise from AMD KDS by
the chip id and reported TCB the report names; AMD's ASK+ARK chain per
product comes from KDS. Every report and certificate is copied into this
directory, so that the directory is whole on its own and a tarball of it
is the corpus; the manifest's `source` column says where each report was
kept. `expected.tsv` holds what every verifier must read from each report,
taken from the raw bytes at the specification's offsets. Nothing here is
secret: reports, VCEKs and chains are what a verifier is handed. The
standard library only.

Reports signed by a VLEK (FLAGS.SIGNING_KEY 1; EC2, ADR 0038) are taken
from the aws-sev-snp captures under internal/shared/tee/testdata: the VLEK
beside each report is the one the host's certificate table showed
(vlek.pem, as snpguest read it), never fetched — KDS does not serve
VLEKs — and the chain is the product's VLEK chain (ASVK and ARK,
chains/<product>-vlek.pem, copied from the capture's kds/ directory). The
manifest's `signer` column says vcek or vlek, and the `vcek` column holds
the endorsement key of either kind.
"""
import base64, hashlib, json, os, sys, time, urllib.request, urllib.error

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
OUT = os.path.join(ROOT, "test", "corpus", "sev-snp")
SRC = os.path.join(ROOT, "scripts", "hardware-test")
VLEK_SRC = os.path.join(ROOT, "internal", "shared", "tee", "testdata", "aws-sev-snp")
KDS = "https://kdsintf.amd.com/vcek/v1"
REPORT_LEN = 1184
FILE_NAMES = ("report-vaultgenome.bin", "snp-report.bin", "snp-attestation-report.bin", "report.bin")
VCEK_NAMES = ("vcek.pem", "thim-vcek.pem", "cert-VCEK.bin", "vcek.bin")
PRODUCT_BY_CPUID = {(0x19, 0x01): "Milan", (0x19, 0x11): "Genoa", (0x19, 0xA0): "Genoa"}
PACE_S = 2.0
FETCH = "--no-fetch" not in sys.argv


def meta(raw):
    u32 = lambda o: int.from_bytes(raw[o:o + 4], "little")
    u64 = lambda o: int.from_bytes(raw[o:o + 8], "little")
    fam, model, step = raw[0x188], raw[0x189], raw[0x18A]
    return {
        "version": u32(0x000), "guest_svn": u32(0x004), "policy": u64(0x008),
        "cpuid": (fam, model, step), "reported_tcb": u64(0x180),
        "chip_id": raw[0x1A0:0x1E0].hex(), "measurement": raw[0x090:0x0C0].hex(),
        "signer": {0: "vcek", 1: "vlek"}.get((u32(0x048) >> 2) & 7, "signing-key-%d" % ((u32(0x048) >> 2) & 7)),
    }


def product_of(m, path):
    if m["version"] >= 3:
        fam, model, _ = m["cpuid"]
        if fam == 0x1A:
            return "Turin", "cpuid"
        p = PRODUCT_BY_CPUID.get((fam, model))
        if p:
            return p, "cpuid"
    rel = os.path.relpath(path, SRC)
    kit = rel.split(os.sep)[0]
    return {"azure-cgpu": "Genoa"}.get(kit, "Milan"), "kit"


def cpuid_fms(fam, model, step):
    """CPUID function 1 EAX for a family, model and stepping (extended family and model in the high bits)."""
    base, ext = fam, 0
    if fam >= 0xF:
        base, ext = 0xF, fam - 0xF
    return ext << 20 | (model >> 4) << 16 | base << 8 | (model & 0xF) << 4 | step


def expected_row(cid, raw):
    u32 = lambda o: int.from_bytes(raw[o:o + 4], "little")
    u64 = lambda o: int.from_bytes(raw[o:o + 8], "little")
    fw = lambda o: "%d.%d.%d" % (raw[o + 2], raw[o + 1], raw[o])   # major.minor.build (build, minor, major in the bytes)
    fam, model, step = raw[0x188], raw[0x189], raw[0x18A]
    return [cid, "verifies", u32(0x000), u32(0x004), "%#x" % u64(0x008), "%#x" % u64(0x040), u32(0x030), u32(0x034),
            "%#018x" % u64(0x038), "%#018x" % u64(0x180), "%#018x" % u64(0x1E0), "%#018x" % u64(0x1F0),
            raw[0x090:0x0C0].hex(), raw[0x0C0:0x0E0].hex(), raw[0x050:0x090].hex(), raw[0x1A0:0x1E0].hex(),
            "%#x" % u64(0x1F8), "%#x" % u64(0x200), fw(0x1E8), fw(0x1EC), "%#x" % (cpuid_fms(fam, model, step) if u32(0) >= 3 else 0)]


def corpus_id(path):
    if path.startswith(VLEK_SRC):
        rel = os.path.relpath(path, VLEK_SRC).split(os.sep)   # <stamp>/<host>/<configfs|snpguest>/<report>.bin
        return "aws-sev-snp-" + "-".join([rel[0], rel[1], rel[2], os.path.splitext(rel[3])[0]])
    rel = os.path.relpath(os.path.dirname(path), SRC).split(os.sep)
    parts = [p for p in rel if p not in ("evidence", "keybind-evidence", "live-evidence")]
    if "live-evidence" in rel:
        parts.append("live")
    return "-".join(parts)


def pem_to_der(b):
    if b.startswith(b"-----BEGIN"):
        body = b.split(b"-----BEGIN CERTIFICATE-----")[1].split(b"-----END CERTIFICATE-----")[0]
        return base64.b64decode(b"".join(body.split()))
    return b


def der_to_pem(der):
    b64 = base64.encodebytes(der).replace(b"\n", b"")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(lines) + b"\n-----END CERTIFICATE-----\n"


def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vaultgenome-corpus/1 (+ADR 0034)"})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                wait = int(e.headers.get("Retry-After") or (5 * 2 ** attempt))
                print(f"  KDS {e.code} on {url[-60:]}; waiting {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            raise
    raise RuntimeError(f"KDS gave up on {url}")


def is_report(raw):
    """A raw report: 1184 bytes, VERSION 2..5, SIG_ALGO 1 (ECDSA P-384). The
    demo kits of 2026-10-14/15 kept the ioctl response instead (a 32-byte
    header, the report's tail cut); those are not reports and are skipped."""
    if len(raw) != REPORT_LEN:
        return False
    version = int.from_bytes(raw[0:4], "little")
    sig_algo = int.from_bytes(raw[0x34:0x38], "little")
    return 2 <= version <= 5 and sig_algo == 1


def vlek_sources():
    """The aws-sev-snp captures: every raw report under a capture's host directories
    (configfs/report*.bin, snpguest/report.bin), with the VLEK beside it."""
    if not os.path.isdir(VLEK_SRC):
        return
    for dirpath, _, files in os.walk(VLEK_SRC):
        for f in sorted(files):
            if (f.startswith("report") and f.endswith(".bin")) and os.path.basename(dirpath) in ("configfs", "snpguest"):
                p = os.path.join(dirpath, f)
                raw = open(p, "rb").read()
                if is_report(raw):
                    yield "file", p, raw


def sources():
    for dirpath, _, files in os.walk(SRC):
        for f in sorted(files):
            p = os.path.join(dirpath, f)
            if f in FILE_NAMES:
                raw = open(p, "rb").read()
                if is_report(raw):
                    yield "file", p, raw
                else:
                    print(f"  skipped (not a raw report): {os.path.relpath(p, ROOT)}", file=sys.stderr)
            elif f == "receipt.json":
                try:
                    ev = json.load(open(p)).get("evidence")
                    raw = base64.b64decode(ev) if isinstance(ev, str) else b""
                except (ValueError, json.JSONDecodeError):
                    continue
                if is_report(raw):
                    yield "receipt", p, raw


def main():
    os.makedirs(os.path.join(OUT, "reports"), exist_ok=True)
    os.makedirs(os.path.join(OUT, "vcek"), exist_ok=True)
    os.makedirs(os.path.join(OUT, "chains"), exist_ok=True)
    rows, chains_done, fetched = [], {}, 0
    for kind, path, raw in sorted(list(sources()) + list(vlek_sources()), key=lambda s: s[1]):
        m = meta(raw)
        product, psrc = product_of(m, path)
        cid = corpus_id(path)
        source = os.path.relpath(path, ROOT)
        if m["signer"] == "vlek":
            # A VLEK-signed report (ADR 0038): the VLEK from beside it (the capture's vlek.pem — the
            # certificate table's entry), never from KDS; the chain the product's VLEK chain, copied once.
            host_dir = os.path.dirname(os.path.dirname(path))
            report_rel = os.path.join("reports", cid + ".bin")
            open(os.path.join(OUT, report_rel), "wb").write(raw)
            vlek_pem = os.path.join(host_dir, "snpguest", "certs", "vlek.pem")
            vcek_rel, vsrc = "", ""
            if os.path.exists(vlek_pem):
                der = pem_to_der(open(vlek_pem, "rb").read())
                vcek_rel, vsrc = os.path.join("vcek", cid + ".der"), "capture:" + os.path.relpath(vlek_pem, ROOT)
                open(os.path.join(OUT, vcek_rel), "wb").write(der)
            else:
                print(f"  {cid}: no vlek.pem beside the report", file=sys.stderr)
            key = product + "-vlek"
            if key not in chains_done:
                chain_path = os.path.join(OUT, "chains", key + ".pem")
                src_chain = os.path.join(host_dir, "kds", f"vlek-{product}-cert_chain.pem")
                if not os.path.exists(chain_path) and os.path.exists(src_chain):
                    open(chain_path, "wb").write(open(src_chain, "rb").read())
                    print(f"  chain for {key} copied from the capture", file=sys.stderr)
                chains_done[key] = os.path.join("chains", key + ".pem") if os.path.exists(chain_path) else ""
            rows.append({
                "id": cid, "kind": kind, "product": product, "product_source": psrc, "signer": "vlek",
                "version": m["version"], "cpuid": "%#x/%#x/%#x" % m["cpuid"],
                "reported_tcb": "%#018x" % m["reported_tcb"], "chip_id": m["chip_id"],
                "report": report_rel, "report_sha256": hashlib.sha256(raw).hexdigest(),
                "vcek": vcek_rel, "vcek_source": vsrc, "chain": chains_done[key], "source": source,
                "_raw": raw,
            })
            continue
        # every report lives in the corpus, so that the directory is whole on its own
        report_rel = os.path.join("reports", cid + ".bin")
        open(os.path.join(OUT, report_rel), "wb").write(raw)
        # the VCEK: beside the report (copied in, as DER), or from KDS by chip id and reported TCB
        vcek_rel, vsrc = "", ""
        for name in VCEK_NAMES:
            cand = os.path.join(os.path.dirname(path), name)
            if os.path.exists(cand):
                der = pem_to_der(open(cand, "rb").read())
                vcek_rel, vsrc = os.path.join("vcek", cid + ".der"), "kit:" + os.path.relpath(cand, ROOT)
                open(os.path.join(OUT, vcek_rel), "wb").write(der)
                break
        if not vcek_rel:
            der_name = f"{m['chip_id'][:16]}-{m['reported_tcb']:016x}.der"
            der_path = os.path.join(OUT, "vcek", der_name)
            if not os.path.exists(der_path):
                if not FETCH or product == "Turin":
                    print(f"  {cid}: no VCEK on disk ({'fetch disabled' if not FETCH else 'Turin needs fmcSPL'})", file=sys.stderr)
                else:
                    tcb = m["reported_tcb"]
                    q = f"blSPL={tcb & 0xFF}&teeSPL={(tcb >> 8) & 0xFF}&snpSPL={(tcb >> 48) & 0xFF}&ucodeSPL={(tcb >> 56) & 0xFF}"
                    url = f"{KDS}/{product}/{m['chip_id']}?{q}"
                    time.sleep(PACE_S)
                    try:
                        der = http_get(url)
                    except urllib.error.HTTPError as e:
                        print(f"  {cid}: KDS {e.code} for chip {m['chip_id'][:16]}… tcb {m['reported_tcb']:#x}", file=sys.stderr)
                        der = b""
                    if der:
                        fetched += 1
                        open(der_path, "wb").write(der)
                        print(f"  {cid}: VCEK fetched from KDS ({len(der)} bytes)", file=sys.stderr)
            if os.path.exists(der_path):
                vcek_rel, vsrc = os.path.join("vcek", der_name), "kds"
        # AMD's chain for the product, once
        if product not in chains_done:
            chain_path = os.path.join(OUT, "chains", product + ".pem")
            if not os.path.exists(chain_path) and FETCH:
                time.sleep(PACE_S)
                open(chain_path, "wb").write(http_get(f"{KDS}/{product}/cert_chain"))
                fetched += 1
                print(f"  chain for {product} fetched from KDS", file=sys.stderr)
            chains_done[product] = os.path.join("chains", product + ".pem") if os.path.exists(chain_path) else ""
        rows.append({
            "id": cid, "kind": kind, "product": product, "product_source": psrc, "signer": "vcek",
            "version": m["version"], "cpuid": "%#x/%#x/%#x" % m["cpuid"],
            "reported_tcb": "%#018x" % m["reported_tcb"], "chip_id": m["chip_id"],
            "report": report_rel, "report_sha256": hashlib.sha256(raw).hexdigest(),
            "vcek": vcek_rel, "vcek_source": vsrc, "chain": chains_done[product], "source": source,
            "_raw": raw,
        })
    cols = ["id", "kind", "product", "product_source", "signer", "version", "cpuid", "reported_tcb", "chip_id", "report", "report_sha256", "vcek", "vcek_source", "chain", "source"]
    with open(os.path.join(OUT, "manifest.tsv"), "w") as f:
        f.write("\t".join(cols) + "\n")
        for r in rows:
            f.write("\t".join(str(r[c]) for c in cols) + "\n")
    # expected.tsv: what every verifier must read from each report, taken from
    # the raw bytes at the specification's offsets (AMD 56860, the attestation
    # report), with no verifier involved; the three readings of ADR 0034 agree
    # with these values (C47).
    ecols = ["id", "verdict", "version", "guest_svn", "policy", "platform_info", "vmpl", "signature_algo", "current_tcb", "reported_tcb",
             "committed_tcb", "launch_tcb", "measurement", "host_data", "report_data", "chip_id", "launch_mit_vector", "current_mit_vector",
             "firmware_current", "firmware_committed", "cpuid_fms"]
    with open(os.path.join(OUT, "expected.tsv"), "w") as f:
        f.write("\t".join(ecols) + "\n")
        for r in rows:
            f.write("\t".join(str(x) for x in expected_row(r["id"], r["_raw"])) + "\n")
    # sums over what this directory holds
    sums = []
    for sub in ("manifest.tsv", "expected.tsv", "reports", "vcek", "chains"):
        p = os.path.join(OUT, sub)
        files = [p] if os.path.isfile(p) else [os.path.join(p, x) for x in sorted(os.listdir(p))]
        for fp in files:
            sums.append(f"{hashlib.sha256(open(fp, 'rb').read()).hexdigest()}  {os.path.relpath(fp, OUT)}")
    open(os.path.join(OUT, "SHA256SUMS"), "w").write("\n".join(sums) + "\n")
    chips = len({r["chip_id"] for r in rows if r["signer"] == "vcek"})
    print(f"corpus: {len(rows)} reports ({sum(1 for r in rows if r['kind']=='file')} files, {sum(1 for r in rows if r['kind']=='receipt')} receipts), "
          f"{chips} distinct chips, products {sorted(set(r['product'] for r in rows))}, "
          f"{sum(1 for r in rows if r['vcek'])} with a VCEK ({sum(1 for r in rows if r['vcek_source']=='kds')} from KDS), {fetched} fetched now")
    missing = [r["id"] for r in rows if not r["vcek"] or not r["chain"]]
    if missing:
        print("missing certificates:", ", ".join(missing))
        sys.exit(1)


if __name__ == "__main__":
    main()
