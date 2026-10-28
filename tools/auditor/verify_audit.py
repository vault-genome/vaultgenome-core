#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""An auditor's own verifier of the audit log (ADR 0034, part three).

It reads the daemon's audit file as bytes — bbolt pages, no library — and
replays the chain the way the product's `acpctl audit verify` does, with
nothing of the product: every event's canonical JSON re-encoded as the Go
side encodes it, SHA-256 over it, the link to the previous event's hash
from the genesis (32 zero bytes, or where a continued segment says it
starts), and the signature over the hash under the audit public key the
daemon's `identity` printed. The standard library only; the elliptic
curves are written out here (Ed25519 after RFC 8032, ECDSA P-384 after
SEC 1), slowly and plainly, so that an auditor can read what is checked.

    python3 -I verify_audit.py --audit xcc-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-demo [--json]

Exit 0 when every event links and verifies; 1 otherwise, with the first
failure named. ML-DSA-87 (`alg: ml-dsa-87`) is not implemented here: a
log signed under it is reported as unverified by this tool, not as broken.
"""
import argparse, base64, hashlib, json, struct, sys

# ---- bbolt ------------------------------------------------------------------
# A bbolt file is pages of one size; pages 0 and 1 are meta pages (the one
# with the higher txid is current); a bucket is a B+tree of branch and
# leaf pages, or a page inlined into its parent's value when small.

META_MAGIC = 0xED0CDAED
PAGE_BRANCH, PAGE_LEAF, PAGE_META = 0x01, 0x02, 0x04
BUCKET_LEAF_FLAG = 0x01


class Bolt:
    def __init__(self, data):
        self.data = data
        metas = []
        for pg in (0, 1):
            magic, version, page_size, _flags = struct.unpack_from("<IIII", data, pg * 4096 + 16)
            if magic != META_MAGIC:
                continue
            root_pgid, _root_seq, _freelist, _pgid, txid = struct.unpack_from("<QQQQQ", data, pg * 4096 + 32)
            metas.append((txid, page_size, root_pgid))
        if not metas:
            raise ValueError("not a bbolt file: no meta page with the magic")
        txid, self.page_size, self.root_pgid = max(metas)
        # a page size other than 4096 moves the second meta page; re-read it there
        if self.page_size != 4096:
            magic, _v, ps, _f = struct.unpack_from("<IIII", data, self.page_size + 16)
            if magic == META_MAGIC and ps == self.page_size:
                root_pgid, _s, _fl, _p, txid2 = struct.unpack_from("<QQQQQ", data, self.page_size + 32)
                if txid2 > txid:
                    self.root_pgid = root_pgid

    def page(self, pgid):
        off = pgid * self.page_size
        _id, flags, count, overflow = struct.unpack_from("<QHHI", self.data, off)
        return flags, count, self.data[off:off + (overflow + 1) * self.page_size]

    def _items(self, flags, count, page):
        """(key, value, elem_flags) of a leaf page, or child pgids of a branch page, in order."""
        if flags & PAGE_LEAF:
            out = []
            for i in range(count):
                base = 16 + i * 16
                eflags, pos, ksize, vsize = struct.unpack_from("<IIII", page, base)
                k = page[base + pos:base + pos + ksize]
                v = page[base + pos + ksize:base + pos + ksize + vsize]
                out.append((k, v, eflags))
            return out
        if flags & PAGE_BRANCH:
            out = []
            for i in range(count):
                base = 16 + i * 16
                _pos, _ksize, pgid = struct.unpack_from("<IIQ", page, base)
                out.append(pgid)
            return out
        raise ValueError("unexpected page flags %#x" % flags)

    def walk(self, pgid):
        """Every (key, value, flags) under a B+tree root, in key order."""
        flags, count, page = self.page(pgid)
        if flags & PAGE_LEAF:
            return self._items(flags, count, page)
        out = []
        for child in self._items(flags, count, page):
            out.extend(self.walk(child))
        return out

    def walk_inline(self, value):
        _root, _seq = struct.unpack_from("<QQ", value, 0)
        page = value[16:]
        _id, flags, count, _overflow = struct.unpack_from("<QHHI", page, 0)
        return self._items(flags, count, page)

    def bucket(self, name):
        """The (key, value) pairs of a top-level bucket, in key order; None if absent."""
        for k, v, eflags in self.walk(self.root_pgid):
            if k == name and eflags & BUCKET_LEAF_FLAG:
                root, _seq = struct.unpack_from("<QQ", v, 0)
                items = self.walk(root) if root != 0 else self.walk_inline(v)
                return [(ik, iv) for ik, iv, _f in items]
        return None


# ---- canonical JSON, as the product encodes it ------------------------------
# Keys sorted bytewise, no spaces, strings escaped as Go's encoding/json
# escapes them (HTML-safe: < > & become \u003c \u003e \u0026; U+2028 and
# U+2029 escaped), integers as their digits.

def go_string(s):
    out = json.dumps(s, ensure_ascii=False)
    return out.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def canonical(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        raise ValueError("a float in an audit event is not expected")
    if isinstance(v, str):
        return go_string(v)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(go_string(k) + ":" + canonical(v[k]) for k in sorted(v, key=lambda k: k.encode())) + "}"
    raise ValueError("unexpected value %r" % type(v))


# ---- DER / PEM (just enough for a PKIX public key) --------------------------

def pem_to_der(text):
    body = text.split("-----BEGIN PUBLIC KEY-----")[1].split("-----END PUBLIC KEY-----")[0]
    return base64.b64decode("".join(body.split()))


def der_tlv(b, i=0):
    tag = b[i]
    n = b[i + 1]
    if n & 0x80:
        ln = n & 0x7F
        length = int.from_bytes(b[i + 2:i + 2 + ln], "big")
        start = i + 2 + ln
    else:
        length, start = n, i + 2
    return tag, b[start:start + length], start + length


OID_ED25519 = bytes.fromhex("2b6570")           # 1.3.101.112
OID_EC_PUBLIC_KEY = bytes.fromhex("2a8648ce3d0201")  # 1.2.840.10045.2.1
OID_SECP384R1 = bytes.fromhex("2b81040022")     # 1.3.132.0.34


def parse_pkix(der):
    tag, spki, _ = der_tlv(der)
    assert tag == 0x30
    tag, alg, nxt = der_tlv(spki)
    assert tag == 0x30
    tag, oid, nxt2 = der_tlv(alg)
    assert tag == 0x06
    params = None
    if nxt2 < len(alg):
        ptag, params, _ = der_tlv(alg, nxt2)
    tag, bits, _ = der_tlv(spki, nxt)
    assert tag == 0x03 and bits[0] == 0
    key = bits[1:]
    if oid == OID_ED25519:
        return "ed25519", key
    if oid == OID_EC_PUBLIC_KEY and params == OID_SECP384R1:
        assert key[0] == 4 and len(key) == 97
        return "ecdsa-p384-sha384", (int.from_bytes(key[1:49], "big"), int.from_bytes(key[49:], "big"))
    raise ValueError("unsupported public key algorithm")


# ---- Ed25519 (RFC 8032) -----------------------------------------------------

ED_P = 2 ** 255 - 19
ED_Q = 2 ** 252 + 27742317777372353535851937790883648493


def ed_inv(x):
    return pow(x, ED_P - 2, ED_P)


ED_D = -121665 * ed_inv(121666) % ED_P
ED_SQRT_M1 = pow(2, (ED_P - 1) // 4, ED_P)


def ed_add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % ED_P
    B = (Y1 + X1) * (Y2 + X2) % ED_P
    C = 2 * T1 * T2 * ED_D % ED_P
    D = 2 * Z1 * Z2 % ED_P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % ED_P, G * H % ED_P, F * G % ED_P, E * H % ED_P)


def ed_mul(P, e):
    Q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            Q = ed_add(Q, P)
        P = ed_add(P, P)
        e >>= 1
    return Q


def ed_equal(P, Q):
    X1, Y1, Z1, _ = P
    X2, Y2, Z2, _ = Q
    return (X1 * Z2 - X2 * Z1) % ED_P == 0 and (Y1 * Z2 - Y2 * Z1) % ED_P == 0


def ed_decode(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= ED_P:
        return None
    x2 = (y * y - 1) * ed_inv(ED_D * y * y + 1) % ED_P
    if x2 == 0:
        if sign:
            return None
        x = 0
    else:
        x = pow(x2, (ED_P + 3) // 8, ED_P)
        if (x * x - x2) % ED_P != 0:
            x = x * ED_SQRT_M1 % ED_P
        if (x * x - x2) % ED_P != 0:
            return None
        if (x & 1) != sign:
            x = ED_P - x
    return (x, y, 1, x * y % ED_P)


ED_G = ed_decode(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))


def ed25519_verify(pub, msg, sig):
    if len(sig) != 64:
        return False
    A = ed_decode(pub)
    R = ed_decode(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if A is None or R is None or s >= ED_Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % ED_Q
    return ed_equal(ed_mul(ED_G, s), ed_add(R, ed_mul(A, h)))


# ---- ECDSA P-384 (SEC 1), signature r||s, digest SHA-384 --------------------

P384_P = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)
P384_A = P384_P - 3
P384_B = int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)
P384_N = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
P384_G = (int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
          int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16))


def p_inv(x):
    return pow(x, P384_P - 2, P384_P)


def p_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % P384_P == 0:
            return None
        lam = (3 * x1 * x1 + P384_A) * p_inv(2 * y1) % P384_P
    else:
        lam = (y2 - y1) * p_inv(x2 - x1) % P384_P
    x3 = (lam * lam - x1 - x2) % P384_P
    return (x3, (lam * (x1 - x3) - y1) % P384_P)


def p_mul(P, e):
    Q = None
    while e > 0:
        if e & 1:
            Q = p_add(Q, P)
        P = p_add(P, P)
        e >>= 1
    return Q


def on_curve(P):
    x, y = P
    return (y * y - (x * x * x + P384_A * x + P384_B)) % P384_P == 0


def ecdsa_p384_verify(pub, msg, sig):
    if len(sig) != 96 or not on_curve(pub):
        return False
    r = int.from_bytes(sig[:48], "big")
    s = int.from_bytes(sig[48:], "big")
    if not (0 < r < P384_N and 0 < s < P384_N):
        return False
    e = int.from_bytes(hashlib.sha384(msg).digest(), "big")
    w = pow(s, P384_N - 2, P384_N)
    X = p_add(p_mul(P384_G, e * w % P384_N), p_mul(pub, r * w % P384_N))
    return X is not None and X[0] % P384_N == r


# ---- the chain --------------------------------------------------------------

def verify(audit_path, pubkey_pem, kid):
    result = {"ok": False, "audit_path": audit_path, "suite": None, "events": 0, "tip": None, "kid": kid, "errors": []}
    try:
        data = open(audit_path, "rb").read()
        db = Bolt(data)
    except (OSError, ValueError, struct.error) as e:
        result["errors"].append("audit file: %s" % e)
        return result
    try:
        suite, pub = parse_pkix(pem_to_der(open(pubkey_pem).read()))
    except (OSError, ValueError, AssertionError, IndexError) as e:
        # A key this tool cannot read — ML-DSA-87 among them — is reported
        # as not implemented here, not as a broken log.
        result["errors"].append("public key: not implemented in this tool (%s)" % (e or "unsupported algorithm"))
        return result
    result["suite"] = suite
    items = db.bucket(b"audit_events")
    if items is None:
        result["errors"].append("no audit_events bucket")
        return result
    expected_prev = bytes(32)
    start = db.bucket(b"segment")
    if start:
        for k, v in start:
            if k == b"start":
                rec = json.loads(v)
                result["segment_start"] = rec
                expected_prev = bytes.fromhex(rec.get("prev_tip_hex") or "00" * 32)   # SegmentStart.prev_tip_hex (ADR 0027)
    last_hash = expected_prev
    for i, (key, raw) in enumerate(items):
        if len(key) != 8:
            result["errors"].append("event #%d: key is not an 8-byte sequence" % i)
            return result
        try:
            evt = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            result["errors"].append("event #%d: not JSON: %s" % (i, e))
            return result
        prev = base64.b64decode(evt.get("prev_hash") or "")
        if prev != expected_prev:
            result["errors"].append("event #%d (%s): prev_hash does not link to the previous event" % (i, evt.get("event_id")))
            return result
        cover = dict(evt)
        cover["hash"] = None
        cover["signature"] = None
        h = hashlib.sha256(canonical(cover).encode("utf-8")).digest()
        if base64.b64decode(evt.get("hash") or "") != h:
            result["errors"].append("event #%d (%s): hash does not match the canonical bytes" % (i, evt.get("event_id")))
            return result
        if evt.get("signing_key_id") != kid:
            result["errors"].append("event #%d: signed under %r, not %r" % (i, evt.get("signing_key_id"), kid))
            return result
        alg = evt.get("alg") or "ed25519"   # absent on records before ADR 0031: Ed25519
        if alg != suite:
            result["errors"].append("event #%d: alg %s but the public key is %s" % (i, alg, suite))
            return result
        sig = base64.b64decode(evt.get("signature") or "")
        if suite == "ed25519":
            ok = ed25519_verify(pub, h, sig)
        elif suite == "ecdsa-p384-sha384":
            ok = ecdsa_p384_verify(pub, h, sig)
        else:
            result["errors"].append("event #%d: %s is not implemented in this tool" % (i, suite))
            return result
        if not ok:
            result["errors"].append("event #%d (%s): signature does not verify" % (i, evt.get("event_id")))
            return result
        expected_prev = h
        last_hash = h
        result["events"] = i + 1
    result["tip"] = last_hash.hex()
    result["ok"] = True
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--audit", required=True)
    ap.add_argument("--audit-pubkey", required=True)
    ap.add_argument("--audit-kid", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = verify(a.audit, a.audit_pubkey, a.audit_kid)
    if a.json:
        print(json.dumps(r, sort_keys=True))
    else:
        print(("ok — %d events, tip %s, %s" % (r["events"], r["tip"], r["suite"])) if r["ok"] else ("FAIL — " + "; ".join(r["errors"])))
    sys.exit(0 if r["ok"] else 1)


if __name__ == "__main__":
    main()
