#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The guest half of the boot-chain kit (run.sh): GCE's startup script on an
# n2d AMD SEV-SNP Confidential VM with a vTPM. GCE runs it on every boot, and
# a state file says which boot this is:
#
#   A  the first boot: what the chip and the vTPM say of it (the image's
#      first boot settles GRUB's environment, so nothing is sealed yet); reboot.
#   B  the same kernel: the same captures; the probe seals one text with the
#      chip's derived key and with the vTPM under each selection in $SELS;
#      reboot.
#   C  the same kernel again: the same captures; the probe opens each; then
#      another kernel is installed and made the default; reboot.
#   D  the other kernel: the same captures; the probe opens each.
#
# A capture: the kernel, its command line and the hashes of its files; the
# vTPM's EK and AK certificates and templates (GCE's NV indices); the AK made
# in the endorsement hierarchy from its template and compared with the key
# its certificate names; a quote by it over sha256:0-14 with a fresh nonce,
# checked with tpm2_checkquote; the PCRs; the event log; the chip's report
# through configfs-tsm with REPORT_DATA = SHA-256(nonce) || SHA-256(the AK's
# public key, DER). Each boot's capture goes to the serial console as a
# base64 tarball between ===VGBC-BEGIN=== and ===VGBC-END=== (three copies);
# the last boot ends with ===VGBC-DONE===. Nothing secret is in a capture:
# the probe's text is fixed and its sealed blobs stay on the VM.
set -u
export HOME=/root DEBIAN_FRONTEND=noninteractive
STATE=/var/lib/vg-boot-chain
mkdir -p "$STATE/out"
PHASE=A
[ -s "$STATE/phase" ] && PHASE="$(cat "$STATE/phase")"
[ "$PHASE" = DONE ] && exit 0
OUT="$STATE/out/$PHASE"
rm -rf "$OUT"; mkdir -p "$OUT"
exec > >(tee -a "$OUT/console.log") 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
BUCKET="$(md attributes/vg-bucket)"
STAMP="$(md attributes/vg-stamp)"
PCRS=sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14
SELS=(sha256:0,1,2,3,4,5,6,7 sha256:0,1,2,3,4,5,6,7,8,9 sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14)
step() { echo "== [$PHASE] $*"; echo "== $*" >> "$OUT/steps.txt"; }
note() { echo "$*" >> "$OUT/steps.txt"; }
step "boot $PHASE of run $STAMP at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ "$PHASE" = A ]; then
  step "tpm2-tools"
  for i in $(seq 1 12); do apt-get install -y -qq tpm2-tools >/dev/null 2>&1 && break; apt-get update -qq >/dev/null 2>&1 || true; sleep 10; done
  step "the probe from gs://$BUCKET"
  GTOKEN=$(md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
  curl -sSf -H "Authorization: Bearer $GTOKEN" -o "$STATE/probe" \
    "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/bc%2Fprobe?alt=media" || step "fetch probe failed"
  unset GTOKEN
  chmod +x "$STATE/probe"
fi
tpm2_getcap properties-fixed 2>/dev/null | grep -A1 -E "TPM2_PT_MANUFACTURER|TPM2_PT_FIRMWARE_VERSION_1" > "$OUT/tpm-vendor.txt" || true

step "configfs-tsm and the sev-guest driver"
modprobe sev-guest 2>/dev/null || {
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
  modprobe sev-guest 2>/dev/null || true
}
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done

step "the kernel"
uname -r > "$OUT/kernel.txt"
cat /proc/cmdline > "$OUT/cmdline.txt"
sha256sum "/boot/vmlinuz-$(uname -r)" "/boot/initrd.img-$(uname -r)" > "$OUT/boot-files.sha256" 2>/dev/null || true
note "kernel=$(uname -r)"

step "the vTPM's certificates and templates (GCE NV indices)"
for idx in 0x01c00002 0x01c0000a 0x01c10000 0x01c10001 0x01c10002 0x01c10003; do
  tpm2_nvread -C o "$idx" -o "$OUT/nv-$idx.bin" 2>>"$OUT/nv.txt" \
    || tpm2_nvread "$idx" -o "$OUT/nv-$idx.bin" 2>>"$OUT/nv.txt" \
    || echo "$idx unreadable" >> "$OUT/nv.txt"
done
python3 - "$OUT" <<'PY'
# The certificate indices are padded past the DER: cut each to its length.
import pathlib, sys
out = pathlib.Path(sys.argv[1])
for idx in ("0x01c00002", "0x01c0000a", "0x01c10000", "0x01c10002"):
    p = out / f"nv-{idx}.bin"
    if not p.exists():
        continue
    b = p.read_bytes()
    if len(b) < 4 or b[0] != 0x30:
        continue
    if b[1] < 0x80:
        n = 2 + b[1]
    else:
        k = b[1] & 0x7F
        n = 2 + k + int.from_bytes(b[2 : 2 + k], "big")
    (out / f"cert-{idx}.der").write_bytes(b[:n])
PY
for idx in 0x01c00002 0x01c0000a 0x01c10000 0x01c10002; do
  [ -s "$OUT/cert-$idx.der" ] && openssl x509 -inform der -in "$OUT/cert-$idx.der" -noout -text > "$OUT/cert-$idx.txt" 2>&1
done

step "the AK, made in the endorsement hierarchy from GCE's template"
python3 - "$OUT/nv-0x01c10001.bin" "$STATE" > "$OUT/ak-template.txt" 2>&1 <<'PY'
# TPMT_PUBLIC (TPM 2.0 Part 2, 12.2.4) of an RSA key, turned into the
# flags tpm2_createprimary takes; the policy and unique go to files.
import pathlib, struct, sys
b = pathlib.Path(sys.argv[1]).read_bytes()
state = pathlib.Path(sys.argv[2])
o = 0
def u16():
    global o
    v = struct.unpack(">H", b[o:o+2])[0]; o += 2; return v
def u32():
    global o
    v = struct.unpack(">I", b[o:o+4])[0]; o += 4; return v
def b2():
    global o
    n = u16(); v = b[o:o+n]; o += n; return v
typ, name_alg, attrs = u16(), u16(), u32()
policy = b2()
assert typ == 0x0001, f"not an RSA template: 0x{typ:04x}"
sym = u16()
if sym != 0x0010:
    u16(); u16()
scheme = u16()
scheme_hash = u16() if scheme != 0x0010 else None
bits, exponent = u16(), u32()
unique = b2()
names = {1: "fixedtpm", 2: "stclear", 4: "fixedparent", 5: "sensitivedataorigin", 6: "userwithauth",
         7: "adminwithpolicy", 10: "noda", 11: "encryptedduplication", 16: "restricted", 17: "decrypt", 18: "sign"}
flags = "|".join(v for k, v in sorted(names.items()) if attrs >> k & 1)
algs = {0x000B: "sha256", 0x000C: "sha384", 0x0004: "sha1", 0x0010: "null", 0x0014: "rsassa", 0x0016: "rsapss"}
key = f"rsa{bits}:{algs.get(scheme, hex(scheme))}" + (f"-{algs.get(scheme_hash, hex(scheme_hash))}" if scheme_hash else "") + (":null" if sym == 0x0010 else ":aes128cfb")
args = ["-g", algs.get(name_alg, hex(name_alg)), "-G", key, "-a", flags]
if policy:
    (state / "ak.policy").write_bytes(policy); args += ["-L", str(state / "ak.policy")]
if unique:
    # tpm2-tools reads -u as a TPMU_PUBLIC_ID with its length word in
    # little-endian order (tpm2_createprimary(1)).
    (state / "ak.unique").write_bytes(struct.pack("<H", len(unique)) + unique); args += ["-u", str(state / "ak.unique")]
print(f"attributes=0x{attrs:08x} policy={len(policy)}B unique={len(unique)}B exponent={exponent}")
(state / "ak.args").write_text("\n".join(args) + "\n")
PY
if [ -s "$STATE/ak.args" ]; then mapfile -t AKARGS < "$STATE/ak.args"; else
  AKARGS=(-g sha256 -G rsa2048:rsassa-sha256:null -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|sign'); fi
note "ak args: ${AKARGS[*]}"
tpm2_createprimary -C e "${AKARGS[@]}" -c "$STATE/ak.ctx" > "$OUT/ak-create.txt" 2>&1 || step "createprimary failed"
tpm2_readpublic -c "$STATE/ak.ctx" -f pem -o "$OUT/ak-pub.pem" > "$OUT/ak-public.txt" 2>&1 || true
openssl x509 -inform der -in "$OUT/cert-0x01c10000.der" -noout -pubkey > "$OUT/akcert-pub.pem" 2>/dev/null || true
A1=$(openssl pkey -pubin -in "$OUT/ak-pub.pem" -outform der 2>/dev/null | sha256sum | cut -d' ' -f1)
A2=$(openssl pkey -pubin -in "$OUT/akcert-pub.pem" -outform der 2>/dev/null | sha256sum | cut -d' ' -f1)
note "ak_pub_sha256=$A1 akcert_pub_sha256=$A2"
if [ "$A1" = "$A2" ] && [ "$A1" != "$(printf '' | sha256sum | cut -d' ' -f1)" ]; then step "the AK made here is the key Google's AK certificate names"; else step "AK MISMATCH with its certificate"; fi

step "a quote by the AK over $PCRS with a fresh nonce"
NONCE=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
echo "$NONCE" > "$OUT/nonce.hex"
tpm2_quote -c "$STATE/ak.ctx" -l "$PCRS" -q "$NONCE" -m "$OUT/quote.msg" -s "$OUT/quote.sig" -o "$OUT/quote.pcrs" -g sha256 > "$OUT/quote.txt" 2>&1 || step "quote failed"
if tpm2_checkquote -u "$OUT/ak-pub.pem" -m "$OUT/quote.msg" -s "$OUT/quote.sig" -f "$OUT/quote.pcrs" -g sha256 -q "$NONCE" > "$OUT/checkquote.txt" 2>&1; then step "tpm2_checkquote ok"; else step "tpm2_checkquote FAIL"; fi
tpm2_pcrread sha256 > "$OUT/pcrs.txt" 2>&1 || true
cp /sys/kernel/security/tpm0/binary_bios_measurements "$OUT/eventlog.bin" 2>/dev/null || step "no event log"
tpm2_eventlog "$OUT/eventlog.bin" > "$OUT/eventlog.yaml" 2>&1 || true
note "eventlog_events=$(grep -c 'EventNum:' "$OUT/eventlog.yaml" 2>/dev/null)"

step "the chip's report, REPORT_DATA = SHA-256(nonce) || SHA-256(AK public key)"
python3 - "$NONCE" "$OUT" <<'PY' || echo "chip report FAIL" >> "$OUT/steps.txt"
import hashlib, pathlib, subprocess, sys
nonce = bytes.fromhex(sys.argv[1]); out = pathlib.Path(sys.argv[2])
akder = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(out / "ak-pub.pem"), "-outform", "der"], capture_output=True).stdout
rd = hashlib.sha256(nonce).digest() + hashlib.sha256(akder).digest()
d = pathlib.Path("/sys/kernel/config/tsm/report/vgbootchain")
d.mkdir(exist_ok=True)
try:
    (d / "inblob").write_bytes(rd)
    rep = (d / "outblob").read_bytes()
    (out / "snp-report.bin").write_bytes(rep)
    (out / "tsm-provider.txt").write_text((d / "provider").read_text())
    try:
        (out / "snp-certs.bin").write_bytes((d / "auxblob").read_bytes())
    except OSError:
        pass
finally:
    d.rmdir()
(out / "report-data.hex").write_text(rd.hex() + "\n")
with open(out / "steps.txt", "a") as f:
    f.write(f"snp report {len(rep)} bytes; measurement {rep[0x90:0xC0].hex()}; report_data_bound {rep[0x50:0x90] == rd}\n")
PY

case "$PHASE" in
  B) step "the probe seals one text with the chip and with the vTPM under ${SELS[*]}"
     "$STATE/probe" seal "$STATE" "${SELS[@]}" > "$OUT/probe.txt" 2>&1 ;;
  C|D) step "the probe opens what boot B sealed"
     "$STATE/probe" open "$STATE" "${SELS[@]}" > "$OUT/probe.txt" 2>&1 ;;
esac
[ -f "$OUT/probe.txt" ] && cat "$OUT/probe.txt" >> "$OUT/steps.txt"
case "$PHASE" in
  B|C|D) step "the product: gcp-sev-snp-vtpm quotes, the verifier pinned to boot B's PCRs checks it, the chip-and-vTPM sealer"
     "$STATE/probe" product "$STATE" "$PHASE" > "$OUT/product.txt" 2>&1
     cat "$OUT/product.txt" >> "$OUT/steps.txt"
     cp -r "$STATE/product-$PHASE" "$OUT/product" 2>/dev/null || true
     cp "$STATE/vcek-cache/"* "$OUT/product/" 2>/dev/null || true ;;
esac

switch_kernel() {
  CUR="$(uname -r)"
  apt-get update -qq >/dev/null 2>&1
  CAND="$(apt-cache search --names-only '^linux-image-[0-9][0-9.]*-[0-9][0-9]*-gcp$' 2>/dev/null | awk '{print $1}' | sed 's/^linux-image-//' | grep -vx "$CUR" | sort -V | tail -1)"
  note "running=$CUR next=$CAND"
  [ -n "$CAND" ] || { step "no other gcp kernel in the archive"; return 1; }
  apt-get install -y -qq "linux-image-$CAND" "linux-modules-$CAND" > "$OUT/kernel-install.txt" 2>&1 || step "kernel install failed"
  apt-get install -y -qq "linux-modules-extra-$CAND" >> "$OUT/kernel-install.txt" 2>&1 || note "no linux-modules-extra-$CAND (the HWE kernel ships its modules in linux-modules)"
  SUB="$(sed -n "s/^submenu '[^']*' .*\$menuentry_id_option '\([^']*\)'.*/\1/p" /boot/grub/grub.cfg | head -1)"
  ID="$(grep -F "$CAND" /boot/grub/grub.cfg | grep -v recovery | sed -n "s/.*\$menuentry_id_option '\([^']*\)'.*/\1/p" | head -1)"
  note "grub submenu=$SUB entry=$ID"
  printf 'GRUB_DEFAULT="%s>%s"\n' "$SUB" "$ID" > /etc/default/grub.d/99-vg-boot-chain.cfg
  update-grub >> "$OUT/kernel-install.txt" 2>&1 || step "update-grub failed"
  echo "$CAND" > "$STATE/next-kernel"
}

case "$PHASE" in
  C) step "another kernel, made the default"; switch_kernel ;;
  D) [ "$(uname -r)" = "$(cat "$STATE/next-kernel" 2>/dev/null)" ] && step "booted the other kernel $(uname -r)" || step "NOT the other kernel: $(uname -r)" ;;
esac

emit() {
  ( cd "$OUT" && sha256sum -- * > "$STATE/sums.txt" ) && mv "$STATE/sums.txt" "$OUT/sha256sums.txt"
  cd "$STATE/out" && tar czf "$PHASE.tgz" "$PHASE" && base64 -w0 "$PHASE.tgz" > "$PHASE.b64"
  SZ=$(stat -c%s "$PHASE.b64"); H=$(sha256sum "$PHASE.b64" | cut -d' ' -f1)
  fold -w 76 "$PHASE.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$PHASE.lines"; NL=$(wc -l < "$PHASE.lines")
  dmesg -n 1 2>/dev/null || true
  sleep 3
  for COPY in 1 2; do
    { echo; echo "===VGBC-BEGIN=== $PHASE size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$PHASE.lines"; echo "===VGBC-END=== $PHASE"; } > /dev/ttyS0 2>/dev/null || true
    sleep 3
  done
}

case "$PHASE" in
  A) echo B > "$STATE/phase"; emit; (sleep 5; systemctl reboot) & ;;
  B) echo C > "$STATE/phase"; emit; (sleep 5; systemctl reboot) & ;;
  C) echo D > "$STATE/phase"; emit; (sleep 5; systemctl reboot) & ;;
  D) echo DONE > "$STATE/phase"; emit; echo "===VGBC-DONE=== $STAMP" > /dev/ttyS0 ;;
esac
exit 0
