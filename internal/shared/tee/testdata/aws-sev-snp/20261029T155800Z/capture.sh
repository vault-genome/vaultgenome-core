#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
# The VLEK capture on an EC2 SEV-SNP guest: everything a verifier will need, byte for byte.
# Runs as the ubuntu user with sudo; writes /tmp/vg-capture and /tmp/vg-capture.tgz. Nothing here stops on a failed
# step: every step's exit status is in steps.txt, every stderr beside its output.
set -uo pipefail
OUT=/tmp/vg-capture; rm -rf "$OUT" /tmp/vg-capture.tgz; mkdir -p "$OUT/host" "$OUT/configfs" "$OUT/snpguest/certs" "$OUT/kds"; cd "$OUT"
step() { echo "== $*" | tee -a steps.txt; }
did() { echo "   exit=$?" | tee -a steps.txt; }
date -u +%Y-%m-%dT%H:%M:%SZ > started.txt

step "the host as the guest sees it"
uname -a > host/kernel.txt; cat /etc/os-release > host/os-release.txt
for f in bios_vendor bios_version bios_date bios_release product_name product_version sys_vendor chassis_asset_tag; do printf '%s=%s\n' "$f" "$(cat /sys/class/dmi/id/$f 2>/dev/null)"; done > host/dmi.txt
lscpu > host/lscpu.txt; { nproc; grep -m1 'model name' /proc/cpuinfo; grep -m1 flags /proc/cpuinfo | tr ' ' '\n' | grep -E '^(sev|sev_es|sev_snp|sme)$' | tr '\n' ' '; echo; } > host/cpu.txt
sudo dmesg | grep -i -E 'sev|snp|tsm|ccp|memory encryption|coco|tpm' > host/dmesg-sev.txt 2>&1
ls -la /dev/sev-guest /dev/sev /dev/tpm* /sys/kernel/config/tsm /sys/kernel/config/tsm/report > host/devices.txt 2>&1
TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 120')
for k in instance-type placement/availability-zone placement/region ami-id; do printf '%s=%s\n' "$k" "$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$k")"; done > host/imds.txt
did

step "configfs-tsm: two reports with their own nonces, the host's certificate table as auxblob"
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
for i in 1 2; do
  d=/sys/kernel/config/tsm/report/vg$i
  sudo mkdir -p "$d"
  head -c 64 /dev/urandom > "configfs/nonce$i.bin"
  sudo cp "configfs/nonce$i.bin" "$d/inblob"
  sudo cat "$d/outblob" > "configfs/report$i.bin" 2> "configfs/report$i.err"
  sudo cat "$d/auxblob" > "configfs/auxblob$i.bin" 2> "configfs/auxblob$i.err"
  for a in provider generation privlevel_floor privlevel; do printf '%s=%s\n' "$a" "$(sudo cat "$d/$a" 2>/dev/null)"; done > "configfs/attrs$i.txt"
  sudo rmdir "$d"
done
did

step "snpguest v0.11.0: the extended report, the host's certificates, the AMD chains, the verification, the derived keys"
curl -fsSL -o snpguest/snpguest https://github.com/virtee/snpguest/releases/download/v0.11.0/snpguest && chmod +x snpguest/snpguest; did
S=snpguest/snpguest
sha256sum "$S" > snpguest/snpguest.sha256
"$S" --version > snpguest/version.txt 2>&1
sudo "$S" report snpguest/report.bin snpguest/request.bin --random > snpguest/report.log 2>&1; did
sudo "$S" certificates pem snpguest/certs > snpguest/certificates.log 2>&1; did
sudo chown -R "$(id -u):$(id -g)" snpguest
"$S" display report snpguest/report.bin > snpguest/report-display.txt 2>&1; did
"$S" fetch ca pem milan snpguest/certs --endorser vlek > snpguest/fetch-ca-vlek.log 2>&1; did
"$S" verify certs snpguest/certs > snpguest/verify-certs.txt 2>&1; did
"$S" verify attestation snpguest/certs snpguest/report.bin > snpguest/verify-attestation.txt 2>&1; did
sudo "$S" key snpguest/derived-vcek.bin vcek > snpguest/key-vcek.log 2>&1; did
sudo "$S" key snpguest/derived-vlek.bin vlek > snpguest/key-vlek.log 2>&1; did
sudo chown -R "$(id -u):$(id -g)" snpguest
ls -la snpguest/certs > snpguest/certs-list.txt
for c in snpguest/certs/*.pem; do [ -f "$c" ] && openssl x509 -in "$c" -noout -text > "$c.txt" 2>&1; done

step "AMD's key server: the VLEK and VCEK chains for Milan"
curl -fsSL -o kds/vlek-Milan-cert_chain.pem https://kdsintf.amd.com/vlek/v1/Milan/cert_chain; did
curl -fsSL -o kds/vcek-Milan-cert_chain.pem https://kdsintf.amd.com/vcek/v1/Milan/cert_chain; did
for p in vlek vcek; do openssl crl2pkcs7 -nocrl -certfile "kds/$p-Milan-cert_chain.pem" | openssl pkcs7 -print_certs -noout -text > "kds/$p-Milan-chain.txt" 2>&1; done

date -u +%Y-%m-%dT%H:%M:%SZ > finished.txt
find . -type f ! -name sha256sums.txt -exec sha256sum {} + | sort -k2 > sha256sums.txt
cd /tmp && tar czf vg-capture.tgz vg-capture && sha256sum vg-capture.tgz
