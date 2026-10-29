#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
# pass 2 on the guest: the ASVK and ARK from KDS beside the host's VLEK, snpguest's own chain and signature checks,
# the VLEK's TCB and CSP_ID extensions decoded, a second derived key for a later comparison.
set -uo pipefail
cd /tmp/vg-capture; S=snpguest/snpguest
step() { echo "== $*" | tee -a steps.txt; }
did() { echo "   exit=$?" | tee -a steps.txt; }
step "pass 2: fetch ca (vlek endorser), verify certs, verify attestation"
"$S" fetch ca pem snpguest/certs milan --endorser vlek > snpguest/fetch-ca-vlek.log 2>&1; did
ls -la snpguest/certs > snpguest/certs-list.txt
"$S" verify certs snpguest/certs > snpguest/verify-certs.txt 2>&1; did
"$S" verify attestation snpguest/certs snpguest/report.bin > snpguest/verify-attestation.txt 2>&1; did
for c in snpguest/certs/*.pem; do openssl x509 -in "$c" -noout -text > "$c.txt" 2>&1; done
openssl asn1parse -in snpguest/certs/vlek.pem -i > snpguest/certs/vlek.asn1.txt 2>&1
step "derived key again (root VCEK), for the reboot comparison"
sudo "$S" key snpguest/derived-vcek-2.bin vcek > snpguest/key-vcek-2.log 2>&1; did
sudo chown -R "$(id -u):$(id -g)" snpguest
cmp snpguest/derived-vcek.bin snpguest/derived-vcek-2.bin && echo "derived key stable within the boot" | tee -a steps.txt
find . -type f ! -name sha256sums.txt -exec sha256sum {} + | sort -k2 > sha256sums.txt
cd /tmp && rm -f vg-capture.tgz && tar czf vg-capture.tgz vg-capture && sha256sum vg-capture.tgz
