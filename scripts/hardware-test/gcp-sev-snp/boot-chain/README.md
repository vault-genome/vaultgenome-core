# The boot chain of a Compute Engine SEV-SNP guest (ADR 0037)

What the chip and the vTPM each measure of a Compute Engine Confidential VM on
AMD SEV-SNP, and what the `gcp-sev-snp-vtpm` family holds, over four boots of
one VM (an n2d-standard-4, Milan, Ubuntu 24.04, with its vTPM):

| Boot | What happens |
|---|---|
| A | the image's first boot: both sources captured (its first boot grows the root partition, which moves PCR 5) |
| B | the same kernel: captured; a text sealed with the chip's derived key and with the vTPM under three PCR selections; the shipping producer quotes, the verifier pins this boot and checks it, the chip-and-vTPM sealer seals |
| C | a plain reboot: captured; every seal opened; the producer quotes, the verifier pinned to B checks it, the chip-and-vTPM file opened |
| D | another kernel (an older `-gcp` build of the same series, made GRUB's default): the same |

A capture is the kernel and its command line; the vTPM's EK and AK
certificates and templates (NV 0x01c00002, 0x01c0000a, 0x01c10000-0x01c10003);
the AK made in the endorsement hierarchy from Google's template and compared
with the key its certificate names; a quote by it over sha256:0-14, checked
with `tpm2_checkquote`; the PCRs and the event log; and the chip's report
through configfs-tsm with REPORT_DATA = SHA-256(nonce) || SHA-256(AK public
key). The probe (`probe/`) runs the code that ships: `tee.NewGCPSEVVTPMProducer`,
`tee.NewGCPSEVVTPMVerifier`, `tee.NewSEVSNPVTPMSealer`.

```bash
./run.sh <project> [zone]        # one n2d-standard-4 for about half an hour
./decode.sh <serial> <evidence>  # again, on a saved serial capture
```

`run.sh` reads the serial console as it grows, each read from where the last
ended; `decode.sh` assembles each boot's tarball line by line from its two
copies (a piece of the capture can break a line) and keeps it only when its
SHA-256 matches the header.

## The runs

- `evidence/20261024T153800Z` — the first run, three boots: boot A scrolled
  out of the serial buffer (the runner re-read the whole buffer then), the
  AK's `unique` was given to `tpm2_createprimary` without its length word, and
  the other kernel's `linux-modules-extra` does not exist for the HWE `-gcp`
  kernel, so boot C ran the same kernel. Kept for what it did record: the
  chip's measurement the same across boots, and the vTPM's sha256:0-14 seal
  refused across a reboot when sealed on the image's first boot.
- `evidence/20261024T155106Z` — four boots, the PCR answer: from B to C (a
  plain reboot) no PCR moved; from C to D (another kernel) PCRs 8, 9 and 10
  moved; the chip's measurement was the same on all four; the chip-sealed
  text opened on D, under another kernel; the vTPM seal under sha256:0-9 and
  sha256:0-14 opened on C and was refused on D, and under sha256:0-7 opened
  on D too (the kernel is not in PCRs 0-7).
- `evidence/20261024T160531Z` — the code that ships: see `run.txt`.
