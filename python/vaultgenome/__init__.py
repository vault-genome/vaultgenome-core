# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""vaultgenome — the Python distribution of Vault Genome.

Two things live here, each from where it lives in the repository:

* ``vaultgenome.auditor.verify_audit`` — the auditor's own verifier of the
  audit log (``tools/auditor``; the standard library only), installed as
  the command ``vaultgenome-audit``;
* ``vg_genome`` — the model side of a genome (``workers/genome``), installed
  as the command ``vg-genome`` and run as ``python -m vg_genome``; its
  runtime is the extra ``vaultgenome[genome]``.

The authority, the destination daemons and ``acpctl`` are Go programs; a
release of the repository carries them signed, for every platform, beside
this package.
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("vaultgenome")
except PackageNotFoundError:  # a checkout on sys.path, not an installed distribution
    __version__ = "0+unknown"

__all__ = ["__version__"]
