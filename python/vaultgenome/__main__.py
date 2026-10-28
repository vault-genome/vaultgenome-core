# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""``python -m vaultgenome``: the version, and the commands this distribution installs."""
import sys

from . import __version__


def main(argv=None) -> int:
    print(f"vaultgenome {__version__}")
    print("  vaultgenome-audit   verify an audit log with nothing of the product in it (tools/auditor)")
    print("  vg-genome           fine-tune, replay, measure and open a genome (workers/genome; pip install 'vaultgenome[genome]')")
    return 0


if __name__ == "__main__":
    sys.exit(main())
