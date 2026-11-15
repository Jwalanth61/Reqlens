"""Thin launcher so the tool runs as ``python reqlens.py ...`` without installing."""

import sys

from reqlens.cli import main

if __name__ == "__main__":
    sys.exit(main())
