"""Allow ``python -m reqlens ...``."""

import sys

from reqlens.cli import main

if __name__ == "__main__":
    sys.exit(main())
