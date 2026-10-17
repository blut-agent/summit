"""PyInstaller entry point.

`python -m summit` and the PyInstaller binary both start here.
The module-relative imports resolve correctly because this file lives
inside the summit package.
"""

import sys

from summit.cli import main

if __name__ == "__main__":
    sys.exit(main())
