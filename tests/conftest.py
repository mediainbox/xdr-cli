"""Make the CLI modules importable.

The project ships no pyproject.toml or setup.py, so there is no installed
package to import from. Tests import the modules from the repository root.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
