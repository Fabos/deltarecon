#!/usr/bin/env python3
"""Negro Recon launcher."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# If the local virtualenv exists, use it for both Web and CLI so optional
# intelligence/AI dependencies are available consistently.
venv_python = ROOT / ".venv" / "bin" / "python"
if venv_python.exists() and Path(sys.executable).resolve() != venv_python.resolve():
    os.execv(str(venv_python), [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]])

from negro_core import main

if __name__ == "__main__":
    main()
