from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")


def resource_root() -> Path:
    """
    Return the root folder where packaged resources live.
    - In dev: alongside this file's parent (可视化/)
    - In PyInstaller: sys._MEIPASS
    """
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS")).resolve()
    return Path(__file__).resolve().parents[1]


def get_resource_path(rel: str) -> Path:
    return (resource_root() / rel).resolve()

