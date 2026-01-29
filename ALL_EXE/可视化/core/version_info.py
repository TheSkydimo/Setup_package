from __future__ import annotations

import re
from pathlib import Path

import pefile
import win32api


def normalize_three_part_version(ver: str) -> str:
    if not ver:
        return ""
    v = re.sub(r"[^0-9.]", "", str(ver)).strip(".")
    v = re.sub(r"\.+", ".", v)
    parts = [p for p in v.split(".") if p.isdigit()]
    if not parts:
        return ""
    parts = (parts + ["0", "0"])[:3]
    return ".".join(parts)


def _read_string_file_info_versions(file_path: str) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "FileInfo"):
            for fi in pe.FileInfo:
                for entry in fi:
                    if getattr(entry, "Key", b"").decode(errors="ignore") == "StringFileInfo":
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                kk = k.decode(errors="ignore")
                                vv = v.decode(errors="ignore")
                                result[kk] = vv
    except Exception:
        pass
    return result


def get_file_and_product_versions(file_path: str) -> dict[str, str | None]:
    file_version: str | None = None
    product_version: str | None = None
    try:
        info = win32api.GetFileVersionInfo(file_path, "\\")
        ms = info.get("FileVersionMS")
        ls = info.get("FileVersionLS")
        if ms is not None and ls is not None:
            file_version = f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
        p_ms = info.get("ProductVersionMS")
        p_ls = info.get("ProductVersionLS")
        if p_ms is not None and p_ls is not None:
            product_version = f"{p_ms >> 16}.{p_ms & 0xFFFF}.{p_ls >> 16}.{p_ls & 0xFFFF}"
    except Exception:
        pass

    string_versions = _read_string_file_info_versions(file_path)
    if "ProductVersion" in string_versions:
        product_version = string_versions["ProductVersion"]
    if not file_version and "FileVersion" in string_versions:
        file_version = string_versions["FileVersion"]

    return {"file": file_version, "product": product_version}


def ensure_file_exists(path: str | Path) -> Path:
    p = Path(path).resolve()
    if not p.is_file():
        raise FileNotFoundError(str(p))
    return p

