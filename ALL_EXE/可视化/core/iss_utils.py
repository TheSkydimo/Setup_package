from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def find_iscc(explicit_path: str | None = None) -> str | None:
    candidates: list[str] = []
    if explicit_path:
        candidates.append(explicit_path)
    env_iscc = os.environ.get("ISCC_EXE")
    if env_iscc:
        candidates.append(env_iscc)
    which_iscc = shutil.which("ISCC") or shutil.which("ISCC.exe")
    if which_iscc:
        candidates.append(which_iscc)
    candidates.extend(
        [
            r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
            r"C:\Program Files\Inno Setup 6\ISCC.exe",
            r"C:\Program Files (x86)\Inno Setup 5\ISCC.exe",
            r"C:\Program Files\Inno Setup 5\ISCC.exe",
        ]
    )
    for c in candidates:
        try:
            p = Path(c).expanduser().resolve()
        except Exception:
            p = Path(c)
        if p.is_file():
            return str(p)
    return None


def find_ispp_ifdef_block_span(text: str, block_macro: str) -> tuple[int, int] | None:
    lines = text.splitlines(keepends=True)
    start_line_idx: Optional[int] = None
    depth = 0

    ifdef_re = re.compile(rf"(?i)^\s*#ifdef\s+{re.escape(block_macro)}\s*$")
    inc_re = re.compile(r"(?i)^\s*#(if|ifdef|ifndef)\b")
    dec_re = re.compile(r"(?i)^\s*#endif\b")

    char_pos = 0
    start_char = 0
    for i, line in enumerate(lines):
        stripped = line.rstrip("\r\n")
        if start_line_idx is None:
            if ifdef_re.match(stripped):
                start_line_idx = i
                start_char = char_pos
                depth = 1
        else:
            if inc_re.match(stripped):
                depth += 1
            elif dec_re.match(stripped):
                depth -= 1
                if depth == 0:
                    end_char = char_pos + len(line)
                    return (start_char, end_char)
        char_pos += len(line)
    return None


def replace_or_insert_define_in_block(text: str, block_macro: str, name: str, value: str) -> str:
    span = find_ispp_ifdef_block_span(text, block_macro)
    if not span:
        raise RuntimeError(f"Cannot find ISPP block: #ifdef {block_macro}")
    start, end = span
    block = text[start:end]
    pattern = re.compile(rf'(?im)^[ \t]*#define[ \t]+{re.escape(name)}[ \t]+"[^"]*"[ \t]*$')
    replacement = f'#define {name} "{value}"'
    if pattern.search(block):
        block2 = pattern.sub(replacement, block)
    else:
        m = re.search(r"(?im)^\s*#ifdef\s+.+\s*$\r?\n?", block)
        insert_at = m.end() if m else 0
        block2 = block[:insert_at] + replacement + "\n" + block[insert_at:]
    return text[:start] + block2 + text[end:]


def extract_define_value_in_block(text: str, block_macro: str, name: str) -> str | None:
    span = find_ispp_ifdef_block_span(text, block_macro)
    if not span:
        return None
    start, end = span
    block = text[start:end]
    m = re.search(rf'(?im)^[ \t]*#define[ \t]+{re.escape(name)}[ \t]+"([^"]*)"[ \t]*$', block)
    return m.group(1) if m else None


def extract_inno_setup_value(text: str, section: str, key: str) -> str | None:
    sec_re = re.compile(rf"(?im)^\s*\[{re.escape(section)}\]\s*$")
    any_sec_re = re.compile(r"(?im)^\s*\[.+?\]\s*$")
    lines = text.splitlines()
    in_sec = False
    for line in lines:
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        if sec_re.match(s):
            in_sec = True
            continue
        if in_sec and any_sec_re.match(s):
            break
        if not in_sec:
            continue
        m = re.match(rf"(?i)^{re.escape(key)}\s*=\s*(.+?)\s*$", s)
        if m:
            return m.group(1)
    return None


@dataclass(frozen=True)
class InstallerOutput:
    output_dir: Path
    output_base_filename: str


def compute_installer_output(iss_path: Path, block_macro: str, app_version_full: str) -> Path:
    txt = iss_path.read_text(encoding="utf-8", errors="ignore")
    out_dir = extract_inno_setup_value(txt, "Setup", "OutputDir")
    if not out_dir:
        raise RuntimeError("Cannot read [Setup] OutputDir from iss.")
    base_filename = extract_inno_setup_value(txt, "Setup", "OutputBaseFilename")
    if not base_filename:
        raise RuntimeError("Cannot read [Setup] OutputBaseFilename from iss.")

    setup_output_base = extract_define_value_in_block(txt, block_macro, "SetupOutputBase") or ""
    # Expand simple ISPP: {#SetupOutputBase}{#AppVersionFull}
    name = base_filename
    name = name.replace("{#SetupOutputBase}", setup_output_base)
    name = name.replace("{#AppVersionFull}", app_version_full)
    # If OutputDir is relative, it's relative to iss_path folder
    out_path = (iss_path.parent / Path(out_dir)).resolve() if not Path(out_dir).is_absolute() else Path(out_dir).resolve()
    return (out_path / f"{name}.exe").resolve()


def find_newest_installer_fallback(output_dir: Path, prefix: str) -> Path | None:
    if not output_dir.is_dir():
        return None
    candidates = sorted(output_dir.glob(f"{prefix}*.exe"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None

