from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class RepoPaths:
    repo_root: Path
    signbat: Path
    unified_iss: Path
    upload_360: Path
    remote_sign: Path


MARKERS = (
    "SignBat_All_EXE.py",
    "Unified.iss",
    "remote_sign_client.py",
    "360_auto_upload.py",
)


def _is_repo_root(p: Path) -> bool:
    return all((p / name).is_file() for name in MARKERS)


def iter_parents_inclusive(start: Path) -> Iterable[Path]:
    cur = start.resolve()
    yield cur
    for parent in cur.parents:
        yield parent


def find_repo_root(start_dir: Path) -> Path | None:
    for p in iter_parents_inclusive(start_dir):
        if _is_repo_root(p):
            return p
    return None


def resolve_repo_paths(repo_root: Path) -> RepoPaths:
    repo_root = repo_root.resolve()
    signbat = repo_root / "SignBat_All_EXE.py"
    unified_iss = repo_root / "Unified.iss"
    upload_360 = repo_root / "360_auto_upload.py"
    remote_sign = repo_root / "remote_sign_client.py"

    missing = [str(p) for p in (signbat, unified_iss, upload_360, remote_sign) if not p.is_file()]
    if missing:
        raise FileNotFoundError("Repo root is missing required files:\n" + "\n".join(missing))

    return RepoPaths(
        repo_root=repo_root,
        signbat=signbat,
        unified_iss=unified_iss,
        upload_360=upload_360,
        remote_sign=remote_sign,
    )

