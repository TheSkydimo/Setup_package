from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth


class SignError(RuntimeError):
    pass


@dataclass(frozen=True)
class SignConfig:
    server: str
    api_key: str
    user: str
    password: str | None


def sign_sync(server: str, api_key: str, user: str, src: str, out: str, password: str | None) -> Path:
    url = f"{server.rstrip('/')}/sign-sync"
    headers: dict[str, str] = {}
    if api_key:
        headers["x-api-key"] = api_key
    if user:
        headers["x-user"] = user
    auth = HTTPBasicAuth(user, password) if user and password is not None else None
    with open(src, "rb") as f:
        files = {"file": (Path(src).name, f, "application/octet-stream")}
        r = requests.post(url, headers=headers, files=files, timeout=3600, stream=True, auth=auth)
    if r.status_code != 200:
        raise SignError(f"sign-sync failed: {r.status_code} {r.text}")
    out_path = Path(out) if out else Path(src).with_suffix(Path(src).suffix + ".signed")
    with open(out_path, "wb") as w:
        for chunk in r.iter_content(1024 * 1024):
            if chunk:
                w.write(chunk)
    return out_path


def sign_file_inplace(cfg: SignConfig, target_path: str) -> None:
    p = Path(target_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {p}")

    tmp = p.with_suffix(p.suffix + ".signed_tmp")
    if tmp.exists():
        try:
            tmp.unlink()
        except Exception:
            pass

    signed = sign_sync(cfg.server, cfg.api_key, cfg.user, str(p), str(tmp), cfg.password)
    os.replace(str(signed), str(p))

