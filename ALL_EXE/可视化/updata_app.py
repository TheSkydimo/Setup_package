from __future__ import annotations

import argparse
import json
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from ftplib import FTP, error_perm
from pathlib import Path
from typing import Any, Iterable, Optional

import boto3
import paramiko

from exeversion import get_exe_product_version


def _sanitize_version(s: str) -> str:
    s = s.strip()
    if not s:
        return "unknown"
    # keep simple filename-safe chars
    s = re.sub(r"[^0-9A-Za-z._-]+", "_", s)
    return s.strip("._-") or "unknown"


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return ""


def _write_text_file(path: Path, content: str) -> None:
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


@dataclass(frozen=True)
class SoftwareConfig:
    local_exe_path: Path
    upload_name_template: str


@dataclass(frozen=True)
class CloudflareConfig:
    account_id: str
    access_key_id: str
    secret_access_key: str
    bucket_name: str
    remote_dir: str = "skydimo-setup"


@dataclass(frozen=True)
class ServerConfig:
    name: str
    type: str  # "ftp" | "sftp"

    host: str
    port: int
    username: str
    password: str
    remote_dir: str

    # ftp-only options (Hostinger)
    use_public_html_autodetect: bool = False
    site_domain: str = ""


def _load_config(config_path: Path) -> tuple[SoftwareConfig, list[ServerConfig], Optional[CloudflareConfig]]:
    raw = json.loads(config_path.read_text(encoding="utf-8"))

    software_raw = raw.get("software") or {}
    local_exe_path = Path(str(software_raw.get("local_exe_path") or "")).expanduser()
    upload_name_template = str(software_raw.get("upload_name_template") or "Skydimo-{version}.exe")

    if not local_exe_path:
        raise ValueError("config.json: software.local_exe_path is required")

    # Load Cloudflare config (optional)
    cloudflare_config: Optional[CloudflareConfig] = None
    cf_raw = raw.get("cloudflare")
    if cf_raw:
        account_id = str(cf_raw.get("account_id") or "").strip()
        access_key_id = str(cf_raw.get("access_key_id") or "").strip()
        secret_access_key = str(cf_raw.get("secret_access_key") or "").strip()
        bucket_name = str(cf_raw.get("bucket_name") or "").strip()
        remote_dir = str(cf_raw.get("remote_dir") or "skydimo-setup").strip()
        
        if account_id and access_key_id and secret_access_key and bucket_name:
            cloudflare_config = CloudflareConfig(
                account_id=account_id,
                access_key_id=access_key_id,
                secret_access_key=secret_access_key,
                bucket_name=bucket_name,
                remote_dir=remote_dir,
            )

    servers: list[ServerConfig] = []
    for s in raw.get("servers") or []:
        stype = str(s.get("type") or "").strip().lower()
        name = str(s.get("name") or "").strip()
        if not name:
            raise ValueError("config.json: each server must have 'name'")
        if stype not in ("ftp", "sftp"):
            raise ValueError(f"config.json: server '{name}' type must be ftp/sftp")

        host = str(s.get("host") or "").strip()
        port = int(s.get("port") or (22 if stype == "sftp" else 21))

        # Support env indirection for credentials (Hostinger-style)
        username = str(s.get("username") or "").strip()
        password = str(s.get("password") or "").strip()

        username_env = str(s.get("username_env") or "").strip()
        password_env = str(s.get("password_env") or "").strip()
        if username_env:
            username = os.getenv(username_env, str(s.get("username_default") or username))
        if password_env:
            password = os.getenv(password_env, str(s.get("password_default") or password))

        remote_dir = str(s.get("remote_dir") or "").strip()

        use_public_html_autodetect = bool(s.get("use_public_html_autodetect") or False)
        site_domain = str(s.get("site_domain") or "").strip()
        site_domain_env = str(s.get("site_domain_env") or "").strip()
        if site_domain_env:
            site_domain = os.getenv(site_domain_env, str(s.get("site_domain_default") or site_domain))

        if not host:
            raise ValueError(f"config.json: server '{name}' host is required")
        if not username:
            raise ValueError(f"config.json: server '{name}' username is required (or username_env)")
        if not password:
            raise ValueError(f"config.json: server '{name}' password is required (or password_env)")
        if not remote_dir:
            raise ValueError(f"config.json: server '{name}' remote_dir is required")

        servers.append(
            ServerConfig(
                name=name,
                type=stype,
                host=host,
                port=port,
                username=username,
                password=password,
                remote_dir=remote_dir,
                use_public_html_autodetect=use_public_html_autodetect,
                site_domain=site_domain,
            )
        )

    sw = SoftwareConfig(local_exe_path=local_exe_path, upload_name_template=upload_name_template)
    return sw, servers, cloudflare_config


def _ftp_try_cwd(ftp: FTP, path: str) -> bool:
    try:
        ftp.cwd(path)
        return True
    except error_perm:
        return False


def _ftp_ensure_dirs(ftp: FTP, target_dir: str) -> None:
    """
    Ensure target_dir exists and cwd into it.
    Works with absolute-like (/a/b) and relative paths.
    """
    p = target_dir.strip()
    if not p:
        return

    # Try direct cwd first (fast path)
    if _ftp_try_cwd(ftp, p):
        return

    # Create recursively
    is_abs = p.startswith("/")
    parts = [x for x in p.split("/") if x]
    if is_abs:
        ftp.cwd("/")
    for part in parts:
        if _ftp_try_cwd(ftp, part):
            continue
        try:
            ftp.mkd(part)
        except error_perm:
            # race / already exists / permissions
            pass
        ftp.cwd(part)


def _hostinger_public_html_pwd(ftp: FTP, domain: str) -> str:
    """
    Hostinger/Panel-like file manager path often looks like:
      /home/<user>/domains/<domain>/public_html
    But FTP login root is usually chrooted.
    """
    candidates: list[str] = [
        "public_html",
        "/public_html",
        f"domains/{domain}/public_html",
        f"/domains/{domain}/public_html",
        f"{domain}/public_html",
        f"/{domain}/public_html",
    ]
    for p in candidates:
        if _ftp_try_cwd(ftp, p):
            return ftp.pwd()
    raise RuntimeError("Cannot locate public_html via FTP (Hostinger). Check domain / chroot root.")


def _ftp_upload(ftp: FTP, local_path: Path, remote_name: str, dry_run: bool) -> None:
    print(f"  upload: {local_path} -> {remote_name}")
    if dry_run:
        return
    with local_path.open("rb") as f:
        ftp.storbinary(f"STOR {remote_name}", f)


def _sftp_ensure_dirs(sftp: paramiko.SFTPClient, target_dir: str) -> str:
    """
    Ensure posix path exists. Returns normalized path.
    """
    p = target_dir.strip().replace("\\", "/")
    if not p:
        return "."
    # normalize but keep leading /
    p = posixpath.normpath(p)
    if p == ".":
        return "."

    parts = [x for x in p.split("/") if x]
    cur = "/" if p.startswith("/") else "."
    for part in parts:
        nxt = part if cur in (".", "/") else posixpath.join(cur, part)
        if cur == "/":
            nxt = "/" + part
        try:
            sftp.stat(nxt)
        except OSError:
            sftp.mkdir(nxt)
        cur = nxt
    return cur


def _sftp_exists(sftp: paramiko.SFTPClient, remote_path: str) -> bool:
    try:
        sftp.stat(remote_path)
        return True
    except OSError:
        return False


def _sftp_upload(sftp: paramiko.SFTPClient, remote_dir: str, local_path: Path, remote_name: str, dry_run: bool) -> None:
    dst_path = posixpath.join(remote_dir, remote_name)
    print(f"  upload: {local_path} -> {dst_path}")
    if dry_run:
        return
    sftp.put(str(local_path), dst_path)


def _deploy_to_ftp(server: ServerConfig, sw: SoftwareConfig, upload_name: str, dry_run: bool) -> None:
    ftp = FTP()
    ftp.connect(server.host, server.port, timeout=30)
    ftp.login(server.username, server.password)

    try:
        if server.use_public_html_autodetect:
            public_html = _hostinger_public_html_pwd(ftp, server.site_domain)
            # If config remote_dir is "public_html", we are already there.
            if server.remote_dir not in ("public_html", "/public_html"):
                _ftp_ensure_dirs(ftp, server.remote_dir)
            else:
                ftp.cwd(public_html)
        else:
            _ftp_ensure_dirs(ftp, server.remote_dir)

        # Only upload with versioned name. Do not rename or delete any remote files.
        _ftp_upload(ftp, sw.local_exe_path, upload_name, dry_run=dry_run)
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass


def _deploy_to_sftp(server: ServerConfig, sw: SoftwareConfig, upload_name: str, dry_run: bool) -> None:
    with paramiko.SSHClient() as client:
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=server.host,
            port=server.port,
            username=server.username,
            password=server.password,
            timeout=30,
        )
        with client.open_sftp() as sftp:
            remote_dir = _sftp_ensure_dirs(sftp, server.remote_dir)
            # Only upload with versioned name. Do not rename or delete any remote files.
            _sftp_upload(sftp, remote_dir, sw.local_exe_path, upload_name, dry_run=dry_run)


def _deploy_to_cloudflare(cf_config: CloudflareConfig, sw: SoftwareConfig, upload_name: str, dry_run: bool) -> None:
    """Upload file to Cloudflare R2"""
    s3 = boto3.client(
        service_name="s3",
        endpoint_url=f"https://{cf_config.account_id}.r2.cloudflarestorage.com",
        aws_access_key_id=cf_config.access_key_id,
        aws_secret_access_key=cf_config.secret_access_key,
        region_name="auto",
    )
    
    # Build remote key path
    remote_key = f"{cf_config.remote_dir}/{upload_name}" if cf_config.remote_dir else upload_name
    
    print(f"  upload: {sw.local_exe_path} -> s3://{cf_config.bucket_name}/{remote_key}")
    
    if dry_run:
        return
    
    # Read and upload file
    with sw.local_exe_path.open("rb") as f:
        file_content = f.read()
    
    response = s3.put_object(
        Bucket=cf_config.bucket_name,
        Key=remote_key,
        Body=file_content,
    )
    
    print(f"  Status: {response['ResponseMetadata']['HTTPStatusCode']}")
    print(f"  ETag: {response['ETag']}")


def _select_servers(servers: list[ServerConfig], only: Optional[set[str]]) -> list[ServerConfig]:
    if not only:
        return servers
    only_lower = {x.lower() for x in only}
    return [s for s in servers if s.name.lower() in only_lower]


def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Upload SkydimoSetup.exe to configured servers (FTP/SFTP/Cloudflare R2).")
    ap.add_argument("--config", default="config.json", help="Path to config.json")
    ap.add_argument("--dry-run", action="store_true", help="Do not rename/upload; only print actions")
    ap.add_argument("--only", help="Comma-separated server names to run (e.g. bt,langlangyun). Use 'none' to skip servers.")
    ap.add_argument("--no-cloudflare", action="store_true", help="Skip Cloudflare R2 upload")
    args = ap.parse_args(list(argv) if argv is not None else None)

    config_path = Path(args.config).expanduser().resolve()
    sw, servers, cloudflare_config = _load_config(config_path)

    if not sw.local_exe_path.exists():
        print(f"Local exe not found: {sw.local_exe_path}", file=sys.stderr)
        return 2

    product_version = get_exe_product_version(str(sw.local_exe_path)).strip()
    version_safe = _sanitize_version(product_version)
    try:
        upload_name = sw.upload_name_template.format(version=version_safe)
    except Exception as e:
        print(f"Invalid upload_name_template: {e}", file=sys.stderr)
        return 2

    # Select servers based on --only flag
    # Default: upload to all servers
    # If --only is specified, filter by names (or skip all if empty/none)
    if args.only is None:
        selected = servers
    else:
        only_names = set(x.strip().lower() for x in args.only.split(",") if x.strip())
        if "none" in only_names or not only_names:
            selected = []
        else:
            selected = _select_servers(servers, only_names)
    
    # Determine if Cloudflare should be used
    # Default: upload to Cloudflare if configured
    # Skip if --no-cloudflare is specified
    use_cloudflare = cloudflare_config is not None and not args.no_cloudflare
    
    if not selected and not use_cloudflare:
        print("No servers selected and Cloudflare is disabled/not configured.", file=sys.stderr)
        return 2

    print(f"Local exe: {sw.local_exe_path}")
    print(f"ProductVersion: {product_version}")
    print(f"Upload filename: {upload_name}")
    print(f"Dry run: {args.dry_run}")

    # Upload to traditional servers (FTP/SFTP)
    for server in selected:
        print(f"\n==> {server.name} ({server.type}) {server.host}:{server.port}  dir={server.remote_dir}")
        if server.type == "ftp":
            _deploy_to_ftp(server, sw, upload_name=upload_name, dry_run=args.dry_run)
        else:
            _deploy_to_sftp(server, sw, upload_name=upload_name, dry_run=args.dry_run)

    # Upload to Cloudflare R2
    if use_cloudflare:
        print(f"\n==> Cloudflare R2 (r2) bucket={cloudflare_config.bucket_name}  dir={cloudflare_config.remote_dir}")
        _deploy_to_cloudflare(cloudflare_config, sw, upload_name=upload_name, dry_run=args.dry_run)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
