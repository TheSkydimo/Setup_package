from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import runpy
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core.iss_utils import (
    compute_installer_output,
    extract_define_value_in_block,
    extract_inno_setup_value,
    find_iscc,
    find_newest_installer_fallback,
    replace_or_insert_define_in_block,
)
from core.sign_client import SignConfig, sign_file_inplace
from core.version_info import get_file_and_product_versions, normalize_three_part_version
from core.resources import get_resource_path


LogFn = Callable[[str], None]


@dataclass(frozen=True)
class PipelineArgs:
    # repo
    repo_root: Path

    # product/build
    product: str
    prod_define: str
    iss_block_macro: str
    iss_path: Path
    exe_path: Path | None
    iscc_path: Path | None
    no_compile: bool
    use_iss_copy: bool
    license_dir: Path | None
    installer_output_dir: Path | None

    # remote sign
    sign_server: str
    sign_api_key: str
    sign_user: str
    sign_password: str
    no_sign_exe: bool
    no_sign_installer: bool

    # 360 upload
    no_upload_360: bool
    upload_360_headless: bool
    q360_account: str
    q360_password: str
    q360_soft_name: str
    q360_remark: str
    q360_start_url: str
    q360_version: str

    # server upload (FTP/SFTP/Cloudflare R2) - per-platform control
    upload_config_path: str
    # Per-platform remote directory names
    upload_cloudflare_dir: str
    upload_langlangyun_dir: str
    upload_bt_dir: str
    # Enable flags
    upload_to_cloudflare: bool
    upload_to_langlangyun: bool
    upload_to_bt: bool


class _LogWriter:
    def __init__(self, log: LogFn):
        self._log = log
        self._buf = ""

    def write(self, s: str) -> int:
        if not s:
            return 0
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._log(line + "\n")
        return len(s)

    def flush(self) -> None:
        if self._buf:
            self._log(self._buf)
            self._buf = ""


def _resolve_360_script(args: PipelineArgs) -> Path:
    # Prefer embedded copy (packed into EXE), fallback to repo file.
    embedded = get_resource_path("assets/360_auto_upload.py")
    if embedded.is_file():
        return embedded
    return (args.repo_root / "360_auto_upload.py").resolve()


def _build_360_argv(args: PipelineArgs, installer_path: Path) -> list[str]:
    script_path = _resolve_360_script(args)
    argv = [str(script_path), "--installer", str(installer_path)]
    if args.q360_account:
        argv += ["--account", args.q360_account]
    if args.q360_password:
        argv += ["--password", args.q360_password]
    if args.q360_soft_name:
        argv += ["--soft-name", args.q360_soft_name]
    if args.q360_remark:
        argv += ["--remark", args.q360_remark]
    if args.q360_start_url:
        argv += ["--start-url", args.q360_start_url]
    if args.q360_version:
        argv += ["--version", args.q360_version]
    if args.upload_360_headless:
        argv.append("--headless")
    return argv


def _run_server_upload(args: PipelineArgs, installer_path: Path, log: LogFn) -> int:
    """Run updata_app.py to upload installer to configured servers."""
    from pathlib import Path as _P
    import json
    import tempfile
    
    # Determine which platforms to upload to
    upload_flags = []
    if args.upload_to_cloudflare:
        upload_flags.append("cloudflare")
    if args.upload_to_langlangyun:
        upload_flags.append("langlangyun")
    if args.upload_to_bt:
        upload_flags.append("bt")
    
    if not upload_flags:
        log("No upload targets selected.\n")
        return 0
    
    config_path = _P(args.upload_config_path).resolve() if args.upload_config_path else None
    if not config_path or not config_path.is_file():
        log(f"Upload config not found: {config_path}\n")
        return 2
    
    # Create temporary config with installer path (no modification to original)
    try:
        cfg_data = json.loads(config_path.read_text(encoding="utf-8"))
        if "software" not in cfg_data:
            cfg_data["software"] = {}
        # Dynamically set paths for this upload only
        cfg_data["software"]["local_exe_path"] = str(installer_path)
        cfg_data["software"]["upload_name_template"] = installer_path.name
        
        # Dynamically update remote_dir for each platform independently
        # Update Cloudflare R2 remote_dir
        if args.upload_to_cloudflare and args.upload_cloudflare_dir:
            if "cloudflare" in cfg_data and cfg_data["cloudflare"]:
                cfg_data["cloudflare"]["remote_dir"] = args.upload_cloudflare_dir
        
        # Update servers remote_dir individually
        if "servers" in cfg_data and isinstance(cfg_data["servers"], list):
            for server in cfg_data["servers"]:
                if not isinstance(server, dict) or "name" not in server:
                    continue
                
                server_name = server["name"].lower()
                new_dir_name = None
                
                # Determine which directory to use based on server name
                if server_name == "langlangyun" and args.upload_to_langlangyun and args.upload_langlangyun_dir:
                    new_dir_name = args.upload_langlangyun_dir
                elif server_name == "bt" and args.upload_to_bt and args.upload_bt_dir:
                    new_dir_name = args.upload_bt_dir
                
                # Update the remote_dir if we have a new directory name
                if new_dir_name:
                    old_dir = server.get("remote_dir", "")
                    if old_dir:
                        # Split path and replace last meaningful part
                        import posixpath
                        parts = [p for p in old_dir.strip("/").split("/") if p]
                        if parts:
                            parts[-1] = new_dir_name
                            server["remote_dir"] = "/" + "/".join(parts) + "/"
                        else:
                            server["remote_dir"] = "/" + new_dir_name + "/"
        
        # Write to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            tmp.write(json.dumps(cfg_data, ensure_ascii=False, indent=2))
            tmp_config_path = _P(tmp.name)
    except Exception as e:
        log(f"Failed to create temp upload config: {e}\n")
        return 2
    
    # Run updata_app.py with platform filters
    updata_script = _P(__file__).parent.parent / "updata_app.py"
    if not updata_script.is_file():
        log(f"updata_app.py not found: {updata_script}\n")
        return 2
    
    log(f"Running updata_app.py\n")
    log(f"Config: {config_path} (temp: {tmp_config_path})\n")
    log(f"Installer: {installer_path}\n")
    log(f"Upload targets: {', '.join(upload_flags)}\n")
    
    # Build command with platform filters
    argv = [str(updata_script), "--config", str(tmp_config_path)]
    
    # Handle Cloudflare separately (--no-cloudflare if not selected)
    if not args.upload_to_cloudflare:
        argv.append("--no-cloudflare")
    
    # Handle traditional servers (--only for specific servers)
    server_list = []
    if args.upload_to_langlangyun:
        server_list.append("langlangyun")
    if args.upload_to_bt:
        server_list.append("bt")
    
    if server_list:
        argv.extend(["--only", ",".join(server_list)])
    elif not args.upload_to_cloudflare:
        # If no cloudflare and no servers, skip all
        argv.extend(["--only", "none"])
    
    old_argv = sys.argv[:]
    old_out = sys.stdout
    old_err = sys.stderr
    try:
        sys.argv = argv[:]
        sys.stdout = _LogWriter(log)  # type: ignore[assignment]
        sys.stderr = _LogWriter(log)  # type: ignore[assignment]
        try:
            runpy.run_path(str(updata_script), run_name="__main__")
            return 0
        except SystemExit as e:
            code = int(e.code) if isinstance(e.code, int) else 0
            return code
    finally:
        try:
            if hasattr(sys.stdout, "flush"):
                sys.stdout.flush()
        except Exception:
            pass
        try:
            if hasattr(sys.stderr, "flush"):
                sys.stderr.flush()
        except Exception:
            pass
        sys.argv = old_argv
        sys.stdout = old_out
        sys.stderr = old_err
        # Cleanup temp file
        try:
            tmp_config_path.unlink()
        except Exception:
            pass


def _run_360_upload(args: PipelineArgs, installer_path: Path, log: LogFn) -> int:
    argv = _build_360_argv(args, installer_path)
    script = Path(argv[0]).resolve()
    if not script.is_file():
        raise FileNotFoundError(f"360 uploader script not found: {script}")

    log("360 uploader: " + str(script) + "\n")
    log("360 argv: " + " ".join(argv) + "\n")

    old_argv = sys.argv[:]
    old_out = sys.stdout
    old_err = sys.stderr
    try:
        sys.argv = argv[:]  # script expects argv[0] = script path
        sys.stdout = _LogWriter(log)  # type: ignore[assignment]
        sys.stderr = _LogWriter(log)  # type: ignore[assignment]
        try:
            runpy.run_path(str(script), run_name="__main__")
            return 0
        except SystemExit as e:
            code = int(e.code) if isinstance(e.code, int) else 0
            return code
    finally:
        try:
            if hasattr(sys.stdout, "flush"):
                sys.stdout.flush()
        except Exception:
            pass
        try:
            if hasattr(sys.stderr, "flush"):
                sys.stderr.flush()
        except Exception:
            pass
        sys.argv = old_argv
        sys.stdout = old_out
        sys.stderr = old_err


def _prepare_iss_copy(
    repo_root: Path,
    template_path: Path,
    iss_block_macro: str,
    license_dir: Path | None,
    installer_output_dir: Path | None,
) -> Path:
    """
    Create a temporary ISS copy to avoid modifying the original template.
    Also rewrites a few relative paths (OutputDir, Source_path, license file paths)
    into absolute paths so compiling from temp location remains correct.
    """
    repo_root = repo_root.resolve()
    template_path = template_path.resolve()
    if not template_path.is_file():
        # if user didn't provide, fall back to embedded template
        embedded = get_resource_path("assets/Unified.iss")
        if embedded.is_file():
            template_path = embedded
        else:
            raise FileNotFoundError(f"ISS not found: {template_path}")

    # IMPORTANT:
    # The template uses relative paths like "..\\License\\..." and "..\\APEX\\...".
    # In the original repo layout, these are relative to repo_root (ALL_EXE), not repo_root.parent.
    base = repo_root.resolve()
    lic_base = license_dir.resolve() if license_dir else (base / ".." / "License").resolve()
    txt = template_path.read_text(encoding="utf-8", errors="ignore")

    def to_win_abs(p: Path) -> str:
        return str(p.resolve())

    # OutputDir:
    # - If user provided an override (from GUI), force it.
    # - Otherwise, rewrite existing relative OutputDir to an absolute path (resolve relative to repo_root).
    if installer_output_dir:
        txt = _replace_single_setup_kv(txt, "OutputDir", to_win_abs(installer_output_dir))
    else:
        out_dir = None
        # lightweight parse: find first OutputDir=... line after [Setup]
        lines = txt.splitlines(keepends=True)
        in_setup = False
        for line in lines:
            s = line.strip()
            if s.lower() == "[setup]":
                in_setup = True
                continue
            if in_setup and s.startswith("[") and s.endswith("]"):
                break
            if in_setup and s.lower().startswith("outputdir="):
                raw = s.split("=", 1)[1].strip()
                out_dir = raw
                break
        if out_dir:
            abs_out = to_win_abs(base / Path(out_dir))
            txt = _replace_single_setup_kv(txt, "OutputDir", abs_out)

    # Rewrite common per-product defines to absolute paths (safe even when copy stays near original)
    # These are used by Unified.iss: Source_path, SetupLicenseFile, SetupLicenseCNFile
    txt = _replace_define_path_in_any_block(txt, "Source_path", base)
    # Force license files to resolve from configured license dir (or default)
    txt = _replace_define_path_in_any_block(txt, "SetupLicenseFile", lic_base)
    txt = _replace_define_path_in_any_block(txt, "SetupLicenseCNFile", lic_base)

    tmp_dir = Path(os.environ.get("TEMP") or str(repo_root / "可视化" / "build" / "tmp")).resolve() / "ALL_EXE_Launcher"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    tmp_path = tmp_dir / f"Unified_copy_{iss_block_macro}_{ts}.iss"
    tmp_path.write_text(txt, encoding="utf-8")
    return tmp_path


def _replace_single_setup_kv(text: str, key: str, value: str) -> str:
    # Replace first occurrence of key=value inside [Setup]; if missing, insert it.
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_setup = False
    replaced = False
    for line in lines:
        s = line.strip()
        if s.lower() == "[setup]":
            in_setup = True
            out.append(line)
            continue
        if in_setup and s.startswith("[") and s.endswith("]"):
            # leaving [Setup] section
            if not replaced:
                out.append(f"{key}={value}\n")
                replaced = True
            in_setup = False
        if in_setup and (not replaced) and s.lower().startswith(key.lower() + "="):
            prefix = line.split("=", 1)[0]
            out.append(f"{prefix}={value}\n")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        # no [Setup] section found; append a minimal one
        out.append("\n[Setup]\n")
        out.append(f"{key}={value}\n")
    return "".join(out)


def _replace_define_path_in_any_block(text: str, name: str, base: Path) -> str:
    """
    Replace #define NAME "..\\something" into absolute path based on `base` (usually repo_root.parent).
    """
    import re as _re

    def repl(m: "_re.Match[str]") -> str:
        raw = m.group(2)
        # handle ..\ relative paths
        p = raw
        if raw.startswith("..\\") or raw.startswith("../") or raw.startswith(".."):
            p = str((base / Path(raw)).resolve())
        return f'{m.group(1)}"{p}"'

    pat = _re.compile(rf'(?im)^([ \t]*#define[ \t]+{_re.escape(name)}[ \t]+)"([^"]+)"[ \t]*$')
    return pat.sub(repl, text)


def _update_iss_versions(mod, product_key: str, iss_block_macro: str, iss_path: Path, exe_path: Path, log: LogFn) -> None:
    if not exe_path.is_file():
        raise FileNotFoundError(f"EXE not found: {exe_path}")
    if not iss_path.is_file():
        raise FileNotFoundError(f"ISS not found: {iss_path}")

    versions = get_file_and_product_versions(str(exe_path))
    file_version_raw = versions.get("file")
    product_version_raw = versions.get("product")

    if product_version_raw:
        app_version = product_version_raw
    else:
        raw_ver = file_version_raw or ""
        app_version = normalize_three_part_version(raw_ver) or "1.0.0"

    log(
        f"Product: {product_key}\n"
        f"EXE: {exe_path}\n"
        f"  FileVersion: {file_version_raw}\n"
        f"  ProductVersion: {product_version_raw}\n"
        f"  => AppVersionFull: {app_version}\n"
        f"  => AppVersionFile: {file_version_raw}\n"
    )

    content = iss_path.read_text(encoding="utf-8", errors="ignore")
    content = replace_or_insert_define_in_block(content, iss_block_macro, "AppVersionFull", app_version)
    if file_version_raw:
        content = replace_or_insert_define_in_block(content, iss_block_macro, "AppVersionFile", file_version_raw)
    iss_path.write_text(content, encoding="utf-8")

def _subprocess_startupinfo_no_window() -> subprocess.STARTUPINFO | None:
    # Avoid popping a console window when running from a GUI-frozen app on Windows.
    if hasattr(subprocess, "STARTUPINFO") and hasattr(subprocess, "STARTF_USESHOWWINDOW"):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return si
    return None


def _decode_subprocess_output(b: bytes | None) -> str:
    if not b:
        return ""
    # Try utf-8 first; fallback to Windows ANSI codepage; always be loss-tolerant.
    try:
        return b.decode("utf-8")
    except Exception:
        try:
            return b.decode("mbcs", errors="replace")
        except Exception:
            return b.decode("utf-8", errors="replace")


def run_pipeline(args: PipelineArgs, log: LogFn, cancel: threading.Event) -> int:
    """
    Run the full pipeline in-process (no dependency on external python).
    Returns process-like exit code (0=success, non-zero=failure).
    """
    try:
        log(f"Repo: {args.repo_root}\n")
        if cancel.is_set():
            log("Cancelled.\n")
            return 130

        exe_path = args.exe_path
        if not exe_path:
            raise RuntimeError("EXE path is empty. Please configure EXE base dir + file name.")

        # Prepare ISS path (copy mode = do not modify original template)
        iss_template_path = args.iss_path
        iss_path = iss_template_path
        if args.use_iss_copy:
            iss_path = _prepare_iss_copy(
                repo_root=args.repo_root,
                template_path=iss_template_path,
                iss_block_macro=args.iss_block_macro,
                license_dir=args.license_dir,
                installer_output_dir=args.installer_output_dir,
            )
            log(f"Using ISS copy: {iss_path}\n")

        auto_user = os.environ.get("COMPUTERNAME") or ""
        effective_user = args.sign_user or auto_user
        password = args.sign_password if args.sign_password else None
        if args.sign_user and password is None:
            raise RuntimeError("Error: --sign-user provided but --sign-password missing (avoid interactive prompt).")

        sign_cfg = SignConfig(server=args.sign_server, api_key=args.sign_api_key, user=effective_user, password=password)

        # 1) Sign product EXE (in-place)
        if not args.no_sign_exe:
            if cancel.is_set():
                log("Cancelled.\n")
                return 130
            log("Step 1/4: Sign product EXE...\n")
            sign_file_inplace(sign_cfg, str(exe_path))
        else:
            log("Step 1/4: Skip signing product EXE.\n")

        # 2) Update iss version macros
        if cancel.is_set():
            log("Cancelled.\n")
            return 130
        log("Step 2/4: Update Unified.iss version macros...\n")
        _update_iss_versions(
            mod=None,
            product_key=args.product,
            iss_block_macro=args.iss_block_macro,
            iss_path=Path(iss_path),
            exe_path=Path(exe_path),
            log=log,
        )

        if args.no_compile and (not args.no_upload_360):
            raise RuntimeError("Error: 已勾选上传 360，但同时开启了“不编译”。上传 360 需要先编译生成安装包。")
        if args.no_sign_installer and (not args.no_upload_360):
            raise RuntimeError("Error: 已勾选上传 360，但同时开启了“不签名安装包”。为保证 360 提交成功，请先签名安装包。")

        if args.no_compile:
            log("Step 3/4: Skip compile (no-compile).\n")
            return 0

        # 3) Compile Unified.iss with /DPROD_XXX
        if cancel.is_set():
            log("Cancelled.\n")
            return 130
        log("Step 3/4: Compile installer (ISCC)...\n")
        iscc = find_iscc(str(args.iscc_path) if args.iscc_path else None)
        if not iscc:
            raise RuntimeError("Error: ISCC.exe not found. Install Inno Setup or set --iscc / ISCC_EXE.")
        cmd = [iscc, str(iss_path), f"/D{args.prod_define}"]
        log("ISCC: " + " ".join(cmd) + "\n")
        completed = subprocess.run(
            cmd,
            check=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=_subprocess_startupinfo_no_window(),
        )
        out_s = _decode_subprocess_output(completed.stdout)
        err_s = _decode_subprocess_output(completed.stderr)
        if out_s:
            log("\n[ISCC stdout]\n" + out_s + "\n")
        if err_s:
            log("\n[ISCC stderr]\n" + err_s + "\n")
        if completed.returncode != 0:
            log(f"\nISCC exit code: {completed.returncode}\n")
            return completed.returncode or 1

        # 4) Locate installer + sign (360 upload omitted here; can be embedded later)
        content = Path(iss_path).read_text(encoding="utf-8", errors="ignore")
        app_version_full = extract_define_value_in_block(content, args.iss_block_macro, "AppVersionFull")
        setup_output_base = extract_define_value_in_block(content, args.iss_block_macro, "SetupOutputBase") or ""
        if not app_version_full:
            raise RuntimeError("Error: cannot read AppVersionFull after updating .iss")

        installer_path = compute_installer_output(Path(iss_path), args.iss_block_macro, app_version_full)
        if not installer_path.is_file():
            fb = find_newest_installer_fallback(installer_path.parent, setup_output_base) if setup_output_base else None
            if fb and fb.is_file():
                installer_path = fb
        if not installer_path.is_file():
            raise FileNotFoundError(f"Error: installer not found after compile: {installer_path}")

        if not args.no_sign_installer:
            if cancel.is_set():
                log("Cancelled.\n")
                return 130
            log("Step 4/4: Sign installer EXE...\n")
            sign_file_inplace(sign_cfg, str(installer_path))
        else:
            log("Step 4/4: Skip signing installer.\n")

        # 5) Optional: upload to 360
        if not args.no_upload_360:
            if cancel.is_set():
                log("Cancelled.\n")
                return 130
            log("Step 5/6: Upload to 360...\n")
            code = _run_360_upload(args, installer_path, log)
            if code != 0:
                log(f"\n360 upload exit code: {code}\n")
                return code or 1

        # 6) Optional: upload to servers (FTP/SFTP/Cloudflare R2)
        if args.upload_to_cloudflare or args.upload_to_langlangyun or args.upload_to_bt:
            if cancel.is_set():
                log("Cancelled.\n")
                return 130
            log("Step 6/6: Upload to servers...\n")
            code = _run_server_upload(args, installer_path, log)
            if code != 0:
                log(f"\nServer upload exit code: {code}\n")
                return code or 1

        log("\nDone.\n")
        return 0
    except SystemExit as e:
        code = int(e.code) if isinstance(e.code, int) else 1
        log(f"\nExit: {code}\n")
        return code
    except Exception as e:
        log(f"\nError: {type(e).__name__}: {e}\n")
        return 1

