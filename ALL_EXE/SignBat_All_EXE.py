"""
一键打包/签名/更新版本号的构建脚本（Windows）。

本脚本主要做三件事：
- **读取 EXE 版本信息**（FileVersion / ProductVersion），用于生成安装包版本号；
- **修改统一的 Inno Setup 脚本**（`Unified.iss`）里某个产品的 ISPP 宏区块（`#ifdef PROD_XXX`）：
  - 写入 `AppVersionFull`（允许带后缀，如 `2.0.2.r251201`）
  - 写入 `AppVersionFile`（通常为四段数字版本）
- **调用 Inno Setup Compiler（ISCC.exe）编译生成安装包**，并可选对产物做远程签名（remote_sign_client）。

说明：
- 本仓库采用“统一脚本 + 多产品宏区块”的方式管理版本与输出名；因此更新版本时必须只改对应产品的 `#ifdef PROD_XXX` 区块，避免误伤其它产品。
"""

import os
import re
import sys
import shutil
import subprocess
import argparse
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
import pefile
import win32api
import platform

from remote_sign_client import sign_sync, SignError

# 脚本所在目录及项目根目录（脚本位于 `<项目根>/iss` 下）
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent


@dataclass(frozen=True)
class ProductConfig:
    key: str  # e.g. "APEX"
    prod_define: str  # e.g. "PROD_APEX"
    exe_relpath: str  # relative to PROJECT_ROOT


PRODUCTS: dict[str, ProductConfig] = {
    "SKYDIMO": ProductConfig(
        key="SKYDIMO",
        prod_define="PROD_SKYDIMO",
        exe_relpath=r"Skydimo\Skydimo.exe",
    ),
    "APEX": ProductConfig(
        key="APEX",
        prod_define="PROD_APEX",
        exe_relpath=r"APEX\Apex Light.exe",
    ),
    "MAGEELIFE": ProductConfig(
        key="MAGEELIFE",
        prod_define="PROD_MAGEELIFE",
        exe_relpath=r"MageeLife\MageeLife.exe",
    ),
    "AARGB": ProductConfig(
        key="AARGB",
        prod_define="PROD_AARGB",
        exe_relpath=r"AARGB\AARGB.exe",
    ),
}


def find_iscc(explicit_path: str | None = None) -> str | None:
    """
    定位 Inno Setup Compiler（ISCC.exe）。

    搜索优先级：
      1) 显式传入路径
      2) 环境变量 ISCC_EXE
      3) PATH 中的 ISCC / ISCC.exe
      4) 常见安装路径
    """
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


def compile_inno_setup_script(iscc_exe: str, iss_path: str) -> bool:
    """
    调用 ISCC.exe 编译指定的 .iss，输出由 .iss 的 [Setup] 里的 OutputDir/OutputBaseFilename 控制。
    """
    cmd = [iscc_exe, iss_path]
    print(f"ISCC: {' '.join(cmd)}")
    try:
        completed = subprocess.run(cmd, check=False)
        if completed.returncode != 0:
            print(f"Error: ISCC failed (exit code {completed.returncode})")
            return False
        return True
    except FileNotFoundError:
        print(f"Error: ISCC not found: {iscc_exe}")
        return False
    except Exception as e:
        print(f"Error: ISCC failed: {e}")
        return False

# ----------------------------
# Signing utilities (remote)
# ----------------------------
@dataclass(frozen=True)
class SignConfig:
    server: str
    api_key: str
    user: str
    password: str | None


def sign_file_inplace(cfg: SignConfig, target_path: str) -> None:
    """
    远程签名并“原地替换”目标文件（尽量原子化）。

    实现方式：
    - 先把签名结果写到同目录的临时文件：`<target>.signed_tmp`
    - 再用 `os.replace()` 替换原文件（Windows 上也更可靠）
    """
    p = Path(target_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {p}")

    tmp = p.with_suffix(p.suffix + ".signed_tmp")
    if tmp.exists():
        try:
            tmp.unlink()
        except Exception:
            pass

    try:
        sign_sync(cfg.server, cfg.api_key, cfg.user, str(p), str(tmp), cfg.password)
    except SignError as e:
        raise RuntimeError(f"Sign failed: {p.name}: {e}") from e

    os.replace(str(tmp), str(p))
    print(f"Signed (in-place): {p}")


def _find_ispp_ifdef_block_span(text: str, block_macro: str) -> tuple[int, int] | None:
    """
    在 ISPP 文本中查找某个宏区块的字符区间 `[start, end)`：

        #ifdef <block_macro>
          ...
        #endif

    处理嵌套：通过维护指令深度来正确匹配对应的 `#endif`。
    """
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


def _extract_ispp_define_value_in_block(text: str, block_macro: str, name: str) -> str | None:
    span = _find_ispp_ifdef_block_span(text, block_macro)
    if not span:
        return None
    start, end = span
    block = text[start:end]
    m = re.search(
        rf'(?im)^[ \t]*#define[ \t]+{re.escape(name)}[ \t]+"([^"]*)"[ \t]*$',
        block,
    )
    return m.group(1) if m else None


def _extract_inno_setup_value(text: str, section: str, key: str) -> str | None:
    """
    从 Inno Setup 的某个 section 中提取 `key=value`：

    示例：在 `[Setup]` 中读取 `OutputDir=...`

    说明：
    - 这是一个“够用就行”的轻量解析器
    - 不处理 include / 复杂语法
    """
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


def compute_installer_output_path(iss_path: str, product_key: str, app_version_full: str) -> Path:
    """
    根据 `Unified.iss` 计算安装包输出路径（期望值）。

    典型配置：
      - `[Setup] OutputDir=..\\Setup_package`
      - `OutputBaseFilename={#SetupOutputBase}{#AppVersionFull}`

    我们据此推导最终安装包 `.exe` 的完整路径，便于后续查找/签名/上传。
    """
    iss_p = Path(iss_path).resolve()
    content = iss_p.read_text(encoding="utf-8")

    out_dir_raw = _extract_inno_setup_value(content, "Setup", "OutputDir") or ""
    if not out_dir_raw:
        raise RuntimeError("Cannot find [Setup] OutputDir in .iss")

    setup_output_base = _extract_ispp_define_value_in_block(content, "PROD_" + product_key, "SetupOutputBase")
    if not setup_output_base:
        raise RuntimeError(f"Cannot find #define SetupOutputBase in PROD_{product_key} block")

    # OutputDir is relative to .iss location
    out_dir = (iss_p.parent / Path(out_dir_raw)).resolve()
    filename = f"{setup_output_base}{app_version_full}.exe"
    return out_dir / filename


def find_newest_installer_fallback(output_dir: Path, setup_output_base: str) -> Path | None:
    if not output_dir.is_dir():
        return None
    candidates = list(output_dir.glob(f"{setup_output_base}*.exe"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


# 版本信息相关工具
def _read_string_file_info_versions(file_path):
    """
    使用 pefile 读取 StringFileInfo 中的 ProductVersion / FileVersion。

    返回字典，可能包含：
        - "ProductVersion"
        - "FileVersion"
    任意键不存在时不会出现在结果中。
    """
    result = {}
    try:
        pe = pefile.PE(file_path)
        try:
            if hasattr(pe, "FileInfo"):
                for fi in pe.FileInfo:
                    for entry in fi:
                        try:
                            key = getattr(entry, "Key", b"")
                            key_str = key.decode(errors="ignore") if isinstance(key, (bytes, bytearray)) else str(key)
                        except Exception:
                            key_str = ""
                        if key_str == "StringFileInfo":
                            for st in getattr(entry, "StringTable", []) or []:
                                try:
                                    d = {
                                        (k.decode(errors="ignore") if isinstance(k, (bytes, bytearray)) else str(k)):
                                        (v.decode(errors="ignore") if isinstance(v, (bytes, bytearray)) else str(v))
                                        for k, v in st.entries.items()
                                    }
                                except Exception:
                                    d = {}

                                for key_name in ("ProductVersion", "FileVersion"):
                                    if key_name in d and key_name not in result:
                                        result[key_name] = d[key_name]
        finally:
            try:
                pe.close()
            except Exception:
                pass
    except Exception:
        pass
    return result


def get_exe_version(file_path):
    """
    获取 EXE 的“主版本号”字符串。

    1) 优先返回 Win32 FileVersion（数值型）
    2) 回退到 StringFileInfo 中的 ProductVersion / FileVersion
    """
    # 1) Win32 文件版本（更稳定）
    try:
        info = win32api.GetFileVersionInfo(file_path, "\\")
        ms = info["FileVersionMS"]
        ls = info["FileVersionLS"]
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except Exception:
        pass

    # 2) 回退到 pefile 读取 StringFileInfo
    versions = _read_string_file_info_versions(file_path)
    return versions.get("ProductVersion") or versions.get("FileVersion")


def get_file_and_product_versions(file_path):
    """
    同时获取“文件版本(FileVersion)”和“产品版本(ProductVersion)”。

    返回结构：
        {"file": <FileVersion 或 None>, "product": <ProductVersion 或 None>}
    """
    file_version = None
    product_version = None

    # 1) Win32 数值型版本
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

    # 2) 字符串版本补充（可获取到带后缀的完整 ProductVersion，如 2.0.2.r251201）
    string_versions = _read_string_file_info_versions(file_path)
    # ProductVersion 优先使用字符串值
    if "ProductVersion" in string_versions:
        product_version = string_versions["ProductVersion"]
    # FileVersion 在 Win32 不存在时用字符串补充
    if not file_version and "FileVersion" in string_versions:
        file_version = string_versions["FileVersion"]

    return {"file": file_version, "product": product_version}


def modify_inno_setup_script(
    file_path,
    app_version,
    file_version=None,
    product_version=None,
    product_key: str | None = None,
):
    """
    修改 Inno Setup 脚本中的版本相关定义。

    参数：
        - app_version  : 写入到 AppVersionFull（通常等于 ProductVersion，可带后缀）
        - file_version : 写入到 AppVersionFile（通常为四段 FileVersion）
        - product_version : 保留参数位（目前不写入 iss，供日志展示/未来扩展）
    """
    with open(file_path, "r", encoding='utf-8') as file:
        content = file.read()

    def _replace_or_insert_define_in_ispp_block(text: str, block_macro: str, name: str, value: str) -> str:
        """
        只在指定的 ISPP 宏区块中替换/插入定义：

        - 目标形态：`#define <name> "<value>"`
        - 作用范围：仅限 `#ifdef <block_macro> ... #endif` 区间

        这样可以避免在“统一脚本”里误改其它产品的版本定义。
        """
        span = _find_ispp_ifdef_block_span(text, block_macro)
        if not span:
            raise RuntimeError(f"Cannot find ISPP block: #ifdef {block_macro}")

        start, end = span
        block = text[start:end]

        pattern = re.compile(rf'(?im)^[ \t]*#define[ \t]+{re.escape(name)}[ \t]+"[^"]*"[ \t]*$')
        replacement = f'#define {name} "{value}"'

        if pattern.search(block):
            block2 = pattern.sub(replacement, block)
        else:
            # Insert right after the #ifdef line
            m = re.search(r"(?im)^\s*#ifdef\s+.+\s*$\r?\n?", block)
            insert_at = m.end() if m else 0
            block2 = block[:insert_at] + replacement + "\n" + block[insert_at:]

        return text[:start] + block2 + text[end:]

    if not product_key:
        raise ValueError("product_key is required")

    # Unified.iss: each product has its own #ifdef PROD_XXX block.
    # We only update the selected product block's AppVersionFull/AppVersionFile.
    # (This script intentionally no longer supports updating legacy per-product .iss files.)
    content = _replace_or_insert_define_in_ispp_block(content, "PROD_" + product_key, "AppVersionFull", app_version)
    if file_version:
        content = _replace_or_insert_define_in_ispp_block(content, "PROD_" + product_key, "AppVersionFile", file_version)

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content)


def normalize_three_part_version(ver: str) -> str:
    """
    将输入版本号（可能带后缀）归一化成三段数字：X.Y.Z
    例：'2.0.2.r251201' -> '2.0.2'
    """
    if not ver:
        return ""
    v = re.sub(r"[^0-9.]", "", str(ver)).strip(".")
    v = re.sub(r"\.+", ".", v)
    parts = [p for p in v.split(".") if p.isdigit()]
    if not parts:
        return ""
    parts = (parts + ["0", "0"])[:3]
    return ".".join(parts)


def update_apex_iss_versions() -> bool:
    raise RuntimeError("Deprecated. Use update_product_versions() instead.")


def update_product_versions(product_key: str, iss_path: str, exe_path: str) -> bool:
    """
    Read version info from the product EXE, then update Unified.iss within:
      #ifdef PROD_<PRODUCT_KEY>
        #define AppVersionFull "..."
        #define AppVersionFile "..."
      #endif
    """
    if product_key not in PRODUCTS:
        print(f"Error: Unsupported product: {product_key}")
        return False

    if not os.path.isfile(exe_path):
        print(f"Error: EXE not found: {exe_path}")
        return False
    if not os.path.isfile(iss_path):
        print(f"Error: ISS not found: {iss_path}")
        return False

    versions = get_file_and_product_versions(exe_path)
    file_version_raw = versions.get("file")
    product_version_raw = versions.get("product")

    if product_version_raw:
        app_version = product_version_raw
    else:
        raw_ver = file_version_raw or get_exe_version(exe_path)
        app_version = normalize_three_part_version(raw_ver) or "1.0.0"

    print(
        f"Product: {product_key}\n"
        f"EXE: {exe_path}\n"
        f"  FileVersion: {file_version_raw}\n"
        f"  ProductVersion: {product_version_raw}\n"
        f"  => AppVersionFull: {app_version}\n"
        f"  => AppVersionFile: {file_version_raw}"
    )

    modify_inno_setup_script(
        iss_path,
        app_version,
        file_version=file_version_raw,
        product_version=product_version_raw,
        product_key=product_key,
    )
    print(f"Updated: {iss_path}")
    return True

def main():
    parser = argparse.ArgumentParser(
        description="Sign product EXE, update Unified.iss version macros from it, compile installer with ISCC (/DPROD_XXX), then sign the installer."
    )
    parser.add_argument(
        "--product",
        choices=sorted(PRODUCTS.keys()),
        required=True,
        help="Which product to build (controls EXE path + /DPROD_XXX + which block in Unified.iss to update).",
    )
    parser.add_argument(
        "--iss",
        default=str(SCRIPT_DIR / "Unified.iss"),
        help="Path to Unified.iss (defaults to ./Unified.iss).",
    )
    parser.add_argument(
        "--exe",
        default=None,
        help="Override EXE path (otherwise uses built-in product mapping).",
    )
    parser.add_argument(
        "--no-compile",
        action="store_true",
        help="Only update the .iss file; do not compile via ISCC.",
    )
    parser.add_argument(
        "--iscc",
        default=None,
        help=r"Path to ISCC.exe (optional). You may also set env var ISCC_EXE.",
    )
    parser.add_argument(
        "--sign-server",
        default=os.environ.get("SIGN_SERVER", "http://192.168.1.66:8099"),
        help="Remote sign server, e.g. http://192.168.1.10:8099 (or env SIGN_SERVER).",
    )
    parser.add_argument(
        "--sign-api-key",
        default=os.environ.get("SIGN_API_KEY", ""),
        help="API key header x-api-key (or env SIGN_API_KEY).",
    )
    parser.add_argument(
        "--sign-user",
        default=os.environ.get("SIGN_USER", ""),
        help="User header x-user + optional HTTP basic auth (or env SIGN_USER).",
    )
    parser.add_argument(
        "--sign-password",
        default=os.environ.get("SIGN_PASSWORD", ""),
        help="Password for HTTP basic auth (or env SIGN_PASSWORD).",
    )
    parser.add_argument(
        "--no-sign-exe",
        action="store_true",
        help="Do not sign the product EXE before building installer.",
    )
    parser.add_argument(
        "--no-sign-installer",
        action="store_true",
        help="Do not sign the generated installer EXE.",
    )
    parser.add_argument(
        "--no-upload-360",
        action="store_true",
        help="Do not upload to 360 after signing installer (default is upload).",
    )
    parser.add_argument(
        "--upload-360-headless",
        action="store_true",
        help="Run 360 upload in headless Chrome (passed to 360_auto_upload.py). Ignored if --no-upload-360.",
    )
    parser.add_argument(
        "--q360-account",
        default=os.environ.get("Q360_ACCOUNT", ""),
        help="360 account for auto upload (or env Q360_ACCOUNT).",
    )
    parser.add_argument(
        "--q360-password",
        default=os.environ.get("Q360_PASSWORD", ""),
        help="360 password for auto upload (or env Q360_PASSWORD).",
    )
    parser.add_argument(
        "--q360-soft-name",
        default=os.environ.get("Q360_SOFT_NAME", ""),
        help="Visible software name in 360 dropdown (or env Q360_SOFT_NAME).",
    )
    parser.add_argument(
        "--q360-remark",
        default=os.environ.get("Q360_REMARK", ""),
        help="Remark text when submitting to 360 (or env Q360_REMARK).",
    )
    parser.add_argument(
        "--q360-start-url",
        default=os.environ.get("Q360_START_URL", ""),
        help="Override 360 login start URL (or env Q360_START_URL).",
    )
    parser.add_argument(
        "--q360-version",
        default=os.environ.get("Q360_VERSION", ""),
        help="Override 360 submit version string (or env Q360_VERSION).",
    )

    args = parser.parse_args()

    cfg = PRODUCTS[args.product]
    exe_path = args.exe or str(PROJECT_ROOT / Path(cfg.exe_relpath))
    iss_path = args.iss

    # Build SignConfig
    auto_user = os.environ.get("COMPUTERNAME") or platform.node() or ""
    effective_user = args.sign_user or auto_user
    password: str | None = args.sign_password if args.sign_password else None
    if args.sign_user and password is None:
        raise SystemExit("Error: --sign-user provided but --sign-password missing (avoid interactive prompt).")
    sign_cfg = SignConfig(server=args.sign_server, api_key=args.sign_api_key, user=effective_user, password=password)

    # 1) Sign product EXE (in-place)
    if not args.no_sign_exe:
        sign_file_inplace(sign_cfg, exe_path)

    ok = update_product_versions(args.product, iss_path=iss_path, exe_path=exe_path)
    if not ok:
        sys.exit(1)

    if args.no_compile:
        sys.exit(0)

    # Compile Unified.iss with the chosen product define
    iscc = find_iscc(args.iscc)
    if not iscc:
        print(
            "Error: ISCC.exe not found.\n"
            "Install Inno Setup, or provide ISCC path via:\n"
            "  - --iscc \"C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe\"\n"
            "  - or set env var ISCC_EXE\n"
            "You can also skip compiling with --no-compile."
        )
        sys.exit(2)

    # Add /DPROD_XXX
    cmd = [iscc, iss_path, f"/D{cfg.prod_define}"]
    print(f"ISCC: {' '.join(cmd)}")
    completed = subprocess.run(cmd, check=False)
    ok = completed.returncode == 0
    if not ok:
        sys.exit(1)

    # 2) Sign installer EXE (in-place) and keep it in OutputDir
    if not args.no_sign_installer:
        # We recompute AppVersionFull by reading it from updated iss (product block)
        content = Path(iss_path).read_text(encoding="utf-8")
        app_version_full = _extract_ispp_define_value_in_block(content, "PROD_" + args.product, "AppVersionFull")
        setup_output_base = _extract_ispp_define_value_in_block(content, "PROD_" + args.product, "SetupOutputBase") or ""
        if not app_version_full:
            raise SystemExit("Error: cannot read AppVersionFull after updating .iss")

        installer_path = compute_installer_output_path(iss_path, args.product, app_version_full)
        if not installer_path.is_file():
            fb = find_newest_installer_fallback(installer_path.parent, setup_output_base) if setup_output_base else None
            if fb and fb.is_file():
                installer_path = fb
        if not installer_path.is_file():
            raise SystemExit(f"Error: installer not found after compile: {installer_path}")

        sign_file_inplace(sign_cfg, str(installer_path))

    # 3) Default: upload to 360 after installer is signed (can be disabled via --no-upload-360)
    if not args.no_upload_360:
        if "installer_path" not in locals():
            raise SystemExit("Error: 360 upload requires installer build/sign step. Remove --no-compile and --no-sign-installer, or use --no-upload-360.")
        upload_script = (SCRIPT_DIR / "360_auto_upload.py").resolve()
        if not upload_script.is_file():
            raise SystemExit(f"Error: 360 upload script not found: {upload_script}")

        cmd = [
            sys.executable,
            str(upload_script),
            "--installer",
            str(installer_path),
        ]
        if args.q360_account:
            cmd += ["--account", args.q360_account]
        if args.q360_password:
            cmd += ["--password", args.q360_password]
        if args.q360_soft_name:
            cmd += ["--soft-name", args.q360_soft_name]
        if args.q360_remark:
            cmd += ["--remark", args.q360_remark]
        if args.q360_start_url:
            cmd += ["--start-url", args.q360_start_url]
        if args.q360_version:
            cmd += ["--version", args.q360_version]
        if args.upload_360_headless:
            cmd.append("--headless")
        print(f"360 Upload: {' '.join(cmd)}")
        completed2 = subprocess.run(cmd, check=False)
        if completed2.returncode != 0:
            raise SystemExit(f"Error: 360 upload failed (exit code {completed2.returncode})")

    sys.exit(0)
if __name__ == "__main__":
    main()