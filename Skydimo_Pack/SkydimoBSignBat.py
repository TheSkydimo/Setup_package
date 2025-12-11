import os
import re
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Optional

import pefile
import win32api


# 脚本所在目录及项目根目录（脚本在 `<项目根>/Skydimo_Pack` 下）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)


# =========================
# 配置常量（高内聚集中管理）
# =========================

COMPANY_NAME = "Shenzhen Light Universe Technology Co., Ltd."
PRODUCT_DESC = "Skydimo Setup — PC Ambient Lighting Controller"
PRODUCT_URL = "https://skydimo.com"
PRODUCT_URL_LEGACY = "https://www.skydimo.com"

SIGNTOOL_EXE = os.path.join(PROJECT_ROOT, "signtool.exe")
INNO_SETUP_COMPILER = r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"

DEFAULT_PROJECT_NAME = "Skydimo"
DEFAULT_EXE_PATH = os.path.join(PROJECT_ROOT, DEFAULT_PROJECT_NAME, f"{DEFAULT_PROJECT_NAME}.exe")
DEFAULT_ISS_PATH = os.path.join(PROJECT_ROOT, "iss", f"{DEFAULT_PROJECT_NAME}.iss")
DEFAULT_SETUP_DIR = os.path.join(PROJECT_ROOT, "Setup_package")
DEFAULT_SETUP_FILENAME = "SkydimoSetup.exe"

DEFAULT_OEM_VER = 1
DEFAULT_VER_VALUE = 1

# 默认时间戳服务器配置
DEFAULT_TIMESTAMP_URLS: Dict[str, List[str]] = {
    "rfc3161": [
        "https://timestamp.digicert.com",                   # DigiCert RFC3161 (HTTPS)
        "http://timestamp.sectigo.com",                     # Sectigo/Comodo RFC3161
        "http://rfc3161timestamp.globalsign.com/advanced",  # GlobalSign RFC3161
    ],
    "legacy": [
        "http://timestamp.comodoca.com/authenticode",       # Sectigo/Comodo 旧版 Authenticode
        "http://timestamp.globalsign.com/scripts/timstamp.dll",
        "http://timestamp.verisign.com/scripts/timstamp.dll",
    ],
}


# =========================
# 通用小工具函数
# =========================

def _print_proxy_hints() -> None:
    """打印代理配置，方便排查网络导致的签名失败问题。"""
    proxy_http = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    proxy_https = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy_http or proxy_https:
        print(f"Proxy hints => HTTP_PROXY={proxy_http} HTTPS_PROXY={proxy_https}")


def _ensure_file_exists(path: str, desc: str) -> bool:
    """检查文件是否存在，不存在则打印统一错误信息。"""
    if not os.path.isfile(path):
        print(f"Error: {desc} not found at {path}")
        return False
    return True


def normalize_version_three_segments(ver: Optional[str]) -> str:
    """
    只保留版本号中的前三段数字，不足三段补 0。
    例如:
        "1.2"           -> "1.2.0"
        "1.2.3.4"       -> "1.2.3"
        "v1.2.3-beta"   -> "1.2.3"
    """
    if not ver:
        return ""

    v = re.sub(r"[^0-9.]", "", ver).strip(".")
    v = re.sub(r"\.+", ".", v)
    parts = [p for p in v.split(".") if p.isdigit()]
    if not parts:
        return ""
    parts = (parts + ["0", "0"])[:3]
    return ".".join(parts)


# =========================
# 版本信息相关
# =========================

def _read_string_file_info_versions(file_path: str) -> Dict[str, str]:
    """
    使用 pefile 读取 StringFileInfo 中的 ProductVersion / FileVersion。

    返回字典，可能包含：
        - "ProductVersion"
        - "FileVersion"
    任意键不存在时不会出现在结果中。
    """
    result: Dict[str, str] = {}
    try:
        pe = pefile.PE(file_path)
        try:
            if hasattr(pe, "FileInfo"):
                for fi in pe.FileInfo:
                    for entry in fi:
                        try:
                            key = getattr(entry, "Key", b"")
                            key_str = (
                                key.decode(errors="ignore")
                                if isinstance(key, (bytes, bytearray))
                                else str(key)
                            )
                        except Exception:
                            key_str = ""

                        if key_str == "StringFileInfo":
                            for st in getattr(entry, "StringTable", []) or []:
                                try:
                                    d = {
                                        (
                                            k.decode(errors="ignore")
                                            if isinstance(k, (bytes, bytearray))
                                            else str(k)
                                        ): (
                                            v.decode(errors="ignore")
                                            if isinstance(v, (bytes, bytearray))
                                            else str(v)
                                        )
                                        for k, v in st.entries.items()
                                    }
                                except Exception:
                                    d = {}

                                # 只在尚未获取到对应值时写入，避免覆盖更“权威”的来源
                                for key_name in ("ProductVersion", "FileVersion"):
                                    if key_name in d and key_name not in result:
                                        result[key_name] = d[key_name]
        finally:
            try:
                pe.close()
            except Exception:
                pass
    except Exception:
        # 读取失败直接返回当前结果（可能为空）
        pass
    return result


def get_exe_version(file_path: str) -> Optional[str]:
    """
    获取 EXE 的“主版本号”字符串。

    兼容旧逻辑：
    1) 优先返回 Win32 FileVersion（数值型）
    2) 回退到 StringFileInfo 中的 ProductVersion / FileVersion
    """
    # 1. Win32 文件版本
    try:
        info = win32api.GetFileVersionInfo(file_path, "\\")
        ms = info["FileVersionMS"]
        ls = info["FileVersionLS"]
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except Exception:
        pass

    # 2. StringFileInfo
    versions = _read_string_file_info_versions(file_path)
    return versions.get("ProductVersion") or versions.get("FileVersion")


def get_file_and_product_versions(file_path: str) -> Dict[str, Optional[str]]:
    """
    同时获取“文件版本(FileVersion)”和“产品版本(ProductVersion)”。

    返回结构：
        {"file": <FileVersion 或 None>, "product": <ProductVersion 或 None>}
    """
    file_version: Optional[str] = None
    product_version: Optional[str] = None

    # 1. Win32 数值型版本（如果资源里设置了 ProductVersionMS / ProductVersionLS 也一并读取）
    try:
        info = win32api.GetFileVersionInfo(file_path, "\\")

        # FileVersion
        ms = info.get("FileVersionMS")
        ls = info.get("FileVersionLS")
        if ms is not None and ls is not None:
            file_version = f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"

        # ProductVersion（可能不存在）
        p_ms = info.get("ProductVersionMS")
        p_ls = info.get("ProductVersionLS")
        if p_ms is not None and p_ls is not None:
            product_version = f"{p_ms >> 16}.{p_ms & 0xFFFF}.{p_ls >> 16}.{p_ls & 0xFFFF}"
    except Exception:
        pass

    # 2. 字符串版本补充（可获取到带后缀的完整 ProductVersion，如 2.0.2.6e4c602）
    string_versions = _read_string_file_info_versions(file_path)
    # ProductVersion 优先使用字符串值（这样才能拿到 2.0.2.6e4c602 这种完整版本）
    if "ProductVersion" in string_versions:
        product_version = string_versions["ProductVersion"]
    # FileVersion 只有在 Win32 数值型不存在时，才用字符串值补充
    if not file_version and "FileVersion" in string_versions:
        file_version = string_versions["FileVersion"]

    return {"file": file_version, "product": product_version}


# =========================
# Inno Setup 脚本处理
# =========================

def modify_inno_setup_script(
    file_path: str,
    oem_ver: int,
    version: int,
    app_version: str,
    file_version: Optional[str] = None,
    product_version: Optional[str] = None,
) -> None:
    """
    修改 Inno Setup 脚本中的 OEMVer / Ver / 版本相关定义。

    参数：
        - app_version     : 安装器显示用的短版本号（MyAppVersion）
        - file_version    : 可执行文件 FileVersion（MyFileVersion）
        - product_version : 可执行文件 ProductVersion（MyProductVersion）

    使用相对宽松的正则，避免版本位数变更导致替换失败。
    """
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    oem_ver_pattern = r'#define\s+OEMVer=\d+'
    version_pattern = r'#define\s+Ver=\d+'
    app_version_pattern = r'#define\s+MyAppVersion\s+"[^"]+"'
    file_version_pattern = r'#define\s+MyFileVersion\s+"[^"]+"'
    product_version_pattern = r'#define\s+MyProductVersion\s+"[^"]+"'

    content = re.sub(oem_ver_pattern, f"#define OEMVer={oem_ver}", content)
    content = re.sub(version_pattern, f"#define Ver={version}", content)
    content = re.sub(app_version_pattern, f'#define MyAppVersion "{app_version}"', content)

    if file_version:
        content = re.sub(
            file_version_pattern,
            f'#define MyFileVersion "{file_version}"',
            content,
        )

    if product_version:
        content = re.sub(
            product_version_pattern,
            f'#define MyProductVersion "{product_version}"',
            content,
        )

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content)


# =========================
# 签名相关逻辑
# =========================

def _build_common_signtool_args(digest_algorithm: str) -> List[str]:
    """构建 signtool 通用参数部分（除时间戳相关之外）。"""
    return [
        SIGNTOOL_EXE,
        "sign",
        "/v",
        "/debug",
        "/as",
        "/fd",
        digest_algorithm,
        "/n",
        COMPANY_NAME,
    ]


def _run_signtool(command: List[str]) -> bool:
    """调用 signtool 并统一处理输出与错误。"""
    print(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        print(result.stdout)
        print(result.stderr)
        return True
    except subprocess.TimeoutExpired:
        print("Error: signtool 执行超时（120s）。可能是网络不通或被防火墙/代理阻断。")
        _print_proxy_hints()
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error: Command failed with exit status {e.returncode}")
        print(e.stdout)
        print(e.stderr)
        _print_proxy_hints()
        return False


def sign_file(file_path: str, timestamp_url: str, digest_algorithm: str) -> bool:
    """使用 RFC3161 (/tr,/td) 方式对文件进行签名。"""
    if not _ensure_file_exists(SIGNTOOL_EXE, "signtool.exe"):
        return False

    full_file_path = os.path.abspath(file_path)
    if not _ensure_file_exists(full_file_path, "target file"):
        return False

    command = _build_common_signtool_args(digest_algorithm) + [
        "/tr",
        timestamp_url,
        "/td",
        "sha256",
        "/d",
        PRODUCT_DESC,
        "/du",
        PRODUCT_URL,
        full_file_path,
    ]
    return _run_signtool(command)


def sign_file_legacy(file_path: str, timestamp_url: str, digest_algorithm: str) -> bool:
    """
    使用旧的 Authenticode 时间戳方式（/t），在某些网络或服务器不兼容 RFC3161 时作为降级方案。
    注意：/t 不使用 /td 参数。
    """
    if not _ensure_file_exists(SIGNTOOL_EXE, "signtool.exe"):
        return False

    full_file_path = os.path.abspath(file_path)
    if not _ensure_file_exists(full_file_path, "target file"):
        return False

    command = _build_common_signtool_args(digest_algorithm) + [
        "/t",
        timestamp_url,
        "/d",
        PRODUCT_DESC,
        "/du",
        PRODUCT_URL_LEGACY,
        full_file_path,
    ]
    return _run_signtool(command)


def try_sign_with_fallbacks(
    file_path: str,
    digest_algorithm: str,
    timestamp_urls: Iterable[str],
    max_retries_per_url: int = 2,
    retry_delay_seconds: int = 2,
) -> bool:
    """
    依次尝试多个 RFC3161 时间戳服务器；每个服务器失败时会重试若干次。
    任一服务器签名成功则返回 True；全部失败返回 False。
    """
    for url in timestamp_urls:
        for attempt in range(1, max_retries_per_url + 1):
            print(f"[签名] 使用时间戳服务器: {url} (尝试 {attempt}/{max_retries_per_url})")
            ok = sign_file(file_path, url, digest_algorithm)
            if ok:
                return True
            if attempt < max_retries_per_url:
                print(f"[签名] 将在 {retry_delay_seconds}s 后重试该服务器...")
                try:
                    time.sleep(retry_delay_seconds)
                except Exception:
                    # 即使 sleep 失败也不影响后续重试逻辑
                    pass
        print(f"[签名] 服务器失败，切换到下一个: {url}")
    print("[签名] 所有时间戳服务器均失败。")
    return False


def try_sign_with_dual_fallbacks(
    file_path: str,
    digest_algorithm: str,
    rfc3161_urls: Iterable[str],
    legacy_urls: Iterable[str],
) -> bool:
    """
    先尝试 RFC3161（/tr,/td），全部失败后降级到 Authenticode 旧方式（/t）。
    """
    print("[签名] 优先使用 RFC3161 时间戳方式...")
    if try_sign_with_fallbacks(file_path, digest_algorithm, rfc3161_urls):
        return True

    print("[签名] RFC3161 全部失败，开始尝试旧的 Authenticode 时间戳方式...")
    for url in legacy_urls:
        print(f"[签名] 使用旧方式时间戳服务器: {url}")
        if sign_file_legacy(file_path, url, digest_algorithm):
            return True
    print("[签名] 旧方式时间戳也失败。")
    return False


# =========================
# 简单的状态记忆（目前未在流程中使用，保留以便扩展）
# =========================

def load_last_product_name() -> Optional[str]:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, "last_product_name.txt")
    if os.path.isfile(file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read().strip()
    return None


def save_product_name(product_name: str) -> None:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, "last_product_name.txt")
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(product_name)


# =========================
# 打包主流程（核心业务逻辑）
# =========================

def process_package(timestamp_urls: Dict[str, Iterable[str]]) -> bool:
    """
    主打包流程：
    1. 读取 EXE 版本并标准化
    2. 修改 Inno Setup 脚本
    3. 对 EXE 进行签名
    4. 编译安装包
    5. 对安装包进行签名
    """
    config = {
        "exefullname": DEFAULT_EXE_PATH,
        "OEMVer": DEFAULT_OEM_VER,
        "Ver_value": DEFAULT_VER_VALUE,
        "project_name": DEFAULT_PROJECT_NAME,
        "iss_file": DEFAULT_ISS_PATH,
        "setup_filename": DEFAULT_SETUP_FILENAME,
    }

    print(f"将要对 {config['project_name']} 进行打包")
    print("需要等待三秒后进行软件签名...")
    time.sleep(3)
    print("开始给软件签名....")

    # 检查 exe 文件是否存在
    if not _ensure_file_exists(config["exefullname"], "exe file"):
        return False

    # 获取版本号：
    #   - file_version_raw    : Skydimo.exe 的 FileVersion（属性页中的“文件版本”）
    #   - product_version_raw : Skydimo.exe 的 ProductVersion（属性页中的“产品版本”）
    versions = get_file_and_product_versions(config["exefullname"])
    file_version_raw = versions.get("file")
    product_version_raw = versions.get("product")

    # MyAppVersion：如果有 ProductVersion 字符串，则直接使用完整字符串
    #   例如 2.0.2.6e4c602
    # 否则退回旧逻辑，使用三段数字的短版本号
    if product_version_raw:
        app_version = product_version_raw
    else:
        base_version = file_version_raw or get_exe_version(config["exefullname"])
        app_version = normalize_version_three_segments(base_version) or "1.0.0"

    print(
        f"OEMVer: {config['OEMVer']}, "
        f"FileVersion: {file_version_raw}, "
        f"ProductVersion: {product_version_raw}, "
        f"MyAppVersion: {app_version}"
    )

    # 检查 ISS 文件是否存在
    if not _ensure_file_exists(config["iss_file"], "ISS file"):
        return False

    # 修改 Inno Setup 脚本文件
    modify_inno_setup_script(
        file_path=config["iss_file"],
        oem_ver=config["OEMVer"],
        version=config["Ver_value"],
        app_version=app_version,
        file_version=file_version_raw,
        product_version=product_version_raw,
    )

    # 设置安装包输出路径（项目根目录下的 Setup_package 目录）
    setupfullname = os.path.join(DEFAULT_SETUP_DIR, config["setup_filename"])

    # 签名应用程序
    print("Sign application with SHA256")
    app_sign_ok = try_sign_with_dual_fallbacks(
        config["exefullname"],
        "SHA256",
        timestamp_urls["rfc3161"],
        timestamp_urls["legacy"],
    )
    if not app_sign_ok:
        return False

    print("The exe signature has been completed. Please generate the installation package before proceeding.")
    print(f"使用ISS文件: {config['iss_file']}")

    # 编译安装包
    if not _ensure_file_exists(INNO_SETUP_COMPILER, "ISCC.exe"):
        return False

    print(f"开始编译安装包: {config['project_name']}")
    try:
        subprocess.run([INNO_SETUP_COMPILER, config["iss_file"]], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Inno Setup compilation failed with exit code {e.returncode}")
        return False

    # 签名安装包
    print("Sign setup with SHA256")
    if not _ensure_file_exists(setupfullname, "Setup file after compilation"):
        return False

    setup_sign_ok = try_sign_with_dual_fallbacks(
        setupfullname,
        "SHA256",
        timestamp_urls["rfc3161"],
        timestamp_urls["legacy"],
    )
    if not setup_sign_ok:
        return False

    return True


def main() -> None:
    ok = process_package(DEFAULT_TIMESTAMP_URLS)
    if ok:
        print("所有流程已完成。")
        sys.exit(0)
    else:
        print("流程失败，请查看上方错误信息。")
        sys.exit(1)


if __name__ == "__main__":
    main()