import os
import subprocess
import re
import sys
import pefile
import time
import win32api

# 脚本所在目录及项目根目录（脚本在 `<项目根>/Mageelife_Pack` 下）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

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
    oem_ver,
    version,
    app_version,
    file_version=None,
    product_version=None,
):
    """
    修改 Inno Setup 脚本中的 OEMVer / Ver / 版本相关定义。

    参数：
        - app_version     : 安装器显示用的版本号（MyAppVersion）
        - file_version    : 可执行文件 FileVersion（MyFileVersion）
        - product_version : 可执行文件 ProductVersion（MyProductVersion）
    """
    with open(file_path, "r", encoding='utf-8') as file:
        content = file.read()
    
    oem_ver_pattern = r'#define\s+OEMVer=\d+'
    version_pattern = r'#define\s+Ver=\d+'
    app_version_pattern = r'#define\s+MyAppVersion\s+"[^"]+"'
    file_version_pattern = r'#define\s+MyFileVersion\s+"[^"]+"'
    product_version_pattern = r'#define\s+MyProductVersion\s+"[^"]+"'

    content = re.sub(oem_ver_pattern, f'#define OEMVer={oem_ver}', content)
    content = re.sub(version_pattern, f'#define Ver={version}', content)
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

    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

def sign_file(file_path, timestamp_url, digest_algorithm):
    # signtool.exe 位于项目根目录
    signtool_path = os.path.join(PROJECT_ROOT, "signtool.exe")
    
    if not os.path.isfile(signtool_path):
        print(f"Error: signtool.exe not found at {signtool_path}")
        return False

    full_file_path = os.path.abspath(file_path)
    if not os.path.isfile(full_file_path):
        print(f"Error: {full_file_path} not found")
        return False

    command = [
        signtool_path, "sign", "/v", "/debug", "/as", "/fd", digest_algorithm,
        "/n", "Shenzhen Light Universe Technology Co., Ltd.",
        "/tr", timestamp_url, "/td", "sha256",
        "/d", "MageeLife Setup — PC Ambient Lighting Controller",
        "/du", "https://www.mageelife.com",
        full_file_path
    ]
    print(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
        print(result.stdout)
        print(result.stderr)
        return True
    except subprocess.TimeoutExpired:
        print("Error: signtool 执行超时（120s）。可能是网络不通或被防火墙/代理阻断。")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error: Command failed with exit status {e.returncode}")
        print(e.stdout)
        print(e.stderr)
        # 打印代理环境便于诊断
        proxy_http = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        proxy_https = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        if proxy_http or proxy_https:
            print(f"Proxy hints => HTTP_PROXY={proxy_http} HTTPS_PROXY={proxy_https}")
        return False

def sign_file_legacy(file_path, timestamp_url, digest_algorithm):
    """
    使用旧的 Authenticode 时间戳方式（/t），在某些网络或服务器不兼容 RFC3161 时作为降级方案。
    注意：/t 不使用 /td 参数。
    """
    # signtool.exe 位于项目根目录
    signtool_path = os.path.join(PROJECT_ROOT, "signtool.exe")
    if not os.path.isfile(signtool_path):
        print(f"Error: signtool.exe not found at {signtool_path}")
        return False
    full_file_path = os.path.abspath(file_path)
    if not os.path.isfile(full_file_path):
        print(f"Error: {full_file_path} not found")
        return False
    command = [
        signtool_path, "sign", "/v", "/debug", "/as", "/fd", digest_algorithm,
        "/n", "Shenzhen Light Universe Technology Co., Ltd.",
        "/t", timestamp_url,
        "/d", "MageeLife Setup — PC Ambient Lighting Controller",
        "/du", "https://www.mageelife.com",
        full_file_path
    ]
    print(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
        print(result.stdout)
        print(result.stderr)
        return True
    except subprocess.TimeoutExpired:
        print("Error: signtool 执行超时（120s）。可能是网络不通或被防火墙/代理阻断。")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error: Command failed with exit status {e.returncode}")
        print(e.stdout)
        print(e.stderr)
        proxy_http = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        proxy_https = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        if proxy_http or proxy_https:
            print(f"Proxy hints => HTTP_PROXY={proxy_http} HTTPS_PROXY={proxy_https}")
        return False

def try_sign_with_fallbacks(file_path, digest_algorithm, timestamp_urls, max_retries_per_url=2, retry_delay_seconds=2):
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
                    pass
        print(f"[签名] 服务器失败，切换到下一个: {url}")
    print("[签名] 所有时间戳服务器均失败。")
    return False

def try_sign_with_dual_fallbacks(file_path, digest_algorithm, rfc3161_urls, legacy_urls):
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

def load_last_product_name():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, "last_product_name.txt")
    if os.path.isfile(file_path):
        with open(file_path, "r") as file:
            return file.read().strip()
    return None

def save_product_name(product_name):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, "last_product_name.txt")
    with open(file_path, "w") as file:
        file.write(product_name)

def process_package(current_dir, timestamp_urls):
    """处理不同版本的打包流程"""
    # 配置不同版本的参数
    config = {
        # 可执行文件位于项目根目录下的 MageeLife 目录
        'exefullname': os.path.join(PROJECT_ROOT, "MageeLife", "MageeLife.exe"),
        'OEMVer': 1,
        'Ver_value': 1,
        'project_name': "MageeLife",
        # Inno Setup 脚本位于项目根目录下的 iss 目录
        'iss_file': os.path.join(PROJECT_ROOT, "iss", "MageeLife.iss"),
        'setup_filename': "MageeLifeSetup.exe"
    }
        
    print(f"将要对 {config['project_name']} 进行打包")
    print("需要等待三秒后进行软件签名...")
    time.sleep(3)
    print("开始给软件签名....")
    
    # 检查exe文件是否存在
    if not os.path.isfile(config['exefullname']):
        print(f"Error: {config['exefullname']} not found")
        return False
        
    # 获取版本号：
    #   - file_version_raw    : MageeLife.exe 的 FileVersion（属性页中的“文件版本”）
    #   - product_version_raw : MageeLife.exe 的 ProductVersion（属性页中的“产品版本”）
    versions = get_file_and_product_versions(config['exefullname'])
    file_version_raw = versions.get("file")
    product_version_raw = versions.get("product")

    # MyAppVersion：优先使用完整 ProductVersion 字符串（例如 2.0.2.r251201）
    # 否则退回为三段数字的短版本
    def _normalize_three(ver):
        if not ver:
            return ""
        v = re.sub(r"[^0-9.]", "", ver).strip(".")
        v = re.sub(r"\.+", ".", v)
        parts = [p for p in v.split(".") if p.isdigit()]
        if not parts:
            return ""
        parts = (parts + ["0", "0"])[:3]
        return ".".join(parts)

    if product_version_raw:
        MyApp_Version = product_version_raw
    else:
        raw_ver = file_version_raw or get_exe_version(config['exefullname'])
        MyApp_Version = _normalize_three(raw_ver) or "1.0.0"
    
    print(
        f"OEMVer: {config['OEMVer']}, "
        f"FileVersion: {file_version_raw}, "
        f"ProductVersion: {product_version_raw}, "
        f"MyAppVersion: {MyApp_Version}"
    )
    
    # 检查ISS文件是否存在
    if not os.path.isfile(config['iss_file']):
        print(f"Error: {config['iss_file']} not found")
        return False

    # 修改 Inno Setup 脚本文件
    modify_inno_setup_script(
        config['iss_file'],
        config['OEMVer'],
        config['Ver_value'],
        MyApp_Version,
        file_version=file_version_raw,
        product_version=product_version_raw,
    )

    # 设置安装包输出路径（项目根目录下的 Setup_package 目录）
    setupfullname = os.path.join(PROJECT_ROOT, "Setup_package", config['setup_filename'])

    # 签名应用程序
    print("Sign application with SHA256")
    _app_sign_ok = try_sign_with_dual_fallbacks(config['exefullname'], "SHA256", timestamp_urls['rfc3161'], timestamp_urls['legacy'])
    if not _app_sign_ok:
        return False

    print("The exe signature has been completed. Please generate the installation package before proceeding.")
    print(f"使用ISS文件: {config['iss_file']}")

    # 编译安装包
    inno_setup_path = "C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe"
    if not os.path.isfile(inno_setup_path):
        print(f"Error: ISCC.exe not found at {inno_setup_path}")
        return False
    print(f"开始编译安装包: {config['project_name']}")
    try:
        subprocess.run([inno_setup_path, config['iss_file']], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Inno Setup compilation failed with exit code {e.returncode}")
        return False

    # 签名安装包
    print("Sign setup with SHA256")
    if not os.path.isfile(setupfullname):
        print(f"Error: Setup file not found after compilation: {setupfullname}")
        return False
    _sign_ok = try_sign_with_dual_fallbacks(setupfullname, "SHA256", timestamp_urls['rfc3161'], timestamp_urls['legacy'])
    if not _sign_ok:
        return False
    
    return True

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    timestamp_urls = {
        "rfc3161": [
            "https://timestamp.digicert.com",                   # DigiCert RFC3161 (HTTPS)
            "http://timestamp.sectigo.com",                     # Sectigo/Comodo RFC3161
            "http://rfc3161timestamp.globalsign.com/advanced"   # GlobalSign RFC3161
        ],
        "legacy": [
            "http://timestamp.comodoca.com/authenticode",       # Sectigo/Comodo 旧版 Authenticode
            "http://timestamp.globalsign.com/scripts/timstamp.dll",
            "http://timestamp.verisign.com/scripts/timstamp.dll"
        ]
    }
    ok = process_package(current_dir, timestamp_urls)
    if ok:
        print("所有流程已完成。")
        sys.exit(0)
    else:
        print("流程失败，请查看上方错误信息。")
        sys.exit(1)
if __name__ == "__main__":
    main()