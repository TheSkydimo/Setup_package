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

#获得程序版本号（优先 Win32 文件版本，回退 PE StringFileInfo）
def get_exe_version(file_path):
    # 1) Win32 文件版本（更稳定）
    try:
        info = win32api.GetFileVersionInfo(file_path, "\\")
        ms = info["FileVersionMS"]; ls = info["FileVersionLS"]
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except Exception:
        pass
    # 2) 回退到 pefile 读取 StringFileInfo
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
                                v = d.get("ProductVersion") or d.get("FileVersion") or None
                                if v:
                                    return v
        finally:
            try:
                pe.close()
            except Exception:
                pass
    except Exception:
        pass
    return None

def modify_inno_setup_script(file_path, oem_ver, version, app_version):
    with open(file_path, "r", encoding='utf-8') as file:
        content = file.read()
    
    oem_ver_pattern = r'#define OEMVer=\d'
    version_pattern = r'#define Ver=\d+'
    app_version_pattern = r'#define MyAppVersion "\d+(?:\.\d+){2,3}"'

    content = re.sub(oem_ver_pattern, f'#define OEMVer={oem_ver}', content)
    content = re.sub(version_pattern, f'#define Ver={version}', content)
    content = re.sub(app_version_pattern, f'#define MyAppVersion "{app_version}"', content)

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
        
    # 获取版本号（仅取前三段，不足三段补 0）
    raw_ver = get_exe_version(config['exefullname'])
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
    MyApp_Version = _normalize_three(raw_ver) or "1.0.0"
    
    print(f"OEMVer: {config['OEMVer']}, Version: {MyApp_Version}")
    
    # 检查ISS文件是否存在
    if not os.path.isfile(config['iss_file']):
        print(f"Error: {config['iss_file']} not found")
        return False

    # 修改 Inno Setup 脚本文件
    modify_inno_setup_script(config['iss_file'], config['OEMVer'], config['Ver_value'], MyApp_Version)

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