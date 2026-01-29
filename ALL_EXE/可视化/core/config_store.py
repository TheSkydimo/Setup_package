from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path


def app_base_dir() -> Path:
    """
    Return the directory where the app is located.
    - dev: folder containing this python package (可视化/core)
    - frozen (PyInstaller): folder containing the executable
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent  # .../可视化


def app_config_path(filename: str = "config_app.json") -> Path:
    """Config path next to the app (same folder as launcher GUI)."""
    return (app_base_dir() / filename).resolve()


def default_config_dir(app_name: str = "ALL_EXE_Launcher") -> Path:
    # Prefer stable per-user directories on Windows.
    for k in ("APPDATA", "LOCALAPPDATA"):
        v = os.environ.get(k)
        if v:
            return (Path(v) / app_name).resolve()

    # Fallback (still stable): derive from user home, instead of current working directory
    # (CWD may differ between launching via IDE vs double-clicking an exe).
    home = Path.home()
    roaming = home / "AppData" / "Roaming"
    if roaming.is_dir():
        return (roaming / app_name).resolve()
    return (home / f".{app_name}").resolve()


@dataclass
class ProductPreset:
    """
    产品 preset（用于下拉框/默认路径/ISCC define）。
    说明：
    - exe_base_dir_override 为空时，默认基础目录为 <repo_root 父目录>\\<exe_dir_name>
    - iss_block_macro/prod_define 一般相同（例如 PROD_SKYDIMO）
    - 上传目录和360参数可按产品配置，360参数为空时使用全局默认值
    """

    key: str  # e.g. SKYDIMO
    display: str  # shown in UI
    prod_define: str  # e.g. PROD_SKYDIMO (used as /DPROD_SKYDIMO)
    iss_block_macro: str  # e.g. PROD_SKYDIMO (used to locate #ifdef block)
    exe_dir_name: str  # e.g. Skydimo / AARGB / MageeLife / apex
    exe_file_name: str  # e.g. Skydimo.exe / AARGB.exe / MageeLife.exe / Apex Light.exe
    exe_base_dir_override: str = ""  # optional absolute base dir
    
    # 上传目录配置（按产品）
    upload_cloudflare_dir: str = ""  # e.g. skydimo-setup, 为空时自动生成
    upload_langlangyun_dir: str = ""  # e.g. skydimo-setup
    upload_bt_dir: str = ""  # e.g. skydimo-setup
    
    # 360 参数：全局固定（不随产品变化），因此不放在产品 preset 中


def default_products() -> list[ProductPreset]:
    return [
        ProductPreset(
            key="SKYDIMO",
            display="SKYDIMO",
            prod_define="PROD_SKYDIMO",
            iss_block_macro="PROD_SKYDIMO",
            exe_dir_name="Skydimo",
            exe_file_name="Skydimo.exe",
            upload_cloudflare_dir="skydimo-setup",
            upload_langlangyun_dir="skydimo-setup",
            upload_bt_dir="skydimo-setup",
        ),
        ProductPreset(
            key="AARGB",
            display="AARGB",
            prod_define="PROD_AARGB",
            iss_block_macro="PROD_AARGB",
            exe_dir_name="AARGB",
            exe_file_name="AARGB.exe",
            upload_cloudflare_dir="aargb-setup",
            upload_langlangyun_dir="aargb-setup",
            upload_bt_dir="aargb-setup",
        ),
        ProductPreset(
            key="MAGEELIFE",
            display="MAGEELIFE",
            prod_define="PROD_MAGEELIFE",
            iss_block_macro="PROD_MAGEELIFE",
            exe_dir_name="MageeLife",
            exe_file_name="MageeLife.exe",
            upload_cloudflare_dir="mageelife-setup",
            upload_langlangyun_dir="mageelife-setup",
            upload_bt_dir="mageelife-setup",
        ),
        ProductPreset(
            key="APEX",
            display="APEX",
            prod_define="PROD_APEX",
            iss_block_macro="PROD_APEX",
            exe_dir_name="apex",
            exe_file_name="Apex Light.exe",
            upload_cloudflare_dir="apex-setup",
            upload_langlangyun_dir="apex-setup",
            upload_bt_dir="apex-setup",
        ),
    ]


@dataclass
class LauncherConfig:
    # repo
    repo_root: str = ""

    # product/build
    product: str = "SKYDIMO"
    products: list[ProductPreset] = field(default_factory=default_products)
    iss_path: str = ""
    # EXE path is composed as: exe_base_dir + exe_rel_path (can be empty to use default mapping)
    exe_base_dir: str = ""
    exe_rel_path: str = ""
    iscc_path: str = ""
    no_compile: bool = False

    # installer output (optional override; empty = derived from Unified.iss [Setup] OutputDir)
    installer_output_dir: str = ""
    license_dir: str = ""

    # iss behavior
    use_iss_copy: bool = True

    # remote sign
    sign_server: str = "http://192.168.1.66:8099"
    sign_api_key: str = ""
    sign_user: str = ""
    sign_password: str = ""
    no_sign_exe: bool = False
    no_sign_installer: bool = False

    # 360 upload
    no_upload_360: bool = True
    upload_360_headless: bool = False
    # Defaults are embedded here to avoid reading external scripts at runtime.
    q360_account: str = "13570806357"
    q360_password: str = "ibtNp4f4f6UK3n2M1yCg"
    q360_soft_name: str = "Skydimo"
    q360_remark: str = "Skydimo安装包自动提交（含版本号、仅软件检测）。"
    q360_start_url: str = "https://i.360.cn/login?src=pcw_renzheng&tpl=client&destUrl=https%3A%2F%2Fopen.soft.360.cn%2F"
    q360_version: str = ""

    # server upload (FTP/SFTP/Cloudflare R2) - per-platform control
    upload_config_path: str = "config.json"
    # Per-platform remote directory names
    upload_cloudflare_dir: str = "skydimo-setup"
    upload_langlangyun_dir: str = "skydimo-setup"
    upload_bt_dir: str = "skydimo-setup"
    # Enable flags
    upload_to_cloudflare: bool = False
    upload_to_langlangyun: bool = False
    upload_to_bt: bool = False


def load_config(path: Path) -> LauncherConfig:
    if not path.is_file():
        return LauncherConfig()
    data = json.loads(path.read_text(encoding="utf-8"))
    cfg = LauncherConfig()
    # migrate products list (old config may not have it)
    raw_products = data.get("products")
    if isinstance(raw_products, list) and raw_products:
        presets: list[ProductPreset] = []
        for item in raw_products:
            if not isinstance(item, dict):
                continue
            try:
                presets.append(ProductPreset(**item))
            except Exception:
                # ignore malformed entries
                continue
        if presets:
            cfg.products = presets

    # If old config stored empty strings for embedded defaults, keep the embedded defaults instead.
    embedded_default_keys = {
        "q360_account",
        "q360_password",
        "q360_soft_name",
        "q360_remark",
        "q360_start_url",
    }

    for k, v in data.items():
        if k == "products":
            continue
        # 360 软件名固定为 Skydimo（大小写敏感），不允许被配置文件覆盖
        if k == "q360_soft_name":
            continue
        if k in embedded_default_keys and (v is None or v == ""):
            continue
        if hasattr(cfg, k):
            setattr(cfg, k, v)
    return cfg


def save_config(path: Path, cfg: LauncherConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(cfg), ensure_ascii=False, indent=2), encoding="utf-8")

