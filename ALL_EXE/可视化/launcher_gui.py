from __future__ import annotations

import contextlib
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from tkinter import ttk
import tkinter.scrolledtext
import re

from core.config_store import LauncherConfig, ProductPreset, app_config_path, load_config, save_config
from core.pipeline import PipelineArgs, run_pipeline
from core.repo_locator import find_repo_root
from core.stream import QueueLogSink, QueueWriter


class ToolTip:
    """创建一个 tooltip 用于显示提示信息"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)
    
    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                        background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                        font=("微软雅黑", 9))
        label.pack(ipadx=5, ipady=3)
    
    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None
    
    def update_text(self, text):
        """更新提示文本"""
        self.text = text


# ---- PyInstaller hidden-import nudges (so dynamically-loaded scripts still work) ----
def _pyinstaller_hiddenimports() -> None:
    try:
        import pefile  # noqa: F401
        import win32api  # noqa: F401
        import pywintypes  # noqa: F401
        import pythoncom  # noqa: F401
        import win32timezone  # noqa: F401
        import requests  # noqa: F401
    except Exception:
        pass
    try:
        import selenium  # noqa: F401
        import webdriver_manager  # noqa: F401
    except Exception:
        pass


APP_TITLE = "ALL_EXE 可视化启动器"


def _extract_inno_setup_value(text: str, section: str, key: str) -> str | None:
    """
    Minimal parser: read `key=value` inside `[section]`.
    Enough for OutputDir from Unified.iss.
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


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1020x760")
        self.minsize(920, 680)

        # Config is stored next to the app (portable): config_app.json
        self._cfg_path = app_config_path("config_app.json")
        self._cfg = self._load_or_migrate_cfg(self._cfg_path)

        self._log_q: "queue.Queue[str]" = queue.Queue()
        self._cancel = threading.Event()
        self._worker: threading.Thread | None = None
        self._save_after_id: str | None = None
        self._setting_defaults = False
        self._exe_manual_override = False
        self._product_presets: list[ProductPreset] = []

        # Auto-detect repo root when config is empty
        if not self._cfg.repo_root:
            rr = find_repo_root(Path(__file__).resolve().parent)
            if rr:
                self._cfg.repo_root = str(rr)

        self._build_ui()
        self._load_cfg_into_ui()
        self._refresh_product_presets()
        self._refresh_product_combobox()
        self._infer_exe_manual_override_from_loaded_cfg()
        self._bind_auto_save()
        self._auto_fill_defaults()
        self._auto_update_upload_dirs()  # Auto-set upload dirs based on current product
        self._update_exe_computed_labels()
        self.after(100, self._poll_log_queue)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _load_or_migrate_cfg(self, target_path: Path) -> LauncherConfig:
        """
        Load config from `target_path`.
        If it's missing or looks like a fresh/empty config, try migrating from legacy locations:
        - %APPDATA%\\ALL_EXE_Launcher\\config.json (old default)
        - <app_dir>\\config.json (older portable name)
        """
        # Important: in frozen builds we may have embedded defaults like iss_path pointing into _MEI...
        # Treat config as "empty" if it doesn't have a repo_root (that's the critical user-provided anchor).
        def looks_empty(c: LauncherConfig) -> bool:
            return not (c.repo_root or "").strip()

        cfg = load_config(target_path)
        # If target exists AND has a repo_root, trust it.
        if target_path.is_file() and not looks_empty(cfg):
            return cfg

        # Try legacy locations
        legacy_paths: list[Path] = []
        try:
            from core.config_store import default_config_dir

            legacy_paths.append((default_config_dir() / "config.json").resolve())
        except Exception:
            pass
        try:
            legacy_paths.append(app_config_path("config.json"))
        except Exception:
            pass

        for lp in legacy_paths:
            if not lp.is_file():
                continue
            migrated = load_config(lp)
            if looks_empty(migrated):
                continue
            # Always overwrite an empty target with migrated data.
            save_config(target_path, migrated)
            return migrated

        # Nothing to migrate; ensure a file exists for visibility
        if not target_path.is_file():
            save_config(target_path, cfg)
        return cfg

    # ---------------- UI ----------------
    def _build_ui(self) -> None:
        pad = 10
        outer = ttk.Frame(self, padding=pad)
        outer.pack(fill=tk.BOTH, expand=True)

        top = ttk.LabelFrame(outer, text="仓库定位", padding=pad)
        top.pack(fill=tk.X)

        self.var_repo_root = tk.StringVar()
        ttk.Label(top, text="仓库根目录：").grid(row=0, column=0, sticky="w")
        self.ent_repo_root = ttk.Entry(top, textvariable=self.var_repo_root)
        self.ent_repo_root.grid(row=0, column=1, sticky="we", padx=(0, 8))
        ttk.Button(top, text="浏览...", command=self._browse_repo_root).grid(row=0, column=2, sticky="e")
        ttk.Button(top, text="自动查找", command=self._auto_find_repo_root).grid(row=0, column=3, sticky="e", padx=(8, 0))
        top.columnconfigure(1, weight=1)

        # Show actual config path (helps diagnose "settings lost" issues)
        self.var_cfg_path = tk.StringVar(value=str(self._cfg_path))
        ttk.Label(top, text="配置文件：").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(top, textvariable=self.var_cfg_path, state="readonly").grid(
            row=1, column=1, columnspan=3, sticky="we", pady=(6, 0)
        )

        mid = ttk.Frame(outer)
        mid.pack(fill=tk.BOTH, expand=True, pady=(pad, 0))
        mid.columnconfigure(0, weight=1)
        mid.columnconfigure(1, weight=1)

        lf_build = ttk.LabelFrame(mid, text="一键流水线（签名 → 更新版本 → 编译 → 签名安装包 → 可选上传 360）", padding=pad)
        lf_build.grid(row=0, column=0, sticky="nsew", padx=(0, pad))
        lf_sign = ttk.LabelFrame(mid, text="签名/服务配置", padding=pad)
        lf_sign.grid(row=0, column=1, sticky="nsew")

        mid.rowconfigure(0, weight=0)
        mid.rowconfigure(1, weight=1)

        # --- Build options ---
        self.var_product = tk.StringVar()
        self.var_iss_path = tk.StringVar()
        self.var_installer_out_dir = tk.StringVar()
        self.var_license_dir = tk.StringVar()
        self.var_exe_base_dir = tk.StringVar()
        self.var_exe_rel_path = tk.StringVar()
        self.var_iscc_path = tk.StringVar()

        self.var_no_compile = tk.BooleanVar()
        self.var_no_sign_exe = tk.BooleanVar()
        self.var_no_sign_installer = tk.BooleanVar()
        self.var_upload_360 = tk.BooleanVar()
        self.var_upload_360_headless = tk.BooleanVar()
        self.var_use_iss_copy = tk.BooleanVar()
        
        # Per-platform upload control
        self.var_upload_config_path = tk.StringVar()
        # Per-platform remote directories
        self.var_upload_cloudflare_dir = tk.StringVar()
        self.var_upload_langlangyun_dir = tk.StringVar()
        self.var_upload_bt_dir = tk.StringVar()
        # Enable flags
        self.var_upload_to_cloudflare = tk.BooleanVar()
        self.var_upload_to_langlangyun = tk.BooleanVar()
        self.var_upload_to_bt = tk.BooleanVar()

        r = 0
        ttk.Label(lf_build, text="设备：").grid(row=r, column=0, sticky="w")
        # 设备下拉框 + 设备管理按钮放在一个子容器里，避免与 Unified.iss 的布局冲突
        prod_box = ttk.Frame(lf_build)
        prod_box.grid(row=r, column=1, sticky="w", padx=(0, 8))
        self.cmb_product = ttk.Combobox(prod_box, textvariable=self.var_product, values=[], state="readonly", width=14)
        self.cmb_product.pack(side=tk.LEFT)
        ttk.Button(prod_box, text="设备管理...", command=self._open_product_manager).pack(side=tk.LEFT, padx=(8, 0))

        ttk.Label(lf_build, text="Unified.iss：").grid(row=r, column=2, sticky="e")
        self.ent_iss = ttk.Entry(lf_build, textvariable=self.var_iss_path)
        self.ent_iss.grid(row=r, column=3, sticky="we", padx=(8, 8))
        ttk.Button(lf_build, text="浏览...", command=self._browse_iss).grid(row=r, column=4, sticky="e")
        lf_build.columnconfigure(3, weight=1)

        r += 1
        ttk.Label(lf_build, text="安装包输出目录：").grid(row=r, column=0, sticky="w")
        self.ent_installer_out = ttk.Entry(lf_build, textvariable=self.var_installer_out_dir)
        self.ent_installer_out.grid(row=r, column=1, columnspan=3, sticky="we", padx=(0, 8))
        ttk.Button(lf_build, text="浏览...", command=self._browse_installer_out_dir).grid(row=r, column=4, sticky="e")

        r += 1
        ttk.Label(lf_build, text="License 目录：").grid(row=r, column=0, sticky="w")
        self.ent_license_dir = ttk.Entry(lf_build, textvariable=self.var_license_dir)
        self.ent_license_dir.grid(row=r, column=1, columnspan=3, sticky="we", padx=(0, 8))
        ttk.Button(lf_build, text="浏览...", command=self._browse_license_dir).grid(row=r, column=4, sticky="e")

        r += 1
        self.chk_use_iss_copy = ttk.Checkbutton(
            lf_build,
            text="不修改原 ISS（使用临时副本编译）",
            variable=self.var_use_iss_copy,
        )
        self.chk_use_iss_copy.grid(row=r, column=0, columnspan=5, sticky="w")

        r += 1
        ttk.Label(lf_build, text="EXE 基础目录：").grid(row=r, column=0, sticky="w")
        self.ent_exe_base = ttk.Entry(lf_build, textvariable=self.var_exe_base_dir)
        self.ent_exe_base.grid(row=r, column=1, columnspan=3, sticky="we", padx=(0, 8))
        ttk.Button(lf_build, text="浏览...", command=self._browse_exe_base_dir).grid(row=r, column=4, sticky="e")

        r += 1
        ttk.Label(lf_build, text="EXE 相对路径：").grid(row=r, column=0, sticky="w")
        self.ent_exe_rel = ttk.Entry(lf_build, textvariable=self.var_exe_rel_path)
        self.ent_exe_rel.grid(row=r, column=1, columnspan=3, sticky="we", padx=(0, 8))
        ttk.Button(lf_build, text="选择 EXE...", command=self._pick_exe_and_split).grid(row=r, column=4, sticky="e")

        r += 1
        self.var_exe_full = tk.StringVar()
        self.var_exe_dir = tk.StringVar()
        ttk.Label(lf_build, text="拼接后 EXE：").grid(row=r, column=0, sticky="w")
        ttk.Label(lf_build, textvariable=self.var_exe_full).grid(row=r, column=1, columnspan=4, sticky="w")
        r += 1
        ttk.Label(lf_build, text="目标目录：").grid(row=r, column=0, sticky="w")
        ttk.Label(lf_build, textvariable=self.var_exe_dir).grid(row=r, column=1, columnspan=4, sticky="w")

        r += 1
        ttk.Label(lf_build, text="ISCC.exe（可空）：").grid(row=r, column=0, sticky="w")
        self.ent_iscc = ttk.Entry(lf_build, textvariable=self.var_iscc_path)
        self.ent_iscc.grid(row=r, column=1, columnspan=3, sticky="we", padx=(0, 8))
        ttk.Button(lf_build, text="浏览...", command=self._browse_iscc).grid(row=r, column=4, sticky="e")

        r += 1
        self.chk_no_sign_exe = ttk.Checkbutton(lf_build, text="不签名产品 EXE（--no-sign-exe）", variable=self.var_no_sign_exe, command=self._sync_enabled_states)
        self.chk_no_sign_exe.grid(row=r, column=0, columnspan=2, sticky="w")
        self.chk_no_compile = ttk.Checkbutton(lf_build, text="不编译（--no-compile）", variable=self.var_no_compile, command=self._sync_enabled_states)
        self.chk_no_compile.grid(row=r, column=2, columnspan=2, sticky="w")

        r += 1
        self.chk_no_sign_installer = ttk.Checkbutton(lf_build, text="不签名安装包（--no-sign-installer）", variable=self.var_no_sign_installer, command=self._sync_enabled_states)
        self.chk_no_sign_installer.grid(row=r, column=0, columnspan=2, sticky="w")
        self.chk_upload_360 = ttk.Checkbutton(lf_build, text="上传 360（默认关）", variable=self.var_upload_360, command=self._sync_enabled_states)
        self.chk_upload_360.grid(row=r, column=2, columnspan=2, sticky="w")

        r += 1
        self.chk_upload_360_headless = ttk.Checkbutton(lf_build, text="360 无头 Chrome（--upload-360-headless）", variable=self.var_upload_360_headless)
        self.chk_upload_360_headless.grid(row=r, column=2, columnspan=3, sticky="w")

        r += 1
        sep = ttk.Separator(lf_build, orient="horizontal")
        sep.grid(row=r, column=0, columnspan=5, sticky="we", pady=(6, 6))

        # 360 fields
        r += 1
        ttk.Label(lf_build, text="360 参数：").grid(row=r, column=0, sticky="w")
        ttk.Button(lf_build, text="填入默认值", command=self._fill_360_defaults).grid(row=r, column=4, sticky="e")

        r += 1
        self.var_q360_account = tk.StringVar()
        self.var_q360_password = tk.StringVar()
        self.var_q360_soft_name = tk.StringVar()
        self.var_q360_remark = tk.StringVar()
        self.var_q360_start_url = tk.StringVar()
        self.var_q360_version = tk.StringVar()

        ttk.Label(lf_build, text="360 账号：").grid(row=r, column=0, sticky="w")
        self.ent_q360_account = ttk.Entry(lf_build, textvariable=self.var_q360_account)
        self.ent_q360_account.grid(row=r, column=1, sticky="we", padx=(0, 8))
        ttk.Label(lf_build, text="360 密码：").grid(row=r, column=2, sticky="e")
        self.ent_q360_password = ttk.Entry(lf_build, textvariable=self.var_q360_password, show="*")
        self.ent_q360_password.grid(row=r, column=3, sticky="we", padx=(8, 0))

        r += 1
        ttk.Label(lf_build, text="360 软件名（固定）：").grid(row=r, column=0, sticky="w")
        self.ent_q360_soft_name = ttk.Entry(lf_build, textvariable=self.var_q360_soft_name, state="readonly")
        self.ent_q360_soft_name.grid(row=r, column=1, sticky="we", padx=(0, 8))
        ttk.Label(lf_build, text="360 版本覆盖：").grid(row=r, column=2, sticky="e")
        self.ent_q360_version = ttk.Entry(lf_build, textvariable=self.var_q360_version)
        self.ent_q360_version.grid(row=r, column=3, sticky="we", padx=(8, 0))

        r += 1
        ttk.Label(lf_build, text="360 Remark：").grid(row=r, column=0, sticky="w")
        self.ent_q360_remark = ttk.Entry(lf_build, textvariable=self.var_q360_remark)
        self.ent_q360_remark.grid(row=r, column=1, columnspan=3, sticky="we", padx=(0, 0))

        r += 1
        ttk.Label(lf_build, text="360 Start URL：").grid(row=r, column=0, sticky="w")
        self.ent_q360_start_url = ttk.Entry(lf_build, textvariable=self.var_q360_start_url)
        self.ent_q360_start_url.grid(row=r, column=1, columnspan=3, sticky="we")

        # --- Sign/server config ---
        self.var_sign_server = tk.StringVar()
        self.var_sign_api_key = tk.StringVar()
        self.var_sign_user = tk.StringVar()
        self.var_sign_password = tk.StringVar()

        rs = 0
        ttk.Label(lf_sign, text="Sign Server：").grid(row=rs, column=0, sticky="w")
        ttk.Entry(lf_sign, textvariable=self.var_sign_server).grid(row=rs, column=1, sticky="we")
        rs += 1
        ttk.Label(lf_sign, text="API Key（可空）：").grid(row=rs, column=0, sticky="w")
        ttk.Entry(lf_sign, textvariable=self.var_sign_api_key, show="*").grid(row=rs, column=1, sticky="we")
        rs += 1
        ttk.Label(lf_sign, text="User（可空）：").grid(row=rs, column=0, sticky="w")
        ttk.Entry(lf_sign, textvariable=self.var_sign_user).grid(row=rs, column=1, sticky="we")
        rs += 1
        ttk.Label(lf_sign, text="Password（可空）：").grid(row=rs, column=0, sticky="w")
        ttk.Entry(lf_sign, textvariable=self.var_sign_password, show="*").grid(row=rs, column=1, sticky="we")
        
        rs += 1
        sep2 = ttk.Separator(lf_sign, orient="horizontal")
        sep2.grid(row=rs, column=0, columnspan=2, sticky="we", pady=(10, 10))
        
        # Upload to servers section
        rs += 1
        ttk.Label(lf_sign, text="上传到服务器（默认关）", font=("", 9, "bold")).grid(row=rs, column=0, columnspan=2, sticky="w")
        
        rs += 1
        ttk.Label(lf_sign, text="配置文件：").grid(row=rs, column=0, sticky="w")
        self.ent_upload_config = ttk.Entry(lf_sign, textvariable=self.var_upload_config_path)
        self.ent_upload_config.grid(row=rs, column=1, sticky="we")
        self.tooltip_upload_config = ToolTip(self.ent_upload_config, "上传配置文件完整路径")
        rs += 1
        ttk.Button(lf_sign, text="浏览配置...", command=self._browse_upload_config).grid(row=rs, column=0, columnspan=2, sticky="we", pady=(2, 8))
        
        # Cloudflare R2
        rs += 1
        self.chk_upload_cloudflare = ttk.Checkbutton(lf_sign, text="☐ 上传到 Cloudflare R2", variable=self.var_upload_to_cloudflare, command=self._sync_enabled_states)
        self.chk_upload_cloudflare.grid(row=rs, column=0, columnspan=2, sticky="w")
        rs += 1
        ttk.Label(lf_sign, text="  目录：", font=("", 8)).grid(row=rs, column=0, sticky="w")
        self.ent_cloudflare_dir = ttk.Entry(lf_sign, textvariable=self.var_upload_cloudflare_dir, font=("", 8))
        self.ent_cloudflare_dir.grid(row=rs, column=1, sticky="we", pady=(0, 4))
        self.tooltip_cloudflare = ToolTip(self.ent_cloudflare_dir, "Cloudflare R2 目录")
        
        # langlangyun
        rs += 1
        self.chk_upload_langlangyun = ttk.Checkbutton(lf_sign, text="☐ 上传到 langlangyun", variable=self.var_upload_to_langlangyun, command=self._sync_enabled_states)
        self.chk_upload_langlangyun.grid(row=rs, column=0, columnspan=2, sticky="w")
        rs += 1
        ttk.Label(lf_sign, text="  目录：", font=("", 8)).grid(row=rs, column=0, sticky="w")
        self.ent_langlangyun_dir = ttk.Entry(lf_sign, textvariable=self.var_upload_langlangyun_dir, font=("", 8))
        self.ent_langlangyun_dir.grid(row=rs, column=1, sticky="we", pady=(0, 4))
        self.tooltip_langlangyun = ToolTip(self.ent_langlangyun_dir, "/var/www/files/目录名/")
        
        # bt
        rs += 1
        self.chk_upload_bt = ttk.Checkbutton(lf_sign, text="☐ 上传到 bt", variable=self.var_upload_to_bt, command=self._sync_enabled_states)
        self.chk_upload_bt.grid(row=rs, column=0, columnspan=2, sticky="w")
        rs += 1
        ttk.Label(lf_sign, text="  目录：", font=("", 8)).grid(row=rs, column=0, sticky="w")
        self.ent_bt_dir = ttk.Entry(lf_sign, textvariable=self.var_upload_bt_dir, font=("", 8))
        self.ent_bt_dir.grid(row=rs, column=1, sticky="we", pady=(0, 8))
        self.tooltip_bt = ToolTip(self.ent_bt_dir, "/www/wwwroot/cn3-dl.skydimo.com/目录名/")
        
        rs += 1
        ttk.Button(lf_sign, text="全选 / 取消全选", command=self._toggle_all_upload_platforms).grid(row=rs, column=0, columnspan=2, sticky="we", pady=(8, 0))
        
        lf_sign.columnconfigure(1, weight=1)

        # Buttons + log
        bottom = ttk.LabelFrame(outer, text="日志", padding=pad)
        bottom.pack(fill=tk.BOTH, expand=True, pady=(pad, 0))

        btns = ttk.Frame(bottom)
        btns.pack(fill=tk.X)
        self.btn_run = ttk.Button(btns, text="开始执行", command=self._on_run)
        self.btn_run.pack(side=tk.LEFT)
        self.btn_cancel = ttk.Button(btns, text="取消（尽力）", command=self._on_cancel, state=tk.DISABLED)
        self.btn_cancel.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(btns, text="保存配置", command=self._save_ui_into_cfg).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(btns, text="清空日志", command=self._clear_log).pack(side=tk.RIGHT)

        self.txt_log = tkinter.scrolledtext.ScrolledText(bottom, height=18, wrap="word")
        self.txt_log.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self.txt_log.configure(state="disabled")

        self._sync_enabled_states()

        # product change hook: refresh defaults for exe fields (unless manually overridden)
        self.cmb_product.bind("<<ComboboxSelected>>", lambda _e: self._on_product_change())

    def _append_log(self, s: str) -> None:
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", s)
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _poll_log_queue(self) -> None:
        try:
            while True:
                s = self._log_q.get_nowait()
                self._append_log(s)
        except queue.Empty:
            pass
        self.after(100, self._poll_log_queue)

    # ---------------- config ----------------
    def _load_cfg_into_ui(self) -> None:
        c = self._cfg
        self.var_repo_root.set(c.repo_root)
        self.var_product.set(c.product)
        self.var_iss_path.set(c.iss_path)
        self.var_installer_out_dir.set(c.installer_output_dir)
        self.var_license_dir.set(getattr(c, "license_dir", ""))
        self.var_exe_base_dir.set(c.exe_base_dir)
        self.var_exe_rel_path.set(c.exe_rel_path)
        self.var_iscc_path.set(c.iscc_path)
        self.var_use_iss_copy.set(bool(getattr(c, "use_iss_copy", True)))
        self.var_no_compile.set(bool(c.no_compile))
        self.var_no_sign_exe.set(bool(c.no_sign_exe))
        self.var_no_sign_installer.set(bool(c.no_sign_installer))
        self.var_upload_360.set(not bool(c.no_upload_360))
        self.var_upload_360_headless.set(bool(c.upload_360_headless))
        
        # Per-platform upload settings
        self.var_upload_config_path.set(getattr(c, "upload_config_path", "config.json"))
        self.var_upload_cloudflare_dir.set(getattr(c, "upload_cloudflare_dir", "skydimo-setup"))
        self.var_upload_langlangyun_dir.set(getattr(c, "upload_langlangyun_dir", "skydimo-setup"))
        self.var_upload_bt_dir.set(getattr(c, "upload_bt_dir", "skydimo-setup"))
        self.var_upload_to_cloudflare.set(bool(getattr(c, "upload_to_cloudflare", False)))
        self.var_upload_to_langlangyun.set(bool(getattr(c, "upload_to_langlangyun", False)))
        self.var_upload_to_bt.set(bool(getattr(c, "upload_to_bt", False)))

        self.var_sign_server.set(c.sign_server)
        self.var_sign_api_key.set(c.sign_api_key)
        self.var_sign_user.set(c.sign_user)
        self.var_sign_password.set(c.sign_password)

        self.var_q360_account.set(c.q360_account)
        self.var_q360_password.set(c.q360_password)
        self.var_q360_soft_name.set(c.q360_soft_name)
        self.var_q360_remark.set(c.q360_remark)
        self.var_q360_start_url.set(c.q360_start_url)
        self.var_q360_version.set(c.q360_version)

    def _refresh_product_presets(self) -> None:
        # ensure presets exist (in case old config loaded)
        self._product_presets = list(getattr(self._cfg, "products", []) or [])

    def _refresh_product_combobox(self) -> None:
        # Use product key as the actual value (so pipeline receives stable identifiers).
        values = [p.key for p in self._product_presets]
        self.cmb_product.configure(values=values)
        # normalize current selection to an existing key
        cur = (self.var_product.get() or "").strip()
        if not cur and values:
            self.var_product.set(values[0])
            return
        if values and cur not in values:
            self.var_product.set(values[0])

    def _selected_preset(self) -> ProductPreset | None:
        cur = (self.var_product.get() or "").strip()
        if not cur:
            return None
        for p in self._product_presets:
            if p.key == cur:
                return p
        return None

    def _save_ui_into_cfg(self) -> None:
        c = self._cfg
        c.repo_root = self.var_repo_root.get().strip()
        c.product = self.var_product.get().strip() or "SKYDIMO"
        c.iss_path = self.var_iss_path.get().strip()
        c.installer_output_dir = self.var_installer_out_dir.get().strip()
        c.license_dir = self.var_license_dir.get().strip()
        c.exe_base_dir = self.var_exe_base_dir.get().strip()
        c.exe_rel_path = self.var_exe_rel_path.get().strip()
        c.iscc_path = self.var_iscc_path.get().strip()
        c.use_iss_copy = bool(self.var_use_iss_copy.get())
        c.no_compile = bool(self.var_no_compile.get())
        c.no_sign_exe = bool(self.var_no_sign_exe.get())
        c.no_sign_installer = bool(self.var_no_sign_installer.get())
        c.no_upload_360 = not bool(self.var_upload_360.get())
        c.upload_360_headless = bool(self.var_upload_360_headless.get())
        
        # Per-platform upload settings
        c.upload_config_path = self.var_upload_config_path.get().strip()
        c.upload_cloudflare_dir = self.var_upload_cloudflare_dir.get().strip() or "skydimo-setup"
        c.upload_langlangyun_dir = self.var_upload_langlangyun_dir.get().strip() or "skydimo-setup"
        c.upload_bt_dir = self.var_upload_bt_dir.get().strip() or "skydimo-setup"
        c.upload_to_cloudflare = bool(self.var_upload_to_cloudflare.get())
        c.upload_to_langlangyun = bool(self.var_upload_to_langlangyun.get())
        c.upload_to_bt = bool(self.var_upload_to_bt.get())

        c.sign_server = self.var_sign_server.get().strip()
        c.sign_api_key = self.var_sign_api_key.get().strip()
        c.sign_user = self.var_sign_user.get().strip()
        c.sign_password = self.var_sign_password.get().strip()

        c.q360_account = self.var_q360_account.get().strip()
        c.q360_password = self.var_q360_password.get().strip()
        # 360 软件名固定为 Skydimo（大小写敏感）
        c.q360_soft_name = "Skydimo"
        c.q360_remark = self.var_q360_remark.get().strip()
        c.q360_start_url = self.var_q360_start_url.get().strip()
        c.q360_version = self.var_q360_version.get().strip()

        save_config(self._cfg_path, c)

    def _bind_auto_save(self) -> None:
        # Any change triggers a debounced save, and also refreshes computed path labels.
        def on_change(*_a) -> None:
            self._update_exe_computed_labels()
            self._update_upload_tooltips()  # Update tooltips when upload dirs change
            self._debounced_save()

        def on_exe_edit(*_a) -> None:
            # Mark manual override when user edits EXE fields (but ignore our own default-setting).
            if self._setting_defaults:
                return
            self._exe_manual_override = True

        watched = [
            self.var_repo_root,
            self.var_product,
            self.var_iss_path,
            self.var_installer_out_dir,
            self.var_license_dir,
            self.var_use_iss_copy,
            self.var_exe_base_dir,
            self.var_exe_rel_path,
            self.var_iscc_path,
            self.var_no_compile,
            self.var_no_sign_exe,
            self.var_no_sign_installer,
            self.var_upload_360,
            self.var_upload_360_headless,
            self.var_upload_config_path,
            self.var_upload_cloudflare_dir,
            self.var_upload_langlangyun_dir,
            self.var_upload_bt_dir,
            self.var_upload_to_cloudflare,
            self.var_upload_to_langlangyun,
            self.var_upload_to_bt,
            self.var_sign_server,
            self.var_sign_api_key,
            self.var_sign_user,
            self.var_sign_password,
            self.var_q360_account,
            self.var_q360_password,
            self.var_q360_soft_name,
            self.var_q360_remark,
            self.var_q360_start_url,
            self.var_q360_version,
        ]
        for v in watched:
            v.trace_add("write", on_change)

        # Track manual override for EXE path fields specifically
        self.var_exe_base_dir.trace_add("write", on_exe_edit)
        self.var_exe_rel_path.trace_add("write", on_exe_edit)

    def _debounced_save(self) -> None:
        if self._save_after_id:
            with contextlib.suppress(Exception):
                self.after_cancel(self._save_after_id)
        self._save_after_id = self.after(600, self._save_ui_into_cfg)

    # ---------------- actions ----------------
    def _sync_enabled_states(self) -> None:
        no_compile = bool(self.var_no_compile.get())
        upload_360 = bool(self.var_upload_360.get())
        no_sign_installer = bool(self.var_no_sign_installer.get())
        any_upload = (bool(self.var_upload_to_cloudflare.get()) or 
                      bool(self.var_upload_to_langlangyun.get()) or 
                      bool(self.var_upload_to_bt.get()))

        # 360 requires compile + signed installer
        can_360 = (not no_compile) and (not no_sign_installer) and upload_360

        for w in (
            self.ent_q360_account,
            self.ent_q360_password,
            self.ent_q360_remark,
            self.ent_q360_start_url,
            self.ent_q360_version,
            self.chk_upload_360_headless,
        ):
            w.configure(state=("normal" if can_360 else "disabled"))

        # 360 软件名固定：始终只读（可复制，不可编辑）
        self.ent_q360_soft_name.configure(state="readonly")

        # Server upload config path - enabled if any upload is checked
        self.ent_upload_config.configure(state=("normal" if any_upload else "disabled"))
        # Per-platform directory inputs - enabled when corresponding platform is checked
        self.ent_cloudflare_dir.configure(state=("normal" if self.var_upload_to_cloudflare.get() else "disabled"))
        self.ent_langlangyun_dir.configure(state=("normal" if self.var_upload_to_langlangyun.get() else "disabled"))
        self.ent_bt_dir.configure(state=("normal" if self.var_upload_to_bt.get() else "disabled"))

    def _browse_repo_root(self) -> None:
        p = filedialog.askdirectory(title="选择仓库根目录（包含 SignBat_All_EXE.py/Unified.iss）")
        if p:
            self.var_repo_root.set(p)
            self._auto_fill_defaults()

    def _auto_find_repo_root(self) -> None:
        rr = find_repo_root(Path.cwd())
        if not rr:
            rr = find_repo_root(Path(__file__).resolve().parent)
        if not rr:
            messagebox.showwarning(APP_TITLE, "未能自动找到仓库根目录，请手动选择。")
            return
        self.var_repo_root.set(str(rr))
        self._auto_fill_defaults()

    def _auto_fill_defaults(self) -> None:
        repo_root_s = self.var_repo_root.get().strip()
        repo_root = Path(repo_root_s) if repo_root_s else None
        # repo_root is only used as a base directory for default paths; it no longer requires repo scripts.

        # default iss
        if not self.var_iss_path.get().strip():
            # Prefer embedded template; user may still override via Browse.
            try:
                from core.resources import get_resource_path

                self.var_iss_path.set(str(get_resource_path("assets/Unified.iss")))
            except Exception:
                pass

        if repo_root:
            # default installer output dir: derive from Unified.iss OutputDir (matches: ...\Setup_package\Setup_package)
            if not self.var_installer_out_dir.get().strip():
                out_dir = self._derive_installer_output_dir(Path(self.var_iss_path.get().strip()), repo_root=repo_root)
                if out_dir:
                    self.var_installer_out_dir.set(out_dir)

            # default license dir: configurable, default to ...\Setup_package\License
            if not self.var_license_dir.get().strip():
                self.var_license_dir.set(str((repo_root.parent / "License").resolve()))

        # default exe base/rel: follow your repo layout to reduce manual config
        if repo_root and (not self._exe_manual_override):
            preset = self._selected_preset()
            base_dir, rel = self._default_exe_base_and_rel(repo_root, preset)
            self._apply_exe_defaults(base_dir, rel)

        # default ISCC: try auto-detect via SignBat's find_iscc
        if repo_root and (not self.var_iscc_path.get().strip()):
            iscc = self._default_iscc_from_signbat(repo_root)
            if iscc:
                self.var_iscc_path.set(iscc)

        # 360 defaults are embedded in LauncherConfig; fill when empty (common when old config saved empty strings).
        self._fill_360_defaults(only_if_empty=True)

    def _fill_360_defaults(self, only_if_empty: bool = False) -> None:
        c = LauncherConfig()  # fresh instance contains embedded defaults
        self._setting_defaults = True
        try:
            if (not only_if_empty) or (not self.var_q360_account.get().strip()):
                self.var_q360_account.set(c.q360_account)
            if (not only_if_empty) or (not self.var_q360_password.get().strip()):
                self.var_q360_password.set(c.q360_password)
            if (not only_if_empty) or (not self.var_q360_soft_name.get().strip()):
                self.var_q360_soft_name.set(c.q360_soft_name)
            if (not only_if_empty) or (not self.var_q360_remark.get().strip()):
                self.var_q360_remark.set(c.q360_remark)
            if (not only_if_empty) or (not self.var_q360_start_url.get().strip()):
                self.var_q360_start_url.set(c.q360_start_url)
        finally:
            self._setting_defaults = False

    def _browse_iss(self) -> None:
        p = filedialog.askopenfilename(title="选择 Unified.iss", filetypes=[("Inno Setup Script", "*.iss"), ("All", "*.*")])
        if p:
            self.var_iss_path.set(p)
            if not self.var_installer_out_dir.get().strip():
                repo_root_s = self.var_repo_root.get().strip()
                repo_root = Path(repo_root_s) if repo_root_s else None
                out_dir = self._derive_installer_output_dir(Path(p), repo_root=repo_root)
                if out_dir:
                    self.var_installer_out_dir.set(out_dir)

    def _browse_installer_out_dir(self) -> None:
        p = filedialog.askdirectory(title="选择安装包输出目录（默认自动推导，可手动覆盖）")
        if p:
            self.var_installer_out_dir.set(p)

    def _browse_license_dir(self) -> None:
        p = filedialog.askdirectory(title="选择 License 目录（默认：...\\Setup_package\\License）")
        if p:
            self.var_license_dir.set(p)

    def _browse_exe_base_dir(self) -> None:
        p = filedialog.askdirectory(title="选择 EXE 基础目录（将与 EXE 相对路径拼接）")
        if p:
            self.var_exe_base_dir.set(p)

    def _pick_exe_and_split(self) -> None:
        p = filedialog.askopenfilename(title="选择产品 EXE（将自动拆分为 基础目录 + 相对路径）", filetypes=[("EXE", "*.exe"), ("All", "*.*")])
        if not p:
            return
        exe_path = Path(p)
        base = Path(self.var_exe_base_dir.get().strip()) if self.var_exe_base_dir.get().strip() else None
        if base:
            try:
                rel = exe_path.resolve().relative_to(base.resolve())
                self.var_exe_rel_path.set(str(rel))
                return
            except Exception:
                pass
        # fallback: use parent as base, filename as rel
        self.var_exe_base_dir.set(str(exe_path.parent))
        self.var_exe_rel_path.set(exe_path.name)

    def _browse_iscc(self) -> None:
        p = filedialog.askopenfilename(title="选择 ISCC.exe（可选）", filetypes=[("ISCC", "ISCC.exe"), ("EXE", "*.exe"), ("All", "*.*")])
        if p:
            self.var_iscc_path.set(p)

    def _browse_upload_config(self) -> None:
        p = filedialog.askopenfilename(title="选择上传配置文件（config.json）", filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if p:
            self.var_upload_config_path.set(p)

    def _toggle_all_upload_platforms(self) -> None:
        """全选或取消全选所有上传平台"""
        # 如果所有平台都已勾选，则全部取消；否则全部勾选
        all_selected = (bool(self.var_upload_to_cloudflare.get()) and 
                       bool(self.var_upload_to_langlangyun.get()) and 
                       bool(self.var_upload_to_bt.get()))
        
        new_state = not all_selected
        self.var_upload_to_cloudflare.set(new_state)
        self.var_upload_to_langlangyun.set(new_state)
        self.var_upload_to_bt.set(new_state)
        self._sync_enabled_states()

    def _clear_log(self) -> None:
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    def _validate(self) -> tuple[Path, PipelineArgs] | None:
        self._save_ui_into_cfg()
        repo_root_s = self._cfg.repo_root.strip()
        if not repo_root_s:
            messagebox.showerror(APP_TITLE, "请先选择仓库根目录。")
            return None
        repo_root = Path(repo_root_s)
        if not repo_root.is_dir():
            messagebox.showerror(APP_TITLE, "仓库根目录不存在或不是目录。")
            return None

        iss_path = Path(self._cfg.iss_path.strip()) if self._cfg.iss_path.strip() else (repo_root / "Unified.iss")
        exe_path = self._compose_exe_path()
        iscc_path = Path(self._cfg.iscc_path.strip()) if self._cfg.iscc_path.strip() else None

        if self._cfg.sign_user.strip() and not self._cfg.sign_password.strip():
            messagebox.showerror(APP_TITLE, "你填写了 Sign User，但没填 Password。原脚本会拒绝交互式提示密码。")
            return None

        preset = self._selected_preset()
        if not preset:
            messagebox.showerror(APP_TITLE, "请选择产品。")
            return None

        args = PipelineArgs(
            repo_root=repo_root,
            product=preset.key,
            prod_define=preset.prod_define,
            iss_block_macro=preset.iss_block_macro,
            iss_path=iss_path,
            exe_path=exe_path,
            iscc_path=iscc_path,
            no_compile=bool(self._cfg.no_compile),
            use_iss_copy=bool(self.var_use_iss_copy.get()),
            license_dir=Path(self._cfg.license_dir).resolve() if getattr(self._cfg, "license_dir", "").strip() else None,
            installer_output_dir=Path(self._cfg.installer_output_dir).resolve() if self._cfg.installer_output_dir.strip() else None,
            sign_server=self._cfg.sign_server.strip(),
            sign_api_key=self._cfg.sign_api_key.strip(),
            sign_user=self._cfg.sign_user.strip(),
            sign_password=self._cfg.sign_password.strip(),
            no_sign_exe=bool(self._cfg.no_sign_exe),
            no_sign_installer=bool(self._cfg.no_sign_installer),
            no_upload_360=bool(self._cfg.no_upload_360),
            upload_360_headless=bool(self._cfg.upload_360_headless),
            q360_account=self._cfg.q360_account.strip(),
            q360_password=self._cfg.q360_password.strip(),
            q360_soft_name=self._cfg.q360_soft_name.strip(),
            q360_remark=self._cfg.q360_remark.strip(),
            q360_start_url=self._cfg.q360_start_url.strip(),
            q360_version=self._cfg.q360_version.strip(),
            upload_config_path=getattr(self._cfg, "upload_config_path", "config.json").strip(),
            upload_cloudflare_dir=getattr(self._cfg, "upload_cloudflare_dir", "skydimo-setup").strip(),
            upload_langlangyun_dir=getattr(self._cfg, "upload_langlangyun_dir", "skydimo-setup").strip(),
            upload_bt_dir=getattr(self._cfg, "upload_bt_dir", "skydimo-setup").strip(),
            upload_to_cloudflare=bool(getattr(self._cfg, "upload_to_cloudflare", False)),
            upload_to_langlangyun=bool(getattr(self._cfg, "upload_to_langlangyun", False)),
            upload_to_bt=bool(getattr(self._cfg, "upload_to_bt", False)),
        )
        return repo_root, args

    def _on_product_change(self) -> None:
        # Follow product defaults unless user manually overrode EXE fields.
        repo_root_s = self.var_repo_root.get().strip()
        if not repo_root_s:
            return
        if not self._exe_manual_override:
            preset = self._selected_preset()
            base_dir, rel = self._default_exe_base_and_rel(Path(repo_root_s), preset)
            self._apply_exe_defaults(base_dir, rel)
        self._update_exe_computed_labels()
        
        # Auto-update upload directory names based on product
        self._auto_update_upload_dirs()

    def _auto_update_upload_dirs(self) -> None:
        """根据当前产品自动更新上传目录名（360 软件名固定不变）"""
        preset = self._selected_preset()
        if not preset:
            return
        
        # 使用预设中配置的目录名，如果为空则自动生成
        product_key = preset.key.lower()
        default_dir = f"{product_key}-setup"
        
        # 从预设获取上传目录配置
        cf_dir = getattr(preset, 'upload_cloudflare_dir', '') or default_dir
        lly_dir = getattr(preset, 'upload_langlangyun_dir', '') or default_dir
        bt_dir = getattr(preset, 'upload_bt_dir', '') or default_dir
        
        # Update all three platform directories
        self.var_upload_cloudflare_dir.set(cf_dir)
        self.var_upload_langlangyun_dir.set(lly_dir)
        self.var_upload_bt_dir.set(bt_dir)
        
        # Update tooltips with full paths
        self._update_upload_tooltips()
    
    def _update_upload_tooltips(self) -> None:
        """更新上传目录输入框的 tooltip 显示完整路径"""
        # Update config file path tooltip
        config_path = self.var_upload_config_path.get() or "config.json"
        try:
            full_config_path = str(Path(config_path).resolve())
        except Exception:
            full_config_path = config_path
        self.tooltip_upload_config.update_text(f"配置文件完整路径:\n{full_config_path}")
        
        # Update upload directory tooltips
        cloudflare_dir = self.var_upload_cloudflare_dir.get() or "skydimo-setup"
        langlangyun_dir = self.var_upload_langlangyun_dir.get() or "skydimo-setup"
        bt_dir = self.var_upload_bt_dir.get() or "skydimo-setup"
        
        self.tooltip_cloudflare.update_text(f"Cloudflare R2 完整路径:\n{cloudflare_dir}")
        self.tooltip_langlangyun.update_text(f"langlangyun 完整路径:\n/var/www/files/{langlangyun_dir}/")
        self.tooltip_bt.update_text(f"bt 完整路径:\n/www/wwwroot/cn3-dl.skydimo.com/{bt_dir}/")

    def _open_product_manager(self) -> None:
        win = tk.Toplevel(self)
        win.title("设备管理")
        win.geometry("1100x480")
        win.transient(self)
        win.grab_set()

        frm = ttk.Frame(win, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        cols = ("key", "display", "prod_define", "exe_dir", "exe_file", "upload_dir")
        tree = ttk.Treeview(frm, columns=cols, show="headings", height=12)
        headers = {
            "key": "Key",
            "display": "显示名",
            "prod_define": "ISCC Define",
            "exe_dir": "EXE 目录",
            "exe_file": "EXE 文件",
            "upload_dir": "上传目录",
        }
        col_widths = {"key": 80, "display": 110, "prod_define": 140, "exe_dir": 100, "exe_file": 140, "upload_dir": 140}
        for c in cols:
            tree.heading(c, text=headers[c])
            tree.column(c, width=col_widths.get(c, 100), anchor="w")
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(frm, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        def refresh_tree() -> None:
            tree.delete(*tree.get_children())
            for p in self._product_presets:
                # 显示上传目录（三个平台相同时只显示一个，否则显示"多个"）
                upload_dirs = [
                    getattr(p, 'upload_cloudflare_dir', '') or '',
                    getattr(p, 'upload_langlangyun_dir', '') or '',
                    getattr(p, 'upload_bt_dir', '') or '',
                ]
                unique_dirs = set(d for d in upload_dirs if d)
                if len(unique_dirs) == 1:
                    upload_display = list(unique_dirs)[0]
                elif len(unique_dirs) > 1:
                    upload_display = "(多个)"
                else:
                    upload_display = f"{p.key.lower()}-setup"
                
                tree.insert(
                    "",
                    "end",
                    iid=p.key,
                    values=(
                        p.key,
                        p.display,
                        p.prod_define,
                        p.exe_dir_name,
                        p.exe_file_name,
                        upload_display,
                    ),
                )

        def get_selected_key() -> str | None:
            sel = tree.selection()
            return sel[0] if sel else None

        def upsert_dialog(existing: ProductPreset | None) -> ProductPreset | None:
            dlg = tk.Toplevel(win)
            dlg.title("新增软件" if existing is None else "编辑软件")
            dlg.geometry("720x580")
            dlg.transient(win)
            dlg.grab_set()

            # 创建滚动区域
            canvas = tk.Canvas(dlg, highlightthickness=0)
            scrollbar_dlg = ttk.Scrollbar(dlg, orient="vertical", command=canvas.yview)
            f = ttk.Frame(canvas, padding=12)
            
            f.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.create_window((0, 0), window=f, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar_dlg.set)
            
            scrollbar_dlg.pack(side=tk.RIGHT, fill=tk.Y)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            def row(label: str, var: tk.StringVar, r: int, browse_dir: bool = False, hint: str = ""):
                lbl = ttk.Label(f, text=label)
                lbl.grid(row=r, column=0, sticky="w", pady=2)
                ent = ttk.Entry(f, textvariable=var)
                ent.grid(row=r, column=1, sticky="we", padx=(0, 8), pady=2)
                if browse_dir:
                    ttk.Button(
                        f,
                        text="浏览...",
                        command=lambda: var.set(filedialog.askdirectory(title="选择目录") or var.get()),
                    ).grid(row=r, column=2, sticky="e", pady=2)
                if hint:
                    ToolTip(ent, hint)
                return ent

            def section_label(text: str, r: int):
                sep = ttk.Separator(f, orient="horizontal")
                sep.grid(row=r, column=0, columnspan=3, sticky="we", pady=(10, 5))
                lbl = ttk.Label(f, text=text, font=("", 9, "bold"))
                lbl.grid(row=r+1, column=0, columnspan=3, sticky="w", pady=(0, 5))
                return r + 2

            # 基本信息
            v_key = tk.StringVar(value=(existing.key if existing else ""))
            v_disp = tk.StringVar(value=(existing.display if existing else ""))
            v_def = tk.StringVar(value=(existing.prod_define if existing else "PROD_"))
            v_macro = tk.StringVar(value=(existing.iss_block_macro if existing else "PROD_"))
            
            # EXE 配置
            v_dir = tk.StringVar(value=(existing.exe_dir_name if existing else ""))
            v_file = tk.StringVar(value=(existing.exe_file_name if existing else ""))
            v_override = tk.StringVar(value=(existing.exe_base_dir_override if existing else ""))
            
            # 上传目录配置
            v_upload_cf = tk.StringVar(value=(getattr(existing, 'upload_cloudflare_dir', '') if existing else ""))
            v_upload_lly = tk.StringVar(value=(getattr(existing, 'upload_langlangyun_dir', '') if existing else ""))
            v_upload_bt = tk.StringVar(value=(getattr(existing, 'upload_bt_dir', '') if existing else ""))
            
            r = 0
            row("Key（唯一标识，如 SKYDIMO）", v_key, r, hint="用于内部识别，会自动转大写")
            r += 1
            row("显示名（下拉框显示）", v_disp, r, hint="为空时使用 Key")
            r += 1
            
            r = section_label("编译配置", r)
            row("ISCC Define（如 PROD_SKYDIMO）", v_def, r, hint="编译时传递给 ISCC 的 /D 参数")
            r += 1
            row("ISS Block Macro（如 PROD_SKYDIMO）", v_macro, r, hint="ISS 文件中 #ifdef 块的宏名")
            r += 1
            
            r = section_label("EXE 路径配置", r)
            row("EXE 目录名", v_dir, r, hint="默认为 <repo_parent>\\此目录")
            r += 1
            row("EXE 文件名（如 Skydimo.exe）", v_file, r, hint="必填")
            r += 1
            row("EXE 基础目录覆盖（可空）", v_override, r, browse_dir=True, hint="绝对路径，覆盖默认的基础目录")
            r += 1
            
            r = section_label("上传目录配置", r)
            row("Cloudflare R2 目录", v_upload_cf, r, hint="如 skydimo-setup，为空时自动生成")
            r += 1
            row("langlangyun 目录", v_upload_lly, r, hint="如 skydimo-setup")
            r += 1
            row("bt 目录", v_upload_bt, r, hint="如 skydimo-setup")
            r += 1
            
            # 同步按钮
            def sync_upload_dirs():
                key = v_key.get().strip().lower() or "product"
                dir_name = f"{key}-setup"
                v_upload_cf.set(dir_name)
                v_upload_lly.set(dir_name)
                v_upload_bt.set(dir_name)
            
            ttk.Button(f, text="自动填充上传目录（基于 Key）", command=sync_upload_dirs).grid(
                row=r, column=0, columnspan=3, sticky="w", pady=(5, 10)
            )
            r += 1

            f.columnconfigure(1, weight=1)

            out: dict[str, ProductPreset | None] = {"v": None}

            def ok() -> None:
                key = v_key.get().strip().upper()
                if not key:
                    messagebox.showerror("错误", "Key 不能为空", parent=dlg)
                    return
                if existing is None and any(p.key == key for p in self._product_presets):
                    messagebox.showerror("错误", f"Key 已存在：{key}", parent=dlg)
                    return
                disp = v_disp.get().strip() or key
                prod_define = v_def.get().strip() or ("PROD_" + key)
                iss_macro = v_macro.get().strip() or prod_define
                exe_dir = v_dir.get().strip()
                exe_file = v_file.get().strip()
                if not exe_file:
                    messagebox.showerror("错误", "EXE 文件名不能为空", parent=dlg)
                    return
                if not exe_dir and not v_override.get().strip():
                    messagebox.showerror("错误", "EXE 目录名为空时，必须提供“EXE 基础目录覆盖”", parent=dlg)
                    return
                # 上传目录：为空时自动生成
                upload_cf = v_upload_cf.get().strip() or f"{key.lower()}-setup"
                upload_lly = v_upload_lly.get().strip() or f"{key.lower()}-setup"
                upload_bt = v_upload_bt.get().strip() or f"{key.lower()}-setup"
                
                out["v"] = ProductPreset(
                    key=key,
                    display=disp,
                    prod_define=prod_define,
                    iss_block_macro=iss_macro,
                    exe_dir_name=exe_dir,
                    exe_file_name=exe_file,
                    exe_base_dir_override=v_override.get().strip(),
                    upload_cloudflare_dir=upload_cf,
                    upload_langlangyun_dir=upload_lly,
                    upload_bt_dir=upload_bt,
                )
                dlg.destroy()

            btns = ttk.Frame(f)
            btns.grid(row=r, column=0, columnspan=3, sticky="e", pady=(12, 0))
            ttk.Button(btns, text="取消", command=dlg.destroy).pack(side=tk.RIGHT)
            ttk.Button(btns, text="确定", command=ok).pack(side=tk.RIGHT, padx=(0, 8))

            dlg.wait_window()
            return out["v"]

        def add_preset() -> None:
            p = upsert_dialog(None)
            if not p:
                return
            self._product_presets.append(p)
            self._cfg.products = self._product_presets
            save_config(self._cfg_path, self._cfg)
            self._refresh_product_combobox()
            refresh_tree()

        def edit_preset() -> None:
            k = get_selected_key()
            if not k:
                return
            cur = next((p for p in self._product_presets if p.key == k), None)
            if not cur:
                return
            updated = upsert_dialog(cur)
            if not updated:
                return
            # key change not allowed in edit (keep iid stable)
            updated = ProductPreset(
                key=cur.key,
                display=updated.display,
                prod_define=updated.prod_define,
                iss_block_macro=updated.iss_block_macro,
                exe_dir_name=updated.exe_dir_name,
                exe_file_name=updated.exe_file_name,
                exe_base_dir_override=updated.exe_base_dir_override,
                upload_cloudflare_dir=updated.upload_cloudflare_dir,
                upload_langlangyun_dir=updated.upload_langlangyun_dir,
                upload_bt_dir=updated.upload_bt_dir,
            )
            self._product_presets = [updated if p.key == k else p for p in self._product_presets]
            self._cfg.products = self._product_presets
            save_config(self._cfg_path, self._cfg)
            refresh_tree()
            self._refresh_product_combobox()

        def remove_preset() -> None:
            k = get_selected_key()
            if not k:
                return
            if not messagebox.askyesno("确认", f"确定要删除产品：{k}？", parent=win):
                return
            self._product_presets = [p for p in self._product_presets if p.key != k]
            if not self._product_presets:
                messagebox.showerror("错误", "至少需要保留一个产品 preset。", parent=win)
                return
            self._cfg.products = self._product_presets
            save_config(self._cfg_path, self._cfg)
            refresh_tree()
            self._refresh_product_combobox()

        actions = ttk.Frame(frm)
        actions.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(actions, text="新增设备", command=add_preset).pack(side=tk.LEFT)
        ttk.Button(actions, text="编辑设备", command=edit_preset).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(actions, text="删除设备", command=remove_preset).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(actions, text="关闭", command=win.destroy).pack(side=tk.RIGHT)

        refresh_tree()

    def _infer_exe_manual_override_from_loaded_cfg(self) -> None:
        """
        If loaded config matches one of known defaults, treat it as not-manual so
        switching product keeps updating defaults.
        """
        repo_root_s = self._cfg.repo_root.strip()
        if not repo_root_s:
            return
        repo_root = Path(repo_root_s)
        cur_base = (self._cfg.exe_base_dir or "").strip()
        cur_rel = (self._cfg.exe_rel_path or "").strip()
        if not cur_base and not cur_rel:
            self._exe_manual_override = False
            return
        for preset in self._product_presets:
            base, rel = self._default_exe_base_and_rel(repo_root, preset)
            if cur_base and cur_rel and (Path(cur_base) == Path(base)) and (cur_rel == rel):
                self._exe_manual_override = False
                return
        self._exe_manual_override = True

    def _default_exe_base_and_rel(self, repo_root: Path, preset: ProductPreset | None) -> tuple[str, str]:
        """
        Default exe base/rel derived from product preset.
        If preset.exe_base_dir_override is set, use it as base; otherwise use:
          <repo_parent>\\<preset.exe_dir_name>
        """
        repo_parent = repo_root.resolve().parent
        if not preset:
            return (str(repo_parent), "")
        base = preset.exe_base_dir_override.strip()
        if base:
            return (base, preset.exe_file_name)
        return (str(repo_parent / preset.exe_dir_name), preset.exe_file_name)

    def _apply_exe_defaults(self, base_dir: str, rel_path: str) -> None:
        self._setting_defaults = True
        try:
            self.var_exe_base_dir.set(base_dir)
            self.var_exe_rel_path.set(rel_path)
        finally:
            self._setting_defaults = False

    def _default_exe_rel_from_signbat(self, repo_root: Path, product: str) -> str:
        try:
            from core.pipeline import _load_module_from_path  # type: ignore
        except Exception:
            return ""
        signbat = repo_root / "SignBat_All_EXE.py"
        if not signbat.is_file():
            return ""
        try:
            mod = _load_module_from_path("_signbat_defaults", signbat)
            products = getattr(mod, "PRODUCTS")
            if product not in products:
                return ""
            cfg = products[product]
            return str(Path(cfg.exe_relpath))
        except Exception:
            return ""

    def _default_iscc_from_signbat(self, repo_root: Path) -> str:
        try:
            from core.pipeline import _load_module_from_path  # type: ignore
        except Exception:
            return ""
        signbat = repo_root / "SignBat_All_EXE.py"
        if not signbat.is_file():
            return ""
        try:
            mod = _load_module_from_path("_signbat_iscc", signbat)
            iscc = getattr(mod, "find_iscc")(None)
            return str(iscc) if iscc else ""
        except Exception:
            return ""

    def _compose_exe_path(self) -> Path | None:
        base_s = self._cfg.exe_base_dir.strip()
        rel_s = self._cfg.exe_rel_path.strip()
        if not rel_s:
            return None  # use SignBat built-in mapping
        base = Path(base_s) if base_s else Path(self._cfg.repo_root.strip() or Path.cwd())
        return (base / Path(rel_s)).resolve()

    def _derive_installer_output_dir(self, iss_path: Path, repo_root: Path | None = None) -> str:
        """
        Default expectation:
          repo_root = ...\\Setup_package\\ALL_EXE
          Unified.iss [Setup] OutputDir=..\\Setup_package
          => ...\\Setup_package
        """
        try:
            if iss_path.is_file():
                txt = iss_path.read_text(encoding="utf-8", errors="ignore")
                out = _extract_inno_setup_value(txt, "Setup", "OutputDir")
                if out:
                    # In repo layout, OutputDir is commonly relative to repo_root.parent (e.g. ..\Setup_package)
                    base = (repo_root.resolve().parent if repo_root else iss_path.parent.resolve())
                    return str((base / Path(out)).resolve())
        except Exception:
            pass
        # fallback: iss_path parent ..\Setup_package
        try:
            base = (repo_root.resolve().parent if repo_root else iss_path.parent.resolve())
            return str((base / "Setup_package").resolve())
        except Exception:
            return ""

    def _update_exe_computed_labels(self) -> None:
        base = self.var_exe_base_dir.get().strip()
        rel = self.var_exe_rel_path.get().strip()
        if not rel:
            self.var_exe_full.set("（空：使用内置 PRODUCTS 映射的默认 EXE 路径）")
            self.var_exe_dir.set("（同上）")
            return
        try:
            p = (Path(base) / Path(rel)).resolve() if base else Path(rel).resolve()
            self.var_exe_full.set(str(p))
            self.var_exe_dir.set(str(p.parent))
        except Exception:
            self.var_exe_full.set(f"{base}\\{rel}")
            self.var_exe_dir.set("（无法解析）")

    def _on_run(self) -> None:
        if self._worker and self._worker.is_alive():
            messagebox.showinfo(APP_TITLE, "任务正在运行中。")
            return

        validated = self._validate()
        if not validated:
            return
        _, args = validated

        self._cancel.clear()
        self.btn_run.configure(state=tk.DISABLED)
        self.btn_cancel.configure(state=tk.NORMAL)

        sink = QueueLogSink(self._log_q)
        writer = QueueWriter(sink)

        def worker() -> None:
            sink.write("\n=== START ===\n")
            with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
                code = run_pipeline(args, sink.write, self._cancel)
            sink.write(f"\n=== EXIT {code} ===\n")
            self.after(0, lambda: self._on_worker_done())

        self._worker = threading.Thread(target=worker, name="pipeline-worker", daemon=True)
        self._worker.start()

    def _on_worker_done(self) -> None:
        self.btn_run.configure(state=tk.NORMAL)
        self.btn_cancel.configure(state=tk.DISABLED)

    def _on_cancel(self) -> None:
        self._cancel.set()
        self._log_q.put("\n[Cancel requested]\n")

    def _on_close(self) -> None:
        if self._worker and self._worker.is_alive():
            if not messagebox.askyesno(APP_TITLE, "任务仍在运行，确定要退出吗？"):
                return
        self._save_ui_into_cfg()
        self.destroy()


def main() -> None:
    _pyinstaller_hiddenimports()
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()

