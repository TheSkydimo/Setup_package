# -*- coding: utf-8 -*-
"""
360 软件开放平台 - 自动登录 + 提交软件（仅软件检测）
- 自动勾选“已仔细阅读并同意”，不点击协议链接（避免“去查看”）
- 导航：我的软件 -> 提交软件（页签，不是表单按钮）
- 填写版本号/备注，选择“本地上传安装包”
- 等待 #single_upload .js-uploadify-list 出现、隐藏 input[name=path]/[name=realfilename] 均有值、.text-success 可见
- 点击表单内“提交软件”按钮
- 失败时导出相关 DOM，便于排查

依赖：
  pip install selenium webdriver-manager pefile pypiwin32
"""

import os
import re
import sys
import time
from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path

import pefile
import win32api
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.events import EventFiringWebDriver, AbstractEventListener

# =============== 配置区 ===============
current_dir = os.path.dirname(os.path.abspath(__file__))

DEFAULT_VERSION = "1.0.0"
# Toggle DOM/page HTML dump on errors (default False)
ENABLE_DOM_DUMP = False
UPLOAD_TIMEOUT = 600  # 10 分钟
HEADLESS = False      # True 则无头
# ---- Speed tuning ----
PAGE_LOAD_STRATEGY = "eager"    # return after DOMContentLoaded
# IMPORTANT: 360 登录/安全验证（拼图/验证码）依赖图片资源，默认不要禁用图片加载。
# 若你确认不需要验证码（已保持登录/无风控），可通过命令行 --disable-images 或环境变量 Q360_DISABLE_IMAGES=1 再开启。
DISABLE_IMAGES = False
IMPLICIT_WAIT_SECONDS = 1       # keep implicit wait short
ENABLE_EVENT_LOGGER = False     # wrap driver with EventFiringWebDriver
# ---- Navigation hardening ----
NAV_MAX_RETRIES = 4
# Optional custom UA (leave empty to use Chrome default)
USER_AGENT = ""
# ---- Auth/Security ----
AUTH_MAX_WAIT = 300             # 安全验证最长等待时间（秒）
# =====================================

# These values are set at runtime from CLI/env; keep as globals to minimize code churn.
# 说明：这里用“全局变量 + main() 内赋值”的方式，是为了尽量少改原有结构。
# 实际运行时会被命令行参数/环境变量覆盖（见文件底部的 argparse 部分）。
ACCOUNT = "13570806357"
PASSWORD = "ibtNp4f4f6UK3n2M1yCg"
START_URL = "https://i.360.cn/login?src=pcw_renzheng&tpl=client&destUrl=https%3A%2F%2Fopen.soft.360.cn%2F"
INSTALLER_PATH = ""
SOFT_NAME_VISIBLE = "Skydimo"
REMARK_TEXT = "Skydimo安装包自动提交（含版本号、仅软件检测）。"
VERSION_OVERRIDE = ""


@dataclass(frozen=True)
class Upload360Config:
    installer: str
    account: str
    password: str
    soft_name_visible: str
    remark_text: str
    start_url: str
    version: str
    headless: bool
    enable_dom_dump: bool
    upload_timeout: int
    auth_max_wait: int


def _env(name: str, default: str = "") -> str:
    """读取环境变量（不存在则返回默认值）。"""
    v = os.environ.get(name)
    return v if v is not None else default


def infer_version_from_filename(path: str) -> str:
    """
    从安装包文件名中“猜测版本号”。

    例：
      `SkydimoSetup_2.0.2.6e4c602.exe` -> `2.0.2.6e4c602`
    后续会通过 `normalize_version()` 归一化为三段版本（如 `2.0.2`）。
    """
    name = Path(path).name
    m = re.search(r"_([^_]+)\.exe$", name, flags=re.IGNORECASE)
    return m.group(1) if m else ""


# ---------- 日志/调试 ----------
def log(*args):
    # 统一日志入口：默认关闭（pass），需要调试时可以改成 print(*args) 或写入文件。
    pass


class LoggingListener(AbstractEventListener):
    def _desc_el(self, el):
        try:
            tag = el.tag_name
        except Exception:
            tag = "?"
        def safe_attr(name):
            try:
                return el.get_attribute(name) or ""
            except Exception:
                return ""
        eid = safe_attr("id")
        cls = safe_attr("class")
        name = safe_attr("name")
        etype = safe_attr("type")
        txt = ""
        try:
            t = (el.text or "").strip()
            if len(t) > 40:
                t = t[:37] + "..."
            txt = t
        except Exception:
            txt = ""
        parts = [tag]
        if eid:
            parts.append(f"#{eid}")
        if cls:
            parts.append("." + ".".join([c for c in cls.split() if c]))
        if name:
            parts.append(f"[name={name}]")
        if etype:
            parts.append(f"[type={etype}]")
        if txt:
            parts.append(f"text=\"{txt}\"")
        return "<" + " ".join(parts) + ">"

    # navigation
    def before_navigate_to(self, url, driver):
        log(f"[nav] -> {url}")

    def after_navigate_to(self, url, driver):
        try:
            log(f"[nav] at {driver.current_url}")
        except Exception:
            log("[nav] at (unknown)")

    # finding
    def before_find(self, by, value, driver):
        log(f"[find] by={by} value={value}")

    def after_find(self, by, value, driver):
        log(f"[find] found by={by} value={value}")

    # script
    def before_execute_script(self, script, driver):
        s = (script or "").strip().replace("\n", " ")
        if len(s) > 120:
            s = s[:117] + "..."
        log(f"[script] -> {s}")

    def after_execute_script(self, script, driver):
        log("[script] done")

    # clicking
    def before_click(self, element, driver):
        log(f"[click] {self._desc_el(element)}")

    def after_click(self, element, driver):
        log(f"[click] done {self._desc_el(element)}")

    # value change (clear/send_keys)
    def before_change_value_of(self, element, driver):
        log(f"[input] -> {self._desc_el(element)}")

    def after_change_value_of(self, element, driver):
        log(f"[input] done {self._desc_el(element)}")

    # exceptions
    def on_exception(self, exception, driver):
        try:
            cur = driver.current_url
        except Exception:
            cur = "(unknown)"
        log(f"[error] {exception} @ {cur}")

def dump_upload_dom(driver, outdir="upload_dom_dump"):
    """把关键 DOM 与整页源码导出到本地文件，便于排查。"""
    if not ENABLE_DOM_DUMP:
        return
    os.makedirs(outdir, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")

    def dump_one(tag, css):
        path = os.path.join(outdir, f"{ts}_{tag.replace(' ','_')}.html")
        try:
            el = driver.find_element(By.CSS_SELECTOR, css)
            html = driver.execute_script("return arguments[0].outerHTML;", el)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            log(f"[dump] {tag} -> {path}")
        except Exception as e:
            log(f"[dump] {tag}({css}) 未找到：{e}")

    dump_one("single_upload", "li#single_upload")
    dump_one("js_upload_soft", "div#js-upload-soft")
    dump_one("js_uploadify-list_in_single", "#single_upload .js-uploadify-list")
    dump_one("any_js_uploadify-list", ".js-uploadify-list")
    dump_one("text_success", ".text-success")

    page_path = os.path.join(outdir, f"{ts}_page_source.html")
    with open(page_path, "w", encoding="utf-8") as f:
        f.write(driver.page_source)
    log(f"[dump] page_source -> {page_path}")


# ---------- 版本号 ----------
def normalize_version(ver: str) -> str:
    if not ver:
        return DEFAULT_VERSION
    # 仅保留数字与点，压缩多余的点
    ver = re.sub(r"[^0-9.]", "", ver).strip(".")
    ver = re.sub(r"\.+", ".", ver)
    # 取前三段作为版本号，不足三段用 0 补齐
    parts = [p for p in ver.split(".") if p.isdigit()]
    if not parts:
        return DEFAULT_VERSION
    parts = parts[:3]
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts)

def get_exe_file_version(file_path: str) -> str:
    try:
        info = win32api.GetFileVersionInfo(file_path, "\\")
        ms = info["FileVersionMS"]; ls = info["FileVersionLS"]
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except Exception:
        return ""

def get_exe_product_version(file_path: str) -> str:
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "FileInfo"):
            for fi in pe.FileInfo:
                for entry in fi:
                    if getattr(entry, "Key", b"").decode(errors="ignore") == "StringFileInfo":
                        for st in entry.StringTable:
                            d = {k.decode(errors="ignore"): v.decode(errors="ignore")
                                 for k, v in st.entries.items()}
                            return d.get("ProductVersion") or d.get("FileVersion") or ""
        return ""
    except Exception:
        return ""


# ---------- 浏览器 ----------
def launch_browser(headless: bool = False) -> webdriver.Chrome:
    """
    启动 Chrome（Selenium），并做一些“更稳定/更快”的默认设置：
    - eager 加载策略：DOM Ready 即返回（比 complete 更快）
    - 可选禁用图片加载：减少网络资源
    - 适配 headless/最大化窗口/禁用通知等
    """
    opts = Options()
    # faster load strategy and prefs
    try:
        opts.page_load_strategy = PAGE_LOAD_STRATEGY
    except Exception:
        pass
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--start-maximized")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    # Improve startup/nav robustness
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--no-first-run")
    opts.add_argument("--no-default-browser-check")
    opts.add_argument("--disable-notifications")
    opts.add_argument("--disable-popup-blocking")
    opts.add_argument("--dns-prefetch-disable")
    if USER_AGENT:
        try:
            opts.add_argument(f"--user-agent={USER_AGENT}")
        except Exception:
            pass
    if DISABLE_IMAGES:
        try:
            opts.add_experimental_option(
                "prefs",
                {
                    "profile.managed_default_content_settings.images": 2,
                    "profile.default_content_setting_values.notifications": 2,
                    "credentials_enable_service": False,
                    "profile.password_manager_enabled": False,
                },
            )
        except Exception:
            pass
    base_driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
    driver = EventFiringWebDriver(base_driver, LoggingListener()) if ENABLE_EVENT_LOGGER else base_driver
    try:
        driver.execute_script(
            "return (function(){Object.defineProperty(navigator,'webdriver',{get:()=>undefined}); return true;})()"
        )
    except Exception:
        pass
    driver.set_page_load_timeout(40)
    try:
        driver.implicitly_wait(IMPLICIT_WAIT_SECONDS)
    except Exception:
        driver.implicitly_wait(1)
    return driver

def query_all(driver: webdriver.Chrome, selectors: List[str]) -> List:
    seen, result = set(), []
    for css in selectors:
        try:
            for e in driver.find_elements(By.CSS_SELECTOR, css):
                if e.id not in seen and e.is_displayed():
                    seen.add(e.id); result.append(e)
        except Exception:
            pass
    return result


# ---------- 登录 ----------
def find_login_entry(driver: webdriver.Chrome):
    explicit = driver.find_elements(By.CSS_SELECTOR,
                                    'a[href*="i.360.cn"][href*="login"], a[href*="passport.360.cn"][href*="login"]')
    for el in explicit:
        if el.is_displayed():
            return el
    for el in query_all(driver, ["a", "button"]):
        if re.search(r"(登录|登\s*录|sign\s*in|log\s*in)", (el.text or "").strip(), re.I):
            return el
    for el in query_all(driver, ["a", "button"]):
        href = el.get_attribute("href") or ""
        if any(k in href for k in ("login", "passport.360.cn", "i.360.cn", "account", "signin")):
            return el
    return None

def only_check_agree(driver: webdriver.Chrome) -> bool:
    """仅勾选 input[name=is_agree]，不点 label。"""
    def try_here():
        els = driver.find_elements(By.CSS_SELECTOR, 'input[name="is_agree"]')
        target = next((e for e in els if e.is_displayed()), None)
        if not target:
            return False
        try:
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", target)
            time.sleep(0.05)
            if target.is_selected():
                return True
            driver.execute_script("""
                const el=arguments[0];
                ['mousedown','click','mouseup'].forEach(t=>{
                  el.dispatchEvent(new MouseEvent(t,{bubbles:true,cancelable:true,view:window}));
                });
            """, target)
            time.sleep(0.05)
            if not target.is_selected():
                driver.execute_script("""
                  const el=arguments[0];
                  el.checked=true;
                  el.dispatchEvent(new Event('input',{bubbles:true}));
                  el.dispatchEvent(new Event('change',{bubbles:true}));
                """, target)
            return True
        except Exception:
            try:
                driver.execute_script("""
                  const el=arguments[0];
                  el.checked=true;
                  el.dispatchEvent(new Event('input',{bubbles:true}));
                  el.dispatchEvent(new Event('change',{bubbles:true}));
                """, target)
                return True
            except Exception:
                return False

    if try_here():
        return True
    for f in driver.find_elements(By.TAG_NAME, "iframe"):
        try:
            driver.switch_to.frame(f)
            if try_here():
                driver.switch_to.default_content()
                return True
        except Exception:
            pass
        finally:
            driver.switch_to.default_content()
    return False

def on_login_page_autofill_and_submit(driver: webdriver.Chrome) -> bool:
    try:
        WebDriverWait(driver, 12).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, 'input[type="password"]'))
        )
    except Exception:
        return False

    only_check_agree(driver)

    account_selectors = [
        'input[type="tel"]','input[type="text"]','input[type="email"]',
        'input[name*="account" i]','input[id*="account" i]',
        'input[name*="user" i]','input[id*="user" i]',
        'input[name*="mobile" i]','input[id*="mobile" i]',
    ]
    password_selectors = ['input[type="password"]']

    account_input = None
    for css in account_selectors:
        els = driver.find_elements(By.CSS_SELECTOR, css)
        account_input = next((e for e in els if e.is_displayed()), None)
        if account_input: break

    password_input = None
    for css in password_selectors:
        els = driver.find_elements(By.CSS_SELECTOR, css)
        password_input = next((e for e in els if e.is_displayed()), None)
        if password_input: break

    if not password_input:
        return False

    try:
        if account_input:
            account_input.clear()
            account_input.send_keys(ACCOUNT)
        password_input.clear()
        password_input.send_keys(PASSWORD)
    except Exception:
        return False

    only_check_agree(driver)

    candidates = query_all(driver, [
        'button[type="submit"]','input[type="submit"]',
        'button[id*="login" i]','button[name*="login" i]',
        'a[id*="login" i]','a[name*="login" i]','button','a'
    ])
    for el in candidates:
        txt = (el.text or "").strip()
        tpe = (el.get_attribute("type") or "").lower()
        if re.search(r"(登录|登\s*录|sign\s*in|log\s*in)", txt, re.I) or tpe == "submit":
            try:
                driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
                time.sleep(0.05)
                el.click()
                return True
            except Exception:
                try:
                    driver.execute_script("arguments[0].click();", el)
                    return True
                except Exception:
                    continue

    try:
        password_input.send_keys("\n")
        return True
    except Exception:
        return False

def already_on_login_page(driver: webdriver.Chrome) -> bool:
    try:
        driver.find_element(By.CSS_SELECTOR, 'input[type="password"]')
        return True
    except Exception:
        return False


# ---------- 入口页打开（含重试） ----------
def _is_error_like_url(u: str) -> bool:
    u = (u or "").strip().lower()
    if not u:
        return True
    return u in ("about:blank", "data:,") or u.startswith("chrome-error://") or u.startswith("edge-error://")


def _wait_document_ready(driver: webdriver.Chrome, timeout: int = 10):
    try:
        WebDriverWait(driver, timeout).until(
            lambda d: (d.execute_script("return document.readyState") or "").lower() in ("interactive", "complete")
        )
    except Exception:
        pass


def open_start_page(driver: webdriver.Chrome, url: str = START_URL, max_attempts: int = NAV_MAX_RETRIES):
    """
    打开入口页（带多策略重试）。

    背景：某些环境下直接 `driver.get()` 可能偶发空白页/错误页。
    因此这里按顺序尝试：
    - get
    - JS location.href
    - window.open 新标签
    - Selenium DevTools / CDP 导航
    并在每次尝试后做简单的“健康检查”确认页面确实到了 360 站点/可见登录入口。
    """
    methods = ("get", "js_assign", "open_blank_tab", "devtools_navigate")

    for attempt in range(max_attempts):
        method = methods[min(attempt, len(methods) - 1)]
        try:
            if method == "get":
                driver.get(url)
            elif method == "js_assign":
                driver.execute_script("window.location.href = arguments[0];", url)
            elif method == "open_blank_tab":
                driver.execute_script("window.open(arguments[0], '_blank');", url)
                time.sleep(0.2)
                try:
                    driver.switch_to.window(driver.window_handles[-1])
                except Exception:
                    pass
            elif method == "devtools_navigate":
                # Prefer Selenium 4 DevTools if available; fallback to CDP; then fallback to get
                tried = False
                try:
                    devtools, connection = driver.start_devtools()
                    try:
                        connection.execute(devtools.page.enable())
                    except Exception:
                        pass
                    connection.execute(devtools.page.navigate(url=url))
                    tried = True
                except Exception:
                    pass
                if not tried:
                    try:
                        driver.execute_cdp_cmd("Page.navigate", {"url": url})
                        tried = True
                    except Exception:
                        pass
                if not tried:
                    driver.get(url)
        except Exception as e:
            log(f"[nav retry] {method} -> {e}")

        _wait_document_ready(driver, timeout=10)

        # Health check: ensure not an error-like/blank URL and page looks like 360 site or login available
        try:
            cur = driver.current_url or ""
        except Exception:
            cur = ""

        ok = False
        try:
            ok = (not _is_error_like_url(cur)) and (
                "360.cn" in cur.lower() or already_on_login_page(driver) or find_login_entry(driver) is not None
            )
        except Exception:
            ok = False

        if ok:
            try:
                WebDriverWait(driver, 8).until(lambda d: already_on_login_page(d) or find_login_entry(d) is not None)
            except Exception:
                pass
            return

        time.sleep(0.4 + 0.2 * attempt)

    # 最终失败：导出 DOM 方便排查
    dump_upload_dom(driver)
    raise RuntimeError("无法打开目标页面，多次尝试失败。")


# ---------- 登录完成/安全验证检测 ----------
def logged_in_ready(driver: webdriver.Chrome) -> bool:
    """判断是否已登录并进入开放平台（能看到 open.soft.360.cn 或“我的软件”入口）。"""
    try:
        cur = (driver.current_url or "").lower()
    except Exception:
        cur = ""
    if "open.soft.360.cn" in cur:
        return True
    try:
        link = None
        for css in ['a[href*="/softlist.php"]', 'a[href*="softlist.php"]']:
            link = next((e for e in driver.find_elements(By.CSS_SELECTOR, css) if e.is_displayed()), None)
            if link:
                break
        if link:
            return True
    except Exception:
        pass
    return False


def detect_security_verification(driver: webdriver.Chrome) -> bool:
    """
    检测页面是否出现“安全验证/验证码/短信/滑块”等人机校验。

    说明：
    - 这里采用“关键词 + 常见 class/id + iframe src 关键字”的启发式检测
    - 目的不是 100% 精准，而是尽量及时提醒用户手动完成验证
    """
    keywords_xpath = (
        "//*[contains(normalize-space(.),'安全验证') or "
        "contains(normalize-space(.),'身份验证') or "
        "contains(normalize-space(.),'短信') or "
        "contains(normalize-space(.),'验证码') or "
        "contains(normalize-space(.),'滑块') or "
        "contains(normalize-space(.),'拼图') or "
        "contains(normalize-space(.),'拖动') or "
        "contains(normalize-space(.),'请完成验证')]"
    )

    class_selectors = [
        ".geetest_panel", ".geetest-bubble", ".gt_slider", ".gt_popup", ".gt_box",
        ".nc-container", ".slider", "[class*='captcha' i]", "[id*='captcha' i]",
        "[class*='verify' i]", "[id*='verify' i]",
        ".verify-slide-con", ".verify-slide", ".quc-captcha-slide",
    ]

    def check_here() -> bool:
        try:
            els = driver.find_elements(By.XPATH, keywords_xpath)
            if any(e.is_displayed() for e in els):
                return True
        except Exception:
            pass
        for css in class_selectors:
            try:
                els = driver.find_elements(By.CSS_SELECTOR, css)
                if any(e.is_displayed() for e in els):
                    return True
            except Exception:
                pass
        try:
            ifr = driver.find_elements(By.TAG_NAME, "iframe")
            for f in ifr:
                try:
                    src = (f.get_attribute("src") or "").lower()
                    if any(k in src for k in ("captcha", "verify", "risk", "geetest", "slider", "check")):
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    if check_here():
        return True
    try:
        for f in driver.find_elements(By.TAG_NAME, "iframe"):
            try:
                driver.switch_to.frame(f)
                if check_here():
                    driver.switch_to.default_content()
                    return True
            except Exception:
                pass
            finally:
                try:
                    driver.switch_to.default_content()
                except Exception:
                    pass
    except Exception:
        pass
    return False


def wait_for_security_verification_if_any(driver: webdriver.Chrome, timeout: int = AUTH_MAX_WAIT) -> bool:
    """
    等待用户完成可能出现的安全验证，或等待登录完成。

    返回：
    - True ：检测到已进入开放平台（logged_in_ready）
    - False：超时仍未进入
    """
    end = time.time() + timeout
    last_msg = 0
    while time.time() < end:
        if logged_in_ready(driver):
            return True
        sec = False
        try:
            sec = detect_security_verification(driver)
        except Exception:
            sec = False
        if sec:
            if time.time() - last_msg > 2:
                log("检测到安全验证，请在浏览器中完成（脚本等待中）...")
                last_msg = time.time()
            time.sleep(0.5)
            continue
        if already_on_login_page(driver) or (find_login_entry(driver) is not None):
            time.sleep(0.5)
            continue
        time.sleep(0.4)
    return False


# ---------- 导航 ----------
def goto_my_software(driver: webdriver.Chrome):
    """导航到“我的软件”列表页（通常是 softlist.php），用于后续进入“提交软件”页签。"""
    link = None
    for css in ['a[href*="/softlist.php"]', 'a[href*="softlist.php"]']:
        link = next((e for e in driver.find_elements(By.CSS_SELECTOR, css) if e.is_displayed()), None)
        if link: break
    if not link:
        for a in driver.find_elements(By.CSS_SELECTOR, "a"):
            if "我的软件" in (a.text or "") and a.is_displayed():
                link = a; break
    if link:
        try: link.click()
        except Exception: driver.execute_script("arguments[0].click();", link)
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, "table")))

def goto_submit_page(driver: webdriver.Chrome):
    """
    在开放平台内进入“提交软件”页面。

    注意：
    - 这里点击的是导航/页签里的“提交软件”（不是表单按钮）
    - 如果点击失败，会兜底直接访问 softsubmit.php
    - 部分站点会新开标签页，这里会切到最新标签
    """
    def click_nav_submit():
        nav_links = []
        for css in ['a[href*="softsubmit"]', 'a[href*="softadd"]']:
            nav_links += driver.find_elements(By.CSS_SELECTOR, css)
        nav_links += driver.find_elements(
            By.XPATH, "//a[contains(normalize-space(.), '提交软件') and not(ancestor::form)]"
        )
        nav_links = [el for el in nav_links if el.is_displayed()]
        if not nav_links:
            return False
        el = nav_links[0]
        try:
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
            time.sleep(0.05); el.click()
        except Exception:
            driver.execute_script("arguments[0].click();", el)
        return True

    def ready(d):
        """
        只把真正的“开放平台提交页”当作 ready。
        以前用 `form.is_displayed()` 会把登录页误判为提交页，导致后续找不到上传 input。
        """
        try:
            url = (d.current_url or "").lower()
        except Exception:
            url = ""
        if "open.soft.360.cn" not in url:
            return False
        if ("softsubmit" not in url) and ("softadd" not in url):
            return False
        # 关键上传区域之一出现即可
        for css in ("#single_upload", "#js-upload-soft", ".js-uploadify-list", "input[type='file']"):
            try:
                el = d.find_element(By.CSS_SELECTOR, css)
                if el and el.is_displayed():
                    return True
            except Exception:
                continue
        return False

    clicked = click_nav_submit()
    if not clicked:
        driver.get("https://open.soft.360.cn/softsubmit.php")

    time.sleep(0.3)
    if len(driver.window_handles) > 1:
        driver.switch_to.window(driver.window_handles[-1])

    WebDriverWait(driver, 15).until(ready)


# ---------- 上传等待 ----------
def wait_ready_to_submit_360(driver, timeout=UPLOAD_TIMEOUT):
    """
    仅以 #single_upload .js-uploadify-list 为准：
      1) .text-success 出现并可见
      2) input[name=path] & input[name=realfilename] 非空
    """
    end = time.time() + timeout
    last_log = 0

    def get_list():
        try:
            lst = driver.find_element(By.CSS_SELECTOR, "#single_upload .js-uploadify-list")
            return lst if lst.is_displayed() else None
        except Exception:
            # 某些页面结构变化：退而全局找 js-uploadify-list
            try:
                lst = driver.find_element(By.CSS_SELECTOR, ".js-uploadify-list")
                return lst if lst.is_displayed() else None
            except Exception:
                return None

    while time.time() < end:
        lst = get_list()

        ok_text = ok_path = ok_real = False
        if lst:
            try:
                succ = lst.find_element(By.CSS_SELECTOR, ".text-success")
                ok_text = succ.is_displayed() and (succ.text or "").strip() != ""
            except Exception:
                ok_text = False
            try:
                v_path = (lst.find_element(By.CSS_SELECTOR, 'input[name="path"]').get_attribute("value") or "").strip()
                ok_path = bool(v_path)
            except Exception:
                ok_path = False
            try:
                v_real = (lst.find_element(By.CSS_SELECTOR, 'input[name="realfilename"]').get_attribute("value") or "").strip()
                ok_real = bool(v_real)
            except Exception:
                ok_real = False

        if time.time() - last_log > 1.2:
            log(f"[上传等待] text-success={ok_text} path={ok_path} real={ok_real}")
            last_log = time.time()

        if ok_text and ok_path and ok_real:
            return True

        time.sleep(0.3)

    return False


# ---------- 填表、上传（不点提交） ----------
def fill_submit_form(driver: webdriver.Chrome, version: str, exe_path: str):
    """
    填写提交表单并完成上传（但不点击“提交软件”）。

    主要步骤：
    - 选择软件名称（下拉框）
    - 填写版本号、备注
    - 切到“本地上传安装包”页签（#single_upload）
    - 找到 `<input type=file>` 并 send_keys 触发上传
    - 通过 `wait_ready_to_submit_360()` 等待上传完成标记
    """
    # 软件名称
    try:
        sel = next((e for e in driver.find_elements(By.CSS_SELECTOR, "select") if e.is_displayed()), None)
        if sel: Select(sel).select_by_visible_text(SOFT_NAME_VISIBLE)
    except Exception:
        pass

    # 版本号
    safe_ver = normalize_version(version)
    ver_input = None
    for css in ['input[name*="version" i]', 'input[name*="ver" i]', 'input[placeholder*="版本" i]']:
        ver_input = next((e for e in driver.find_elements(By.CSS_SELECTOR, css) if e.is_displayed()), None)
        if ver_input: break
    if ver_input:
        ver_input.clear(); ver_input.send_keys(safe_ver)

    # 备注
    remark = None
    for css in ['textarea[name*="remark" i]', 'textarea[name*="note" i]', 'textarea']:
        remark = next((e for e in driver.find_elements(By.CSS_SELECTOR, css) if e.is_displayed()), None)
        if remark: break
    if remark:
        remark.clear(); remark.send_keys(f"{REMARK_TEXT} 版本：{safe_ver}")

    # 切到“本地上传”
    try:
        tab = driver.find_element(By.CSS_SELECTOR, "li#single_upload")
        if tab.is_displayed():
            try: tab.click()
            except Exception: driver.execute_script("arguments[0].click();", tab)
            time.sleep(0.2)
    except Exception:
        pass

    # 文件 input
    upload_block = None
    try:
        upload_block = driver.find_element(By.CSS_SELECTOR, "#single_upload")
    except Exception:
        # 兜底：找含“本地上传安装包”的容器
        cand = driver.find_elements(By.XPATH, "//*[contains(normalize-space(.),'本地上传安装包')]")
        upload_block = cand[0] if cand else driver

    file_input = None
    for css in ["input[name='file']", "input[type='file']"]:
        elms = upload_block.find_elements(By.CSS_SELECTOR, css)
        file_input = next((e for e in elms if e.is_displayed() or
                           "webuploader-element-invisible" in (e.get_attribute("class") or "")), None)
        if file_input: break

    if not file_input:
        # 点“文件上传”把 input 展现出来
        btn = next((b for b in upload_block.find_elements(By.CSS_SELECTOR, "a,button,label")
                    if "文件上传" in (b.text or b.get_attribute("title") or b.get_attribute("value") or "")), None)
        if btn:
            try: btn.click()
            except Exception: driver.execute_script("arguments[0].click();", btn)
            # wait up to 6s for file input to appear instead of fixed sleep
            try:
                WebDriverWait(driver, 6).until(lambda d: any(
                    (e.is_displayed() or "webuploader-element-invisible" in (e.get_attribute("class") or ""))
                    for css in ["input[name='file']", "input[type='file']"]
                    for e in upload_block.find_elements(By.CSS_SELECTOR, css)
                ))
            except Exception:
                pass
            for css in ["input[name='file']", "input[type='file']"]:
                elms = upload_block.find_elements(By.CSS_SELECTOR, css)
                file_input = next((e for e in elms if e.is_displayed() or
                                   "webuploader-element-invisible" in (e.get_attribute("class") or "")), None)
                if file_input: break

    if not file_input:
        dump_upload_dom(driver)
        raise RuntimeError("未找到用于上传的 <input type=file>")

    file_input.send_keys(exe_path)
    try:
        driver.execute_script("arguments[0].dispatchEvent(new Event('change', {bubbles:true}));", file_input)
    except Exception:
        pass

    ok = wait_ready_to_submit_360(driver, timeout=UPLOAD_TIMEOUT)
    if not ok:
        dump_upload_dom(driver)
        raise RuntimeError("上传成功标记未就绪，已超时。")


# ---------- 点击表单“提交软件” ----------
def click_form_submit(driver: webdriver.Chrome):
    """点击表单内的“提交软件”按钮（有多个 xpath 兜底策略），提交最终表单。"""
    submit = None
    xpaths = [
        "//form//button[normalize-space()='提交软件' and @type='submit']",
        "//form//input[@type='submit' and ( @value='提交软件' or @value='提交' )]",
        "//form//*[@type='submit']",
    ]
    for xp in xpaths:
        els = driver.find_elements(By.XPATH, xp)
        submit = next((e for e in els if e.is_displayed()), None)
        if submit: break
    if not submit:
        els = driver.find_elements(
            By.XPATH, "//form//*[contains(@class,'btn')][contains(normalize-space(.),'提交')]"
        )
        submit = next((e for e in els if e.is_displayed()), None)
    if not submit:
        dump_upload_dom(driver)
        raise RuntimeError("未找到表单内的“提交软件”按钮")

    driver.execute_script("arguments[0].scrollIntoView({block:'center'});", submit)
    time.sleep(0.1)
    try: submit.click()
    except Exception: driver.execute_script("arguments[0].click();", submit)
    log("✅ 已点击提交。")


# ---------- 主流程 ----------
def main():
    """
    主流程（从入口 URL -> 登录 -> 导航到提交页 -> 上传 -> 提交）。

    版本号策略（优先级从高到低）：
    - --version / env Q360_VERSION
    - 从安装包文件名推断
    - EXE 的 FileVersion / ProductVersion
    - DEFAULT_VERSION
    最终会归一化为三段版本用于填写表单。
    """
    if not INSTALLER_PATH:
        raise RuntimeError("installer path is required. Use --installer or env Q360_INSTALLER.")
    if not ACCOUNT or not PASSWORD:
        raise RuntimeError("360 account/password is required. Use --account/--password or env Q360_ACCOUNT/Q360_PASSWORD.")

    inferred = infer_version_from_filename(INSTALLER_PATH)
    raw_ver = VERSION_OVERRIDE or inferred or get_exe_file_version(INSTALLER_PATH) or get_exe_product_version(INSTALLER_PATH) or DEFAULT_VERSION
    ver = normalize_version(raw_ver)
    log("将使用版本号:", ver)

    driver = launch_browser(headless=HEADLESS)
    try:
        open_start_page(driver, START_URL)

        if not already_on_login_page(driver):
            entry = find_login_entry(driver)
            if entry:
                try: entry.click()
                except Exception: driver.execute_script("arguments[0].click();", entry)
            # After clicking login entry, wait briefly for the form
            try:
                WebDriverWait(driver, 8).until(lambda d: already_on_login_page(d))
            except Exception:
                pass

        if on_login_page_autofill_and_submit(driver):
            log("已尝试提交登录表单（同意已勾选）。若出现验证码/短信验证，请手动完成。")
        else:
            log("未能自动提交登录表单，可能已登录或页面结构变化。")

        # 等待安全验证/登录完成：不完成就不要继续，否则会把登录页当提交页跑崩
        ok_login = wait_for_security_verification_if_any(driver, timeout=AUTH_MAX_WAIT)
        if not ok_login or not logged_in_ready(driver):
            dump_upload_dom(driver)
            try:
                cur = driver.current_url
            except Exception:
                cur = "(unknown)"
            try:
                ttl = driver.title
            except Exception:
                ttl = "(unknown)"
            raise RuntimeError(
                "登录未完成/仍在安全验证页面，已停止后续上传步骤。\n"
                f"当前 URL: {cur}\n"
                f"当前 Title: {ttl}\n"
                "请先在弹出的浏览器里完成拼图/验证码（确保图片能加载），然后重试。"
            )

        goto_my_software(driver)
        goto_submit_page(driver)

        fill_submit_form(driver, version=ver, exe_path=INSTALLER_PATH)

        click_form_submit(driver)

        # 留点观察
        if not HEADLESS:
            time.sleep(2)

    finally:
        # 调试阶段不自动关闭；稳定后可改为 driver.quit()
        pass


if __name__ == "__main__":
    try:
        import argparse

        p = argparse.ArgumentParser(description="Auto upload signed installer to 360 open platform for software check.")
        p.add_argument("--installer", required=False, default=_env("Q360_INSTALLER", ""), help="Path to installer .exe (or env Q360_INSTALLER)")
        # If you hardcode ACCOUNT/PASSWORD in this file for internal use, leaving args empty should NOT overwrite them.
        p.add_argument("--account", required=False, default=_env("Q360_ACCOUNT", ACCOUNT), help="360 account (or env Q360_ACCOUNT)")
        p.add_argument("--password", required=False, default=_env("Q360_PASSWORD", PASSWORD), help="360 password (or env Q360_PASSWORD)")
        p.add_argument("--soft-name", required=False, default=_env("Q360_SOFT_NAME", "Skydimo"), help="Visible software name in dropdown (or env Q360_SOFT_NAME)")
        p.add_argument("--remark", required=False, default=_env("Q360_REMARK", "Skydimo安装包自动提交（含版本号、仅软件检测）。"), help="Remark text (or env Q360_REMARK)")
        p.add_argument("--start-url", required=False, default=_env("Q360_START_URL", START_URL), help="Login start URL (or env Q360_START_URL)")
        p.add_argument("--version", required=False, default=_env("Q360_VERSION", ""), help="Override version string (or env Q360_VERSION). If omitted, infer from filename.")
        p.add_argument("--headless", action="store_true", help="Run Chrome headless.")
        p.add_argument("--dom-dump", action="store_true", help="Dump DOM/page html on errors.")
        p.add_argument(
            "--disable-images",
            action="store_true",
            help="Block image loading (faster). WARNING: will break captcha/puzzle verification pages.",
        )
        p.add_argument("--upload-timeout", type=int, default=int(_env("Q360_UPLOAD_TIMEOUT", str(UPLOAD_TIMEOUT)) or UPLOAD_TIMEOUT))
        p.add_argument("--auth-timeout", type=int, default=int(_env("Q360_AUTH_TIMEOUT", str(AUTH_MAX_WAIT)) or AUTH_MAX_WAIT))

        args = p.parse_args()

        # Apply runtime config to globals (minimal refactor)
        INSTALLER_PATH = args.installer
        ACCOUNT = args.account
        PASSWORD = args.password
        SOFT_NAME_VISIBLE = args.soft_name
        REMARK_TEXT = args.remark
        START_URL = args.start_url
        VERSION_OVERRIDE = args.version
        HEADLESS = bool(args.headless)
        ENABLE_DOM_DUMP = bool(args.dom_dump)
        # allow env override too
        DISABLE_IMAGES = bool(args.disable_images) or (_env("Q360_DISABLE_IMAGES", "").strip() in ("1", "true", "True", "yes", "YES"))
        UPLOAD_TIMEOUT = int(args.upload_timeout)
        AUTH_MAX_WAIT = int(args.auth_timeout)

        main()
    except KeyboardInterrupt:
        sys.exit(0)
