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
from typing import List

import pefile
import win32api
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# =============== 配置区 ===============
ACCOUNT = "13570806357"
PASSWORD = "ibtNp4f4f6UK3n2M1yCg"

START_URL = (
    "https://i.360.cn/login?src=pcw_renzheng&tpl=client&destUrl=https%3A%2F%2Fopen.soft.360.cn%2F"
)
current_dir = os.path.dirname(os.path.abspath(__file__))
EXE_PATH = os.path.abspath(os.path.join(current_dir, "..", "Setup_package", "SkydimoSetup.exe"))
SOFT_NAME_VISIBLE = "Skydimo"
REMARK_TEXT = "Skydimo安装包自动提交（含版本号、仅软件检测）。"

DEFAULT_VERSION = "1.0.0"
# Toggle DOM/page HTML dump on errors (default False)
ENABLE_DOM_DUMP = False
UPLOAD_TIMEOUT = 600  # 10 分钟
HEADLESS = False      # True 则无头
# ---- Speed tuning ----
PAGE_LOAD_STRATEGY = "eager"   # return after DOMContentLoaded
DISABLE_IMAGES = True          # block image loading to speed up
IMPLICIT_WAIT_SECONDS = 1      # keep implicit wait short
# ---- Navigation hardening ----
NAV_MAX_RETRIES = 4
# Optional custom UA (leave empty to use Chrome default)
USER_AGENT = ""
# ---- Auth/Security ----
AUTH_MAX_WAIT = 300             # 安全验证最长等待时间（秒）
# =====================================


# ---------- 日志/调试 ----------
def log(*args):
    """轻量日志钩子，目前默认不输出；如需调试可改为 print(*args)。"""
    pass

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

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
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
    keywords_xpath = (
        "//*[contains(normalize-space(.),'安全验证') or "
        "contains(normalize-space(.),'身份验证') or "
        "contains(normalize-space(.),'短信') or "
        "contains(normalize-space(.),'验证码') or "
        "contains(normalize-space(.),'滑块') or "
        "contains(normalize-space(.),'请完成验证')]"
    )

    class_selectors = [
        ".geetest_panel", ".geetest-bubble", ".gt_slider", ".gt_popup", ".gt_box",
        ".nc-container", ".slider", "[class*='captcha' i]", "[id*='captcha' i]",
        "[class*='verify' i]", "[id*='verify' i]",
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
        url = (d.current_url or "").lower()
        if "softsubmit" in url or "softadd" in url:
            return True
        try:
            if d.find_element(By.CSS_SELECTOR, "form").is_displayed():
                return True
        except Exception:
            pass
        return "软件提交" in (d.title or "")

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
    # 优先使用安装包的产品版本（例如 2.0.2.6e4c602），再退回到文件版本，最后退回到默认版本号。
    raw_ver = get_exe_product_version(EXE_PATH) or get_exe_file_version(EXE_PATH) or DEFAULT_VERSION
    ver = normalize_version(raw_ver)
    log("安装包原始版本号:", raw_ver, "；标准化后用于提交的版本号:", ver)

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

        # 等待安全验证/登录完成，避免未加载出验证就继续导致失败
        wait_for_security_verification_if_any(driver, timeout=AUTH_MAX_WAIT)

        if not logged_in_ready(driver):
            try:
                driver.get("https://open.soft.360.cn/softlist.php")
            except Exception:
                pass

        goto_my_software(driver)
        goto_submit_page(driver)

        fill_submit_form(driver, version=ver, exe_path=EXE_PATH)

        click_form_submit(driver)

        # 留点观察
        if not HEADLESS:
            time.sleep(2)

    finally:
        # 调试阶段不自动关闭；稳定后可改为 driver.quit()
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
