# -*- coding: utf-8 -*-
import os, time, json
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

VT_SIGNIN_URL = "https://www.virustotal.com/gui/sign-in"
EMAIL = "skydimo@skydimo.com"
PASSWORD = "@2025Skydimo"
FILE_TO_UPLOAD = r"D:\Install_packaging_related_programs\Setup_package\SkydimoSetup.exe"

def find_choose_button(driver):
    """穿透所有 Shadow DOM，查找 'Choose file' 按钮（id=infoIcon 或文字匹配），找不到返回 None"""
    return driver.execute_script(r"""
    (function (){
      function isVisible(el){
        if (!el) return false;
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden' || +cs.opacity === 0) return false;
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
      }
      function matches(el){
        if (!el) return false;
        if (el.id === 'infoIcon') return true;
        const t = (el.textContent||'').toLowerCase();
        return /choose\s*file|选择文件|上传文件/.test(t);
      }
      function walk(root){
        const q = root.querySelectorAll ? root.querySelectorAll('button,[role="button"]') : [];
        for (const el of q){
          if (matches(el) && !el.disabled && isVisible(el)) return el;
        }
        const all = root.querySelectorAll ? root.querySelectorAll('*') : [];
        for (const el of all){
          if (el.shadowRoot){
            const found = walk(el.shadowRoot);
            if (found) return found;
          }
        }
        return null;
      }
      return walk(document);
    })();
    """)

def flash_and_click(driver, el):
    """高亮元素并点击（仅视觉/逻辑反馈；不会打开系统文件选择框）"""
    driver.execute_script("""
      const el = arguments[0];
      el.scrollIntoView({behavior:'smooth', block:'center'});
      const prev = el.style.outline;
      el.style.outline = '3px solid #00d0ff';
      setTimeout(()=>{ el.style.outline = prev; }, 1200);
    """, el)
    driver.execute_script("arguments[0].click();", el)


def new_driver():
    opts = webdriver.ChromeOptions()
    opts.add_experimental_option("detach", True)  # 结束后保留浏览器
    opts.add_argument("--start-maximized")
    return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)

def present(driver, by, sel, timeout=0):
    try:
        return WebDriverWait(driver, timeout).until(EC.presence_of_element_located((by, sel)))
    except Exception:
        return None

def clickable(driver, by, sel, timeout=0):
    try:
        return WebDriverWait(driver, timeout).until(EC.element_to_be_clickable((by, sel)))
    except Exception:
        return None

def already_logged_in(driver):
    # 主页上通常能查到文件上传的 <input type="file">
    el = present(driver, By.CSS_SELECTOR, "input[type='file']", timeout=2)
    return el is not None

def dump_debug_info(driver, reason=""):
    print("===== ⛏️ DEBUG 开始:", reason, "=====")
    try:
        print("当前URL:", driver.current_url)
        print("页面Title:", driver.title)
    except Exception as e:
        print("读取URL/Title失败:", repr(e))

    # 顶层 iframe 概览
    try:
        frames = driver.find_elements(By.TAG_NAME, "iframe")
        print("顶层 iframe 数量:", len(frames))
        for idx, f in enumerate(frames[:10]):
            try:
                src = f.get_attribute("src")
                name = f.get_attribute("name")
                fid = f.get_attribute("id")
                print(f"  [iframe {idx}] id={fid!r} name={name!r} src={src!r}")
            except Exception as e:
                print("  [iframe 信息读取失败]", repr(e))
    except Exception as e:
        print("列举 iframe 失败:", repr(e))

    # DOM 快速扫描
    try:
        info = driver.execute_script(
            """
            const info = {};
            const brief = (el)=>{
              const cs = getComputedStyle(el);
              const r = el.getBoundingClientRect();
              return {
                tag: el.tagName,
                id: el.id || null,
                class: el.className || null,
                text: (el.innerText||'').trim().slice(0,140),
                disabled: !!el.disabled,
                display: cs.display,
                visibility: cs.visibility,
                opacity: cs.opacity,
                pointerEvents: cs.pointerEvents,
                rect: {x:r.x, y:r.y, w:r.width, h:r.height}
              };
            };
            info.infoton = (()=>{ const el = document.getElementById('infoton'); return el ? brief(el) : null; })();
            info.buttons = Array.from(document.querySelectorAll('button')).slice(0,50).map(brief);
            info.fileInputs = Array.from(document.querySelectorAll("input[type='file']")).map(el=>{
              const cs = getComputedStyle(el);
              const r = el.getBoundingClientRect();
              return {
                id: el.id || null,
                name: el.name || null,
                accept: el.accept || null,
                multiple: !!el.multiple,
                disabled: !!el.disabled,
                hidden: !!el.hidden,
                display: cs.display,
                visibility: cs.visibility,
                opacity: cs.opacity,
                rect: {x:r.x, y:r.y, w:r.width, h:r.height}
              };
            });
            info.chooseTextEls = Array.from(document.querySelectorAll('*'))
              .filter(el => /choose\s*file/i.test(el.textContent||''))
              .slice(0,30)
              .map(brief);
            info.shadowFileInputs = [];
            (function traverse(root){
              const qsa = root.querySelectorAll ? root.querySelectorAll("input[type='file']") : [];
              qsa.forEach(el=>{
                const cs = getComputedStyle(el);
                const r = el.getBoundingClientRect();
                info.shadowFileInputs.push({
                  fromShadow: root !== document,
                  id: el.id || null,
                  name: el.name || null,
                  accept: el.accept || null,
                  disabled: !!el.disabled,
                  display: cs.display,
                  visibility: cs.visibility,
                  rect: {x:r.x, y:r.y, w:r.width, h:r.height}
                });
              });
              const all = root.querySelectorAll ? root.querySelectorAll('*') : [];
              all.forEach(el=>{ if (el.shadowRoot) traverse(el.shadowRoot); });
            })(document);
            info.modals = Array.from(document.querySelectorAll("[role='dialog'],.modal,[class*='overlay'],[class*='dialog'],[class*='modal']"))
              .slice(0,20).map(brief);
            return info;
            """
        )
        print("DOM 快速扫描:")
        print(json.dumps(info, ensure_ascii=False, indent=2))
    except Exception as e:
        print("执行前端扫描脚本失败:", repr(e))

    print("===== ⛏️ DEBUG 结束 =====")

def probe_iframes_for_file_inputs(driver):
    try:
        frames = driver.find_elements(By.TAG_NAME, "iframe")
        print("🔎 进入 iframe 探测 input[type=file]，数量:", len(frames))
        for idx, fr in enumerate(frames):
            try:
                driver.switch_to.frame(fr)
                cnt = driver.execute_script("return document.querySelectorAll(\"input[type='file']\").length;")
                print(f"  [iframe {idx}] file input 数量:", cnt)
                if cnt:
                    details = driver.execute_script(
                        "return Array.from(document.querySelectorAll(\"input[type='file']\")).map(el=>({id:el.id||null,name:el.name||null,accept:el.accept||null,multiple:!!el.multiple,disabled:!!el.disabled}));"
                    )
                    print(json.dumps(details, ensure_ascii=False, indent=2))
            except Exception as e:
                print(f"  [iframe {idx}] 探测失败:", repr(e))
            finally:
                try:
                    driver.switch_to.default_content()
                except Exception:
                    pass
    except Exception as e:
        print("列举 iframe 失败:", repr(e))

def sign_in(driver):
    # 若已登录，直接返回
    if already_logged_in(driver):
        print("🔓 已是登录状态，跳过登录。")
        return

    driver.get(VT_SIGNIN_URL)
    print("🌐 打开登录页…")

    # 多套选择器：email/name/username 都尝试
    email_x = ("//input[@type='email' or @name='username' or @name='name' "
               "or @placeholder='Email address or username' or @aria-label='Email']")
    pwd_x   = ("//input[@type='password' or @name='password' or @placeholder='Password' "
               "or @placeholder='Type in your password' or @aria-label='Password']")

    # 等待/填写邮箱
    email_el = present(driver, By.XPATH, email_x, timeout=25)
    if not email_el:
        # 兜底：用 JS 找第一个 email/name=username/name=name 的输入框并赋值
        driver.execute_script("""
            const el = document.querySelector("input[type='email'],input[name='username'],input[name='name']");
            if (el) { el.value = arguments[0]; el.dispatchEvent(new Event('input',{bubbles:true})); }
        """, EMAIL)
    else:
        email_el.clear(); email_el.send_keys(EMAIL)

    # 等待/填写密码
    pwd_el = present(driver, By.XPATH, pwd_x, timeout=15)
    if not pwd_el:
        driver.execute_script("""
            const el = document.querySelector("input[type='password'],input[name='password']");
            if (el) { el.value = arguments[0]; el.dispatchEvent(new Event('input',{bubbles:true})); }
        """, PASSWORD)
    else:
        pwd_el.clear(); pwd_el.send_keys(PASSWORD)

    # 点击 Sign in（按钮文案可能变化，用多种方式）
    btn = (clickable(driver, By.XPATH, "//button[normalize-space()='Sign in']", 10)
           or clickable(driver, By.XPATH, "//button[contains(.,'Sign in')]", 5)
           or clickable(driver, By.CSS_SELECTOR, "button[type='submit']", 5))
    if btn:
        btn.click()
    else:
        # 兜底用 JS 点击第一个可用按钮
        driver.execute_script("""
            const b = document.querySelector("button[type='submit'],button");
            if (b) b.click();
        """)

    # 等待登录完成或进入主页（有时会回到首页）
    WebDriverWait(driver, 40).until(lambda d: "virustotal.com" in d.current_url)
    print("✅ 登录流程已提交。")
    time.sleep(2)

def upload_file(driver):
    # 确保在主页（不强制写 URL，直接依靠页面元素）
    # 1) 点击 “Choose file” 按钮（id=infoton），只是模拟操作
    choose_btn = find_choose_button(driver)
    if choose_btn:
        flash_and_click(driver, choose_btn)
        print("🖱️ 点击 Choose file 按钮")
    else:
        print("ℹ️ 未找到 Choose file 按钮，直接使用隐藏 input。")
        dump_debug_info(driver, "未找到 Choose file 按钮")
        probe_iframes_for_file_inputs(driver)

    # 2) 向隐藏的 <input id="fileSelector" type="file"> 发送文件路径（包含 Shadow DOM 兜底）
    file_input = present(driver, By.ID, "fileSelector", timeout=8) \
                 or present(driver, By.CSS_SELECTOR, "input[type='file']", timeout=3)
    if not file_input:
        # 通过 JS 穿透 Shadow DOM 查找第一个可用的 file input
        try:
            file_input = driver.execute_script(
                """
                return (function findFileInput(){
                  function walk(root){
                    const cands = root.querySelectorAll ? root.querySelectorAll("input[type='file']") : [];
                    for (const el of cands){
                      if (!el.disabled) return el;
                    }
                    const all = root.querySelectorAll ? root.querySelectorAll('*') : [];
                    for (const el of all){
                      if (el.shadowRoot){
                        const found = walk(el.shadowRoot);
                        if (found) return found;
                      }
                    }
                    return null;
                  }
                  return walk(document);
                })();
                """
            )
        except Exception as e:
            print("JS 查找 Shadow DOM file input 失败:", repr(e))
    if not file_input:
        dump_debug_info(driver, "未找到 <input type='file'> 控件")
        probe_iframes_for_file_inputs(driver)
        raise RuntimeError("未找到文件选择控件 <input type='file'>。")
    if not os.path.exists(FILE_TO_UPLOAD):
        raise FileNotFoundError(FILE_TO_UPLOAD)

    # 临时调整 file input 可见性，避免 Selenium 拒绝向隐藏元素发送文件路径
    try:
        driver.execute_script(
            """
            const el = arguments[0];
            if (!el) return;
            el.style.display = 'block';
            el.style.visibility = 'visible';
            el.style.opacity = 1;
            el.style.position = 'fixed';
            el.style.zIndex = 2147483647;
            el.style.left = '10px';
            el.style.top = '10px';
            el.style.width = '1px';
            el.style.height = '1px';
            """,
            file_input
        )
    except Exception as e:
        print("调整 file input 可见性失败(可忽略):", repr(e))

    file_input.send_keys(FILE_TO_UPLOAD)
    print("📤 已选择文件：", os.path.basename(FILE_TO_UPLOAD))

    # 3) 点击 “Confirm upload/Start analysis/Start upload” 按钮（不同语言/布局）
    def _find_confirm_in_shadow():
        return driver.execute_script(
            """
            return (function findConfirm(){
              function isVisible(el){
                if (!el) return false;
                const cs = getComputedStyle(el);
                if (cs.display === 'none' || cs.visibility === 'hidden' || +cs.opacity === 0) return false;
                const r = el.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
              }
              function matches(el){
                if (!el) return false;
                if (el.id === 'confirmUploadButton') return true;
                const t = (el.textContent||'').toLowerCase();
                return /confirm\\s*upload|start\\s*(analysis|upload)|analy(s|z)e|确认|上传|开始|分析/.test(t);
              }
              function walk(root){
                const nodes = root.querySelectorAll ? root.querySelectorAll('button,[role="button"],input[type="button"],a[role="button"]') : [];
                for (const el of nodes){ if (matches(el) && !el.disabled && isVisible(el)) return el; }
                const all = root.querySelectorAll ? root.querySelectorAll('*') : [];
                for (const el of all){ if (el.shadowRoot){ const f = walk(el.shadowRoot); if (f) return f; } }
                return null;
              }
              return walk(document);
            })();
            """
        )

    # 先尝试常规 DOM 定位
    confirm = clickable(driver, By.ID, "confirmUploadButton", timeout=10) \
              or clickable(driver, By.XPATH, "//button[contains(.,'Confirm upload') or contains(.,'Start analysis') or contains(.,'Start upload')]", 5)
    if confirm:
        confirm.click()
        print("✅ 点击 Confirm/Start 按钮（可见 DOM）")
    else:
        # 循环轮询 Shadow DOM 的按钮，最长 60s
        clicked = False
        for _ in range(60):
            try:
                btn = _find_confirm_in_shadow()
                if btn:
                    driver.execute_script("arguments[0].scrollIntoView({block:'center'});", btn)
                    driver.execute_script("arguments[0].click();", btn)
                    print("✅ 通过 Shadow DOM 点击 Confirm/Start 按钮")
                    clicked = True
                    break
            except Exception:
                pass
            # 有些情况下选择文件后会直接跳转分析页
            try:
                if "/gui/file/" in driver.current_url or "/gui/url/" in driver.current_url:
                    print("ℹ️ 未显示确认按钮，但检测到分析已开始。")
                    clicked = True
                    break
            except Exception:
                pass
            time.sleep(1)
        if not clicked:
            dump_debug_info(driver, "未找到 Confirm 按钮或无法点击")
            raise RuntimeError("未找到或无法点击 Confirm/Start 按钮。")

    # 4) 等待进入文件分析页
    WebDriverWait(driver, 90).until(lambda d: "/gui/file/" in d.current_url or "/gui/url/" in d.current_url)
    print("🔍 已跳转到分析页，检测开始。")

def main():
    driver = new_driver()
    sign_in(driver)
    upload_file(driver)
    print("🎯 全流程完成，浏览器保持打开以查看检测进度。")

if __name__ == "__main__":
    main()
