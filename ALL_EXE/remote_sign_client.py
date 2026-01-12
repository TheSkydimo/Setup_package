"""
远程签名客户端（HTTP API）。

用途：
- 将本地文件上传到签名服务，由服务端完成代码签名后返回“已签名文件”。

接口约定（由服务端实现，客户端只负责调用）：
- POST /sign-sync : 同步签名，直接返回签名后的文件内容（适合小文件/简单场景）
- POST /sign      : 异步签名，返回 job_id
- GET  /status/{job_id} : 查询异步任务状态（success/failed/processing...）
- GET  /result/{job_id} : 获取签名后的文件内容（stream 下载）

认证：
- 可选 `x-api-key`：API Key（如果服务端启用）
- 可选 `x-user`：调用方标识（用于审计/限流）
- 可选 BasicAuth：当显式传了 user 且 password 不是 None 时启用

注意：
- 这里使用 stream=True 进行分块下载，避免一次性把大文件读进内存。
"""

import sys
import os
import platform
import time
import argparse
from pathlib import Path

import requests
from getpass import getpass
from requests.auth import HTTPBasicAuth


class SignError(RuntimeError):
    """签名相关的业务错误（HTTP 非 200 / 服务端失败等都会抛该异常）。"""
    pass


def sign_sync(server: str, key: str, user: str, src: str, out: str, password: str | None) -> Path:
    """
    同步签名：上传文件 -> 直接拿到签名后的文件流并保存到本地。

    - **server**: 例如 `http://192.168.1.66:8099`
    - **key**: 可选 API Key（写入 x-api-key）
    - **user**: 调用方用户名/机器名（写入 x-user；也用于 BasicAuth 的用户名）
    - **src**: 待签名文件路径
    - **out**: 输出文件路径（为空则默认 `<src>.<suffix>.signed`）
    - **password**: BasicAuth 密码；None 表示不启用 BasicAuth
    """
    url = f"{server.rstrip('/')}/sign-sync"
    headers = {}
    if key:
        headers["x-api-key"] = key
    if user:
        headers["x-user"] = user
    # 只有在 user 存在且 password 不是 None 时，才启用 BasicAuth（允许显式传空密码）
    auth = HTTPBasicAuth(user, password) if user and password is not None else None
    with open(src, "rb") as f:
        files = {"file": (Path(src).name, f, "application/octet-stream")}
        # stream=True：后面用 iter_content 分块写入，避免内存暴涨
        r = requests.post(url, headers=headers, files=files, timeout=3600, stream=True, auth=auth)
    if r.status_code != 200:
        raise SignError(f"sign-sync failed: {r.status_code} {r.text}")
    out_path = Path(out) if out else Path(src).with_suffix(Path(src).suffix + ".signed")
    with open(out_path, "wb") as w:
        for chunk in r.iter_content(1024 * 1024):
            if chunk:
                w.write(chunk)
    print(f"Saved: {out_path}")
    return out_path


def sign_async(
    server: str,
    key: str,
    user: str,
    src: str,
    out: str,
    wait: bool,
    poll_interval: int,
    password: str | None,
) -> Path | None:
    """
    异步签名：先提交任务获取 job_id，再按需轮询并下载结果。

    - wait=False：只提交任务并打印 job_id，函数返回 None
    - wait=True ：轮询 /status，成功后下载 /result 并返回输出路径
    """
    headers = {}
    if key:
        headers["x-api-key"] = key
    if user:
        headers["x-user"] = user
    url = f"{server.rstrip('/')}/sign"
    # 与 sign_sync 保持一致：password 为 None 时不启用 BasicAuth
    auth = HTTPBasicAuth(user, password) if user and password is not None else None
    with open(src, "rb") as f:
        files = {"file": (Path(src).name, f, "application/octet-stream")}
        r = requests.post(url, headers=headers, files=files, timeout=600, auth=auth)
    if r.status_code != 200:
        raise SignError(f"sign failed: {r.status_code} {r.text}")
    job_id = r.json()["job_id"]
    print(f"job_id: {job_id}")
    if not wait:
        return None
    status_url = f"{server.rstrip('/')}/status/{job_id}"
    result_url = f"{server.rstrip('/')}/result/{job_id}"
    while True:
        # 轮询任务状态：success -> 下载；failed -> 抛错；其它 -> sleep 后继续
        s = requests.get(status_url, headers=headers, timeout=30, auth=auth)
        if s.status_code != 200:
            raise SignError(f"status failed: {s.status_code} {s.text}")
        data = s.json()
        st = data["status"]
        if st == "success":
            out_path = Path(out) if out else Path(src).with_suffix(Path(src).suffix + ".signed")
            with requests.get(result_url, headers=headers, timeout=3600, stream=True, auth=auth) as rr:
                if rr.status_code != 200:
                    raise SignError(f"download failed: {rr.status_code} {rr.text}")
                with open(out_path, "wb") as w:
                    for chunk in rr.iter_content(1024 * 1024):
                        if chunk:
                            w.write(chunk)
            print(f"Saved: {out_path}")
            return out_path
        if st == "failed":
            raise SignError(f"job failed: {data.get('error')}")
        time.sleep(poll_interval)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--server", default="http://192.168.1.66:8099", help="e.g. http://192.168.1.10:8099")
    # 这几个参数通常属于“内部/自动化”使用场景，默认不在 help 中展示，避免误导普通用户
    p.add_argument("--api-key", default="", help=argparse.SUPPRESS)
    p.add_argument("--user", default="", help=argparse.SUPPRESS)
    p.add_argument("--password", default="", help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("sign")
    sp.add_argument("file")
    sp.add_argument("--sync", action="store_true", help="use sync API and return signed file directly")
    sp.add_argument("--wait", action="store_true", help="wait until finished for async API")
    sp.add_argument("--out", default="", help="output path for signed file")

    args = p.parse_args()
    if args.cmd == "sign":
        # 默认用机器名作为 user，便于服务端审计/定位来源
        auto_user = os.environ.get("COMPUTERNAME") or platform.node() or ""
        effective_user = args.user or auto_user
        user_was_explicit = bool(args.user)
        password = args.password if args.password else None
        if user_was_explicit and password is None:
            # 只有用户显式传了 --user（意味着要走 BasicAuth）才交互式提示密码
            password = getpass("Password: ")
        try:
            if args.sync:
                sign_sync(args.server, args.api_key, effective_user, args.file, args.out or "", password)
            else:
                sign_async(args.server, args.api_key, effective_user, args.file, args.out or "", args.wait, 2, password)
        except SignError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {type(e).__name__}: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
