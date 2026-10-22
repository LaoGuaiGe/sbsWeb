#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sbsweb.py 合同测试：不需要板子，在本机 127.0.0.1:8080 起真实服务打 HTTP。

只验证 HTTP 行为合同（登录 / CSRF / 会话 / fetch JSON 模式 / 静态回退），
硬件与系统命令全部 monkeypatch 成假数据。纯标准库。

Windows 上 Python 已移除 crypt 模块而 sbsweb.py 顶层 import crypt，导入前注入
一个占位模块即可；实际用到的 verify_password 已被替换，占位模块不会被调用。
"""

import http.client
import json
import os
import re
import sys
import tempfile
import threading
import time
import types
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

if sys.platform == "win32":
    try:
        import crypt  # noqa: F401
    except ImportError:
        sys.modules["crypt"] = types.ModuleType("crypt")

import sbsweb  # noqa: E402

TEST_PASSWORD = "contract-test-pass"
HOST, PORT = "127.0.0.1", 8080


def fake_system_state(addr):
    return {"hostname": "contract-test", "kernel": "6.1.0-test",
            "uptime": 3600, "usb_address": addr,
            "mem": {"total": 1024 ** 3, "avail": 512 * 1024 ** 2,
                    "used": 512 * 1024 ** 2, "pct": 50},
            "disks": [{"label": "eMMC 系统分区", "mount": "/",
                       "total": 7 * 1024 ** 3, "used": 3 * 1024 ** 3, "pct": 43}]}


def fake_sd_state():
    return {"present": False, "device": None, "size": None, "mounted": None,
            "mountpoint": "/media/sd", "error": "contract test：未接 SD 卡"}


def fake_features():
    return ([{"id": "hdmi", "name": "HDMI", "enabled": True, "configured": True,
              "reboot_required": False, "message": None, "groups": ["screens"]},
             {"id": "fan", "name": "风扇", "enabled": True, "configured": True,
              "reboot_required": False, "message": None, "groups": [],
              "detail": {"pwm1": 120}}], None)


def apply_patches():
    sbsweb.verify_password = lambda user, pw: pw == TEST_PASSWORD
    sbsweb.usb0_address = lambda: HOST
    sbsweb.system_state = fake_system_state
    sbsweb.sd_state = fake_sd_state
    sbsweb.tspi_features = fake_features
    sbsweb.live_screen = lambda: "HDMI"
    sbsweb.ping_test = lambda iface, target="223.5.5.5": (True, "1.2 ms，0% 丢包")
    tmp = tempfile.mkdtemp(prefix="sbsweb-test-")
    sbsweb.REC_FILE = os.path.join(tmp, "rec.wav")  # 不存在 → /audio/rec.wav 404


def start_server():
    os.environ["TSPI_WEB_PORT"] = str(PORT)
    sbsweb.PORT = PORT
    threading.Thread(target=sbsweb.main, daemon=True).start()
    for _ in range(100):
        try:
            conn = http.client.HTTPConnection(HOST, PORT, timeout=2)
            conn.request("GET", "/login")
            conn.getresponse().read()
            conn.close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("服务没有在 127.0.0.1:%d 起来" % PORT)


def request(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, {k: v for k, v in resp.getheaders()}, data
    finally:
        conn.close()


def form(**fields):
    return urllib.parse.urlencode(fields).encode()


def get_login_csrf():
    _, _, data = request("GET", "/login")
    m = re.search(rb'name="csrf" value="([^"]+)"', data)
    return m.group(1).decode() if m else ""


results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS" if ok else "FAIL"), name, ("" if ok else "— " + detail))


def main():
    apply_patches()
    start_server()

    # 1. 登录页
    st, _, data = request("GET", "/login")
    check("GET /login → 200", st == 200, f"status={st}")
    check("登录页带一次性 CSRF token", bool(get_login_csrf()))

    # 2. CSRF 缺失 / 错误
    st, _, _ = request("POST", "/login", form(password=TEST_PASSWORD))
    check("POST /login 缺 CSRF → 400", st == 400, f"status={st}")
    st, _, _ = request("POST", "/login",
                       form(csrf="bogus-token", password=TEST_PASSWORD))
    check("POST /login CSRF 错误 → 400", st == 400, f"status={st}")

    # 3. 正确登录 → 302 + HttpOnly 会话 Cookie
    st, hdr, _ = request("POST", "/login",
                         form(csrf=get_login_csrf(), password=TEST_PASSWORD))
    cookie = hdr.get("Set-Cookie", "")
    m = re.search(r"tspiweb=([^;]+)", cookie)
    check("正确登录 → 302", st == 302, f"status={st}")
    check("下发 HttpOnly 会话 Cookie",
          bool(m) and "HttpOnly" in cookie and "SameSite=Strict" in cookie,
          cookie[:80])
    auth = {"Cookie": "tspiweb=" + (m.group(1) if m else "none")}

    # 4. 登录后首页 + 状态接口
    st, _, data = request("GET", "/", headers=auth)
    check("登录后 GET / → 200", st == 200, f"status={st}")
    check("状态页为中文界面",
          "泰山派 1M 配置中心" in data.decode("utf-8", "replace"))
    st, _, data = request("GET", "/api/status")
    check("未登录 /api/status → 401", st == 401, f"status={st}")
    st, _, data = request("GET", "/api/status", headers=auth)
    ok = st == 200
    ok = ok and json.loads(data).get("ok") is True
    check("登录后 /api/status → 200 JSON（假数据）", ok, f"status={st}")

    # 5. fetch 模式：带 X-Requested-With 回 JSON，不带回 302
    _, _, page = request("GET", "/", headers=auth)
    m2 = re.search(rb'name="csrf" value="([^"]+)"', page)
    sess_token = m2.group(1).decode() if m2 else ""
    st, _, data = request(
        "POST", "/net/ping",
        form(csrf=sess_token, iface="wlan0", label="WiFi", card="wifi"),
        {"X-Requested-With": "fetch", "Cookie": auth["Cookie"]})
    ok = st == 200 and json.loads(data).get("ok") is True
    check("带 X-Requested-With 的 POST → JSON", ok,
          f"status={st} body={data[:80]!r}")
    st, _, _ = request(
        "POST", "/net/ping",
        form(csrf=sess_token, iface="wlan0", label="WiFi", card="wifi"),
        {"Cookie": auth["Cookie"]})
    check("无 X-Requested-With 的 POST → 302", st == 302, f"status={st}")

    # 6. 没有录音时的录音回放地址
    st, _, _ = request("GET", "/audio/rec.wav", headers=auth)
    check("无录音 /audio/rec.wav → 404", st == 404, f"status={st}")

    failed = len(results) - sum(results)
    print(f"\n{sum(results)}/{len(results)} 项通过")
    if failed:
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
