#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""泰山派 1M 板载配置网页 — v0.4 第一轮：登录 + 只读状态。

只监听 USB 网卡（usb0 / 192.168.7.1），WiFi 与网口都访问不到。
本轮只读取状态，不做任何修改动作（改配置、连 WiFi 等在第二轮加入）。

依赖：python3 标准库 + tspi-config + nmcli + systemctl。
"""

import crypt
import hmac
import html
import json
import math
import os
import re
import secrets
import socketserver
import subprocess
import sys
import threading
import time
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

warnings.filterwarnings("ignore", category=DeprecationWarning)

APP_NAME = "泰山派 1M 配置"
BIND_IFACE = "usb0"
FALLBACK_ADDR = "192.168.7.1"
PORT = 80
LOGIN_USER = "lckfb"
DEFAULT_PASSWORD = "lckfb"
SESSION_TTL = 8 * 3600
MAX_FAILS = 5
FAIL_WINDOW = 300
STATUS_TTL = 3.0

_sessions = {}
_pre_csrf = {}
_fails = {}
_lock = threading.Lock()
_status_cache = {"at": 0.0, "data": None}


# ---------------------------------------------------------------- utilities

def _dt_status(path):
    try:
        with open(path, "rb") as fh:
            return fh.read().split(b"\x00")[0].decode("ascii", "replace")
    except OSError:
        return ""


def live_screen():
    """Which screen is actually driving the display right now (from the live DT)."""
    if _dt_status("/proc/device-tree/hdmi@fe0a0000/status") == "okay":
        return "HDMI"
    if _dt_status("/proc/device-tree/edp@fe0c0000/status") == "okay":
        return "10 寸 eDP"
    if _dt_status("/proc/device-tree/dsi@fe070000/status") == "okay":
        try:
            with open("/proc/device-tree/dsi@fe070000/panel@0/display-timings/timing0/hactive",
                      "rb") as fh:
                width = int.from_bytes(fh.read(4), "big")
        except OSError:
            width = 0
        return "10 寸 MIPI" if width >= 800 else "3.1 寸 MIPI"
    return "未知"


def ping_test(iface, target="223.5.5.5"):
    """ICMP test through one specific interface."""
    if not iface:
        return False, "没有指定网卡"
    rc, out = run(["ping", "-I", iface, "-c", "3", "-W", "2", target], timeout=20)
    loss = re.search(r"(\d+)% packet loss", out)
    avg = re.search(r"min/avg/max[^=]*=\s*[\d.]+/([\d.]+)/", out)
    if rc == 0 and loss and loss.group(1) == "0":
        return True, f"{iface} 通（平均 {avg.group(1) if avg else '?'} ms）"
    if loss:
        return False, f"{iface} 不通（丢包 {loss.group(1)}%）"
    return False, f"{iface} 不通（无响应）"


def run_full(cmd, timeout=20):
    """Like run() but also returns stderr, for commands whose errors matter."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as exc:
        return 1, "", str(exc)


def emmc_speed_test():
    """Write/read 100 MB on the userdata partition (onboard eMMC)."""
    path = "/userdata/.tspi-emmc-speed.bin"
    write = read = 0.0
    t0 = time.time()
    rc, _ = run(["dd", "if=/dev/zero", "of=" + path, "bs=1M", "count=100",
                 "conv=fsync"], timeout=120)
    if rc == 0:
        write = 100.0 / max(0.01, time.time() - t0)
    t0 = time.time()
    rc, _ = run(["dd", "if=" + path, "of=/dev/null", "bs=1M", "iflag=direct"], timeout=120)
    if rc != 0:
        rc, _ = run(["dd", "if=" + path, "of=/dev/null", "bs=1M"], timeout=120)
    if rc == 0:
        read = 100.0 / max(0.01, time.time() - t0)
    try:
        os.remove(path)
    except OSError:
        pass
    return round(write, 1), round(read, 1)


def ddr_test():
    """Allocate 64 MB of RAM, fill it, verify it and measure bandwidth."""
    size = 64 * 1024 * 1024
    chunk = b"\x5a" * 65536
    try:
        buf = bytearray(size)
    except MemoryError:
        return False, "内存不足，无法分配 64 MB"
    try:
        t0 = time.time()
        buf[:] = b"\x5a" * size
        tw = max(0.001, time.time() - t0)
        ok = True
        t0 = time.time()
        for off in range(0, size, 65536):
            if buf[off:off + 65536] != chunk:
                ok = False
                break
        tr = max(0.001, time.time() - t0)
        del buf
    except MemoryError:
        return False, "内存分配失败"
    wb = size / tw / (1024 ** 2)
    rb = size / tr / (1024 ** 2)
    return ok, f"DDR 64 MB：写入 {wb:.0f} MB/s，读取 {rb:.0f} MB/s，校验{'通过' if ok else '失败'}"


def run(cmd, timeout=5, data=None):
    """Run a command without a shell; return (rc, stdout)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=data)
        return p.returncode, (p.stdout or "").strip()
    except Exception:
        return 1, ""


def usb0_address():
    rc, out = run(["ip", "-4", "-o", "addr", "show", BIND_IFACE])
    if rc == 0:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    return FALLBACK_ADDR


def verify_password(user, password):
    """Check a password against /etc/shadow (needs root)."""
    try:
        with open("/etc/shadow", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(":")
                if len(parts) > 1 and parts[0] == user:
                    stored = parts[1]
                    if not stored or stored[0] in "!*":
                        return False
                    got = crypt.crypt(password, stored)
                    return bool(got) and hmac.compare_digest(got, stored)
    except Exception:
        return False
    return False


def default_password_in_use():
    """True when the account still uses the shipped default password."""
    return verify_password(LOGIN_USER, DEFAULT_PASSWORD)


def change_password(old, new):
    """Change the login account password. Returns (ok, message)."""
    if not verify_password(LOGIN_USER, old):
        return False, "原密码不正确"
    if len(new) < 8:
        return False, "新密码至少 8 位"
    if new == DEFAULT_PASSWORD:
        return False, "新密码不能和默认密码相同"
    rc, _ = run(["chpasswd"], timeout=10, data=f"{LOGIN_USER}:{new}\n")
    if rc != 0:
        return False, "修改失败（chpasswd 返回错误）"
    return True, "密码已修改，请用新密码重新登录"


def ethernet_state():
    """Physical Ethernet ports (skip the 4G modem, which nmcli calls ethernet)."""
    out_list = []
    rc, out = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
    if rc != 0:
        return out_list
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 4 or parts[1] != "ethernet":
            continue
        dev = parts[0]
        if not (dev.startswith("end") or dev.startswith("eth") or dev.startswith("en")):
            continue
        item = {"device": dev, "state": parts[2], "connection": parts[3] or None,
                "carrier": None, "speed": None, "ip": None}
        try:
            with open(f"/sys/class/net/{dev}/carrier", "r", encoding="ascii") as fh:
                item["carrier"] = fh.read().strip() == "1"
        except Exception:
            pass
        try:
            with open(f"/sys/class/net/{dev}/speed", "r", encoding="ascii") as fh:
                item["speed"] = fh.read().strip()
        except Exception:
            pass
        _, addr = run(["ip", "-4", "-o", "addr", "show", dev])
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", addr)
        if m:
            item["ip"] = m.group(1)
        out_list.append(item)
    return out_list


def _nmcli_fields(line):
    r"""切分 `nmcli -t` 的一行（冒号分隔），并还原 \: 等转义。"""
    parts, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def wifi_scan():
    run(["nmcli", "device", "wifi", "rescan"], timeout=15)
    time.sleep(1.0)


def wifi_connect(ssid, password):
    if not ssid:
        return False, "没有选择网络"
    # 清掉同名旧配置，避免旧密码/旧密钥残留导致 “需要密钥” 之类的怪错误
    run(["nmcli", "connection", "delete", ssid], timeout=10)
    args = ["nmcli", "--wait", "30", "device", "wifi", "connect", ssid]
    if password:
        args += ["password", password]
    rc, out, errout = run_full(args, timeout=45)
    detail = (errout or out or "").strip()
    if "secret" in detail.lower() or "密钥" in detail:
        return False, "密码不正确（或加密方式不支持）"
    # 必须校验目标 SSID 出现在活动连接里并拿到 IP；板子还连着旧网络不算成功。
    # 这块板子的 nmcli connection show 不支持 CONNECTION 字段，改用 NAME（连接名，
    # 与 WiFi 卡片 GENERAL.CONNECTION 显示的是同一个值）；-t 输出里的 \: 需还原。
    deadline = time.time() + 8
    while True:
        _, actout = run(["nmcli", "-t", "-f", "ACTIVE,TYPE,NAME,DEVICE",
                         "connection", "show"], timeout=8)
        for line in actout.splitlines():
            parts = _nmcli_fields(line)
            if (len(parts) >= 4 and parts[0] == "yes"
                    and parts[1] == "802-11-wireless" and parts[2] == ssid):
                while True:
                    _, addr = run(["ip", "-4", "-o", "addr", "show", parts[3]], timeout=5)
                    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", addr)
                    if m:
                        return True, f"已连接 {ssid}（IP {m.group(1)}）"
                    if time.time() >= deadline:
                        break
                    time.sleep(1)
                return False, f"已关联 {ssid}，但没拿到 IP（DHCP 无响应），请检查路由器的 DHCP"
        if time.time() >= deadline:
            break
        time.sleep(1)
    st = wifi_state()
    if str(st.get("state") or "").startswith("connecting"):
        return False, f"已关联 {ssid}，但没拿到 IP（DHCP 无响应），请检查路由器的 DHCP"
    if st.get("state") == "connected" and st.get("ssid") != ssid:
        return False, f"连接失败：板子仍连接在 {st.get('ssid') or '其它网络'}"
    if rc == 0:
        return False, f"连接失败：{ssid} 未生效，请稍后重试"
    tail = detail.splitlines()[-1][:120] if detail else "无响应"
    return False, f"连接失败：{tail}"


def rate_limited(ip):
    now = time.time()
    with _lock:
        hits = [t for t in _fails.get(ip, []) if now - t < FAIL_WINDOW]
        _fails[ip] = hits
        return len(hits) >= MAX_FAILS


def note_failure(ip):
    with _lock:
        _fails.setdefault(ip, []).append(time.time())


def clear_failures(ip):
    with _lock:
        _fails.pop(ip, None)


def new_session():
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    with _lock:
        _sessions[token] = {"expires": time.time() + SESSION_TTL, "csrf": csrf}
    return token, csrf


def new_csrf():
    """One-shot token for the login form (no session is created yet)."""
    token = secrets.token_urlsafe(24)
    now = time.time()
    with _lock:
        for k in [k for k, v in _pre_csrf.items() if v < now]:
            _pre_csrf.pop(k, None)
        _pre_csrf[token] = now + 600
    return token


def check_csrf(token):
    with _lock:
        exp = _pre_csrf.pop(token or "", None)
    return bool(exp) and exp > time.time()


def get_session(token):
    if not token:
        return None
    with _lock:
        sess = _sessions.get(token)
        if not sess:
            return None
        if sess["expires"] < time.time():
            _sessions.pop(token, None)
            return None
        return sess


def drop_session(token):
    with _lock:
        _sessions.pop(token, None)


# ------------------------------------------------------------- status data

AUDIO_CARD = "0"
REC_FILE = "/var/lib/tspi-web/rec.wav"
DEFAULT_WAV = "/var/lib/tspi-web/default-v2.wav"
_last_rec = {"at": None, "peak": None, "levels": None, "seconds": 0}


def rec_version():
    """rec.wav 的 <mtime>-<size> 标识，录音后客户端用它刷新 <audio> 的 src。"""
    try:
        stt = os.stat(REC_FILE)
    except OSError:
        return ""
    return f"{int(stt.st_mtime)}-{stt.st_size}"


def audio_state():
    st = {"volume": None, "playback_path": None, "capture_path": None,
          "rec": None, "error": None}
    rc, out = run(["amixer", "-c", AUDIO_CARD, "sget", "DAC"])
    m = re.search(r"(\d+)\s*\[\d+%\]", out)
    if m:
        st["volume"] = dac_reg_to_pct(m.group(1))
    rc, out = run(["amixer", "-c", AUDIO_CARD, "sget", "Playback Path"])
    m = re.search(r"Item0:\s*'([^']+)'", out)
    if m:
        st["playback_path"] = m.group(1)
    rc, out = run(["amixer", "-c", AUDIO_CARD, "sget", "Capture MIC Path"])
    m = re.search(r"Item0:\s*'([^']+)'", out)
    if m:
        st["capture_path"] = m.group(1)
    if _last_rec["at"]:
        st["rec"] = dict(_last_rec)
    if st["volume"] is None:
        st["error"] = "没有读到音频混音器"
    return st


def dac_reg_to_pct(reg):
    """RK809 DAC 寄存器值 → 网页听感百分比（dac_pct_to_reg 的逆，显示用）。"""
    try:
        reg = int(reg)
    except (TypeError, ValueError):
        return 0
    db = -95.0 + 0.368 * min(255, max(0, reg))
    if db <= -95.0:
        return 0
    return max(0, min(100, int(round(100 * 10 ** ((db + 8.49) / 20.0)))))


def dac_pct_to_reg(pct):
    """网页听感百分比（0-100）→ RK809 DAC 寄存器值。
    0 为静音；其余按幅度定位：dB = -8.49 + 20*log10(p/100)，下限 -95，
    寄存器 = (dB + 95) / 0.368，硬件上限 235（约 -8.5 dB）。"""
    p = max(0, min(100, int(pct)))
    if p <= 0:
        return 0
    db = max(-95.0, -8.49 + 20 * math.log10(p / 100.0))
    return max(0, min(235, int(round((db + 95.0) / 0.368))))


def audio_set_volume(pct):
    """按听感百分比设置音量；返回 (ok, message, 生效后的网页百分比)。"""
    try:
        p = int(pct)
    except (TypeError, ValueError):
        return False, "音量设置失败", None
    reg = dac_pct_to_reg(p)
    rc, _ = run(["amixer", "-c", AUDIO_CARD, "sset", "DAC", str(reg)], timeout=8)
    if rc != 0:
        return False, "音量设置失败", None
    eff = dac_reg_to_pct(reg)
    return True, f"音量已设为 {eff}%", eff


def audio_ensure_route(path="SPK"):
    run(["amixer", "-c", AUDIO_CARD, "sset", "Playback Path", path], timeout=8)


def audio_ensure_mic():
    run(["amixer", "-c", AUDIO_CARD, "sset", "Capture MIC Path", "Main Mic"], timeout=8)


def ensure_default_wav():
    """Create a short test tone the first time it is needed."""
    if os.path.exists(DEFAULT_WAV):
        return DEFAULT_WAV
    import math
    import struct
    import wave
    os.makedirs(os.path.dirname(DEFAULT_WAV), exist_ok=True)
    rate, secs = 44100, 2.0
    with wave.open(DEFAULT_WAV, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(rate)
        frames = bytearray()
        for i in range(int(rate * secs)):
            t = i / rate
            env = min(1.0, t * 8, (secs - t) * 8)
            v = int(12000 * env * math.sin(2 * math.pi * 660 * t))
            frames += struct.pack("<hh", v, v)
        w.writeframes(bytes(frames))
    return DEFAULT_WAV


def audio_play_default():
    audio_ensure_route("SPK")
    path = ensure_default_wav()
    rc, out = run(["aplay", "-D", "hw:0,0", path], timeout=10)
    if rc != 0:
        rc2, out2 = run(["aplay", "-D", "plughw:0,0", path], timeout=10)
        if rc2 != 0:
            return False, "播放失败：" + (out2 or out or "aplay 返回错误").splitlines()[-1][:120]
    return True, "已从板子喇叭播放测试音"


def audio_play_recording():
    """Play the last recording on the board speaker (downmix to mono first)."""
    if not os.path.exists(REC_FILE):
        return False, "还没有录音"
    audio_ensure_route("SPK")
    play = "/tmp/tspi-play.wav"
    rc, out = run(["sox", REC_FILE, play, "remix", "1", "1"], timeout=20)
    if rc != 0:
        return False, "转换录音失败（sox）"
    rc, out = run(["aplay", "-D", "hw:0,0", play], timeout=15)
    if rc != 0:
        rc2, out2 = run(["aplay", "-D", "plughw:0,0", play], timeout=15)
        if rc2 != 0:
            return False, "回放失败：" + (out2 or out or "aplay 返回错误").splitlines()[-1][:120]
    return True, "已从板子喇叭回放刚才的录音"


def analyze_wav(path, buckets=48):
    import array
    import wave
    with wave.open(path, "rb") as w:
        data = w.readframes(w.getnframes())
    a = array.array("h")
    a.frombytes(data[: len(data) // 2 * 2])
    if not a:
        return 0.0, [0.0] * buckets
    peak = max(abs(x) for x in a) / 32768.0
    seg = max(1, len(a) // buckets)
    levels = []
    for i in range(buckets):
        chunk = a[i * seg:(i + 1) * seg]
        if not chunk:
            levels.append(0.0)
            continue
        rms = (sum(float(x) * x for x in chunk) / len(chunk)) ** 0.5 / 32768.0
        levels.append(round(min(1.0, rms * 6), 3))
    return round(peak, 3), levels


def audio_record(seconds=5):
    seconds = max(1, min(15, int(seconds)))
    os.makedirs(os.path.dirname(REC_FILE), exist_ok=True)
    audio_ensure_mic()
    rc, out = run(["arecord", "-D", "hw:0,0", "-c", "2", "-r", "44100", "-f", "S16_LE",
                   "-d", str(seconds), REC_FILE], timeout=seconds + 10)
    if rc != 0 or not os.path.exists(REC_FILE):
        return False, "录音失败（arecord 返回错误）"
    peak, levels = analyze_wav(REC_FILE)
    _last_rec.update({"at": time.strftime("%H:%M:%S"), "peak": peak,
                      "levels": levels, "seconds": seconds})
    return True, f"已录制 {seconds} 秒"


def sd_state():
    """Detect the SD card, mount it on demand, and report kernel errors."""
    info = {"present": False, "device": None, "size": None, "mounted": None,
            "mountpoint": "/media/sd", "error": None}
    cands = []
    for name in os.listdir("/sys/class/block"):
        if name.startswith("mmcblk0") or name.startswith("zram"):
            continue
        if re.match(r"^(mmcblk\d+p\d+|sd[a-z]\d+)$", name):
            cands.append(name)
    if cands:
        dev = sorted(cands)[0]
        info["present"] = True
        info["device"] = "/dev/" + dev
        try:
            with open(f"/sys/class/block/{dev}/size", "r", encoding="ascii") as fh:
                info["size"] = int(fh.read().strip()) * 512
        except Exception:
            pass
        for line in open("/proc/mounts", "r", encoding="utf-8", errors="replace"):
            parts = line.split()
            if len(parts) > 1 and parts[0] == info["device"]:
                info["mounted"] = parts[1]
                break
        if not info["mounted"]:
            os.makedirs(info["mountpoint"], exist_ok=True)
            rc, out = run(["mount", info["device"], info["mountpoint"]], timeout=15)
            if rc == 0:
                info["mounted"] = info["mountpoint"]
            else:
                info["error"] = "挂载失败：" + (out.splitlines() or ["未知错误"])[-1][:120]
    else:
        rc, out = run(["dmesg"])
        tail = [l for l in out.splitlines() if "mmc1" in l or "SD card" in l][-2:]
        msg = "没有枚举到块设备，无法挂载"
        if tail:
            msg += "（" + " / ".join(l.split("] ", 1)[-1] for l in tail) + "）"
        info["error"] = msg
    return info


SD_ROOT = "/media/sd"


def sd_safe(rel):
    """Resolve a path inside the SD mount, refusing to escape it."""
    rel = (rel or "/").split("?")[0]
    full = os.path.realpath(os.path.join(SD_ROOT, rel.lstrip("/")))
    root = os.path.realpath(SD_ROOT)
    if full != root and not full.startswith(root + os.sep):
        return None
    return full


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def sd_list(rel):
    full = sd_safe(rel)
    if not full or not os.path.isdir(full):
        return None
    items = []
    for name in sorted(os.listdir(full), key=lambda s: (not os.path.isdir(os.path.join(full, s)), s.lower())):
        fp = os.path.join(full, name)
        try:
            stt = os.stat(fp)
        except OSError:
            continue
        items.append({"name": name, "dir": os.path.isdir(fp), "size": stt.st_size,
                      "mtime": time.strftime("%m-%d %H:%M", time.localtime(stt.st_mtime))})
    return items


def sd_speed_test():
    path = os.path.join(SD_ROOT, ".tspi-speed.bin")
    write = read = 0.0
    t0 = time.time()
    rc, _ = run(["dd", "if=/dev/zero", "of=" + path, "bs=1M", "count=64",
                 "conv=fsync"], timeout=90)
    if rc == 0:
        write = 64.0 / max(0.01, time.time() - t0)
    t0 = time.time()
    rc, _ = run(["dd", "if=" + path, "of=/dev/null", "bs=1M", "iflag=direct"], timeout=90)
    if rc != 0:
        rc, _ = run(["dd", "if=" + path, "of=/dev/null", "bs=1M"], timeout=90)
    if rc == 0:
        read = 64.0 / max(0.01, time.time() - t0)
    try:
        os.remove(path)
    except OSError:
        pass
    return round(write, 1), round(read, 1)


AT_PORT = "/dev/ttyUSB2"


_at_lock = threading.Lock()
_at_fd = None


def _at_open():
    """Open the EC20 AT port once and keep it open (open/close per command
    makes the modem drop replies, which showed up as flaky SIM state)."""
    import termios
    global _at_fd
    fd = os.open(AT_PORT, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    attrs = termios.tcgetattr(fd)
    attrs[0] = 0
    attrs[1] = 0
    attrs[2] = termios.CLOCAL | termios.CREAD | termios.CS8
    attrs[3] = 0
    attrs[4] = termios.B115200
    attrs[5] = termios.B115200
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    _at_fd = fd


def at_cmd(cmd, wait=0.8):
    """Send one AT command on the persistent AT port and return the reply."""
    global _at_fd
    with _at_lock:
        try:
            if _at_fd is None:
                _at_open()
            for _ in range(4):
                try:
                    if not os.read(_at_fd, 4096):
                        break
                except (BlockingIOError, OSError):
                    break
            os.write(_at_fd, (cmd + "\r").encode())
            time.sleep(wait)
            out = b""
            while True:
                try:
                    chunk = os.read(_at_fd, 4096)
                except (BlockingIOError, OSError):
                    break
                if not chunk:
                    break
                out += chunk
            return out.decode("utf-8", "replace")
        except Exception:
            try:
                if _at_fd is not None:
                    os.close(_at_fd)
            except Exception:
                pass
            _at_fd = None
            return ""


def at_query(cmd, attempts=3, wait=0.9):
    """Retry a query a few times: the EC20 AT port occasionally drops replies."""
    out = ""
    for _ in range(attempts):
        out = at_cmd(cmd, wait=wait)
        if "OK" in out or "ERROR" in out or "+" in out:
            return out
        time.sleep(0.2)
    return out


_modem_cache = {"at": 0.0, "data": None}
_modem_last = {"at": 0.0}


def modem_state():
    now = time.time()
    if _modem_cache["data"] and now - _modem_cache["at"] < _modem_cache.get("ttl", 20):
        return _modem_cache["data"]
    st = {"present": os.path.exists(AT_PORT), "sim": "未知", "signal": None,
          "reg": "未知", "operator": None, "dialed": False, "ip": None,
          "raw_errors": []}
    if not st["present"]:
        st["sim"] = "未检测到 EC20"
        return st
    out = at_query("AT+CPIN?", attempts=3)
    if "READY" in out:
        st["sim"] = "就绪"
    elif "ERROR: 10" in out:
        st["sim"] = "未插入 SIM 卡"
    elif "SIM PIN" in out:
        st["sim"] = "需要 PIN"
    else:
        # 兜底：Quectel 的 SIM 插入状态
        q = at_query("AT+QSIMSTAT?", attempts=2)
        m = re.search(r"\+QSIMSTAT:\s*\d+,(\d+)", q)
        if m:
            st["sim"] = "就绪" if m.group(1) == "1" else "未插入 SIM 卡"
        else:
            st["sim"] = "读取中（AT 无响应）"
    out = at_query("AT+CSQ")
    m = re.search(r"\+CSQ:\s*(\d+),", out)
    if m:
        rssi = int(m.group(1))
        st["signal"] = 0 if rssi == 99 else min(100, max(0, int((rssi - 2) * 100 / 28)))
        st["rssi"] = rssi
    out = at_query("AT+CREG?")
    m = re.search(r"\+CREG:\s*\d+,(\d+)", out)
    if m:
        code = m.group(1)
        st["reg"] = {"0": "未注册", "1": "已注册（本地）", "2": "搜索中",
                     "3": "注册被拒", "4": "未知", "5": "已注册（漫游）"}.get(code, code)
    out = at_query("AT+COPS?", attempts=2, wait=1.2)
    m = re.search(r'\+COPS:\s*\d+,\d+,"([^"]+)"', out)
    if m:
        st["operator"] = m.group(1)
    rc, ipout = run(["ip", "-4", "-o", "addr", "show", "ec20"])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ipout)
    if m:
        st["ip"] = m.group(1)
    # 只有"已注册"且拿到地址才算真正拨号成功（无 SIM 时接口上仍有出厂静态地址）
    st["dialed"] = bool(st["ip"]) and str(st["reg"]).startswith("已注册")
    # AT 口偶尔丢回复：失败的字段沿用最近一次成功值，避免界面来回跳
    fresh = (time.time() - _modem_last.get("at", 0)) < 180
    for key in ("sim", "reg", "operator", "signal", "rssi"):
        val = st.get(key)
        bad = val in (None, "未知", "") or "读取中" in str(val)
        if bad and fresh and _modem_last.get(key) not in (None, ""):
            st[key] = _modem_last[key]
        elif not bad:
            _modem_last[key] = val
            _modem_last["at"] = time.time()
    ttl = 20 if "读取中" not in st["sim"] else 5
    _modem_cache.update({"at": time.time(), "data": st, "ttl": ttl})
    return st


def usb_devices():
    """USB devices currently on the bus (id, vendor:product, name)."""
    devs = []
    base = "/sys/bus/usb/devices"
    try:
        names = os.listdir(base)
    except OSError:
        return devs
    for name in sorted(names):
        d = os.path.join(base, name)
        try:
            with open(os.path.join(d, "idVendor"), encoding="ascii") as fh:
                vid = fh.read().strip()
            with open(os.path.join(d, "idProduct"), encoding="ascii") as fh:
                pid = fh.read().strip()
        except OSError:
            continue
        label = ""
        for attr in ("product", "manufacturer"):
            try:
                with open(os.path.join(d, attr), encoding="utf-8", errors="replace") as fh:
                    val = fh.read().strip()
                    if val:
                        label = (label + " " + val).strip()
            except OSError:
                pass
        if name.startswith("usb"):
            continue
        devs.append({"id": name, "vidpid": f"{vid}:{pid}", "name": label or "USB 设备"})
    return devs


def tspi_features():
    rc, out = run(["tspi-config", "--json", "status"], timeout=8)
    if rc != 0 or not out:
        return None, "tspi-config 读取失败"
    try:
        data = json.loads(out)
    except Exception:
        return None, "tspi-config 输出解析失败"
    if not data.get("ok", False):
        return None, data.get("message") or "tspi-config 返回失败"
    return data.get("features", []), None


def wifi_state():
    info = {"device": None, "state": "unknown", "ssid": None, "ip": None,
            "networks": [], "error": None}
    rc, out = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
    if rc != 0:
        info["error"] = "nmcli 不可用"
        return info
    dev = None
    candidates = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        d, typ, state = parts[0], parts[1], parts[2]
        if typ == "wifi" and not d.startswith("p2p"):
            candidates.append((d, state))
    # 优先选已连接的网卡，其次 disconnected，最后才轮到 unmanaged
    rank = {"connected": 0, "disconnected": 1, "unavailable": 2}
    candidates.sort(key=lambda c: rank.get(c[1], 3))
    if candidates:
        dev, info["state"] = candidates[0]
    raw = str(info["state"]).split(" (")[0]
    info["state_zh"] = {"connected": "已连接", "disconnected": "未连接",
                        "connecting": "正在获取地址", "disconnecting": "正在断开",
                        "unavailable": "不可用", "unmanaged": "未托管",
                        "unknown": "未知"}.get(raw, raw)
    info["device"] = dev
    if dev and info["state"] == "connected":
        rc, out = run(["nmcli", "-t", "-f", "GENERAL.CONNECTION,IP4.ADDRESS", "device", "show", dev])
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("GENERAL.CONNECTION:"):
                    info["ssid"] = line.split(":", 1)[1].strip() or None
                elif line.startswith("IP4.ADDRESS"):
                    info["ip"] = line.split(":", 1)[1].strip().split("/")[0] or None
    if dev:
        rc, out = run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY",
                       "device", "wifi", "list", "--rescan", "no"], timeout=8)
        if rc == 0:
            seen = set()
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) < 4:
                    continue
                ssid = parts[1].strip()
                if not ssid or ssid in seen:
                    continue
                seen.add(ssid)
                try:
                    signal = int(parts[2])
                except ValueError:
                    signal = 0
                info["networks"].append({
                    "ssid": ssid,
                    "in_use": parts[0].strip() == "*",
                    "signal": signal,
                    "security": parts[3].strip() or "开放",
                })
            info["networks"] = info["networks"][:12]
    return info


def ssh_state():
    _, active = run(["systemctl", "is-active", "ssh"])
    _, enabled = run(["systemctl", "is-enabled", "ssh"])
    return {"active": active == "active", "enabled": enabled == "enabled"}


def system_state(addr):
    _, host = run(["hostname"])
    _, kernel = run(["uname", "-r"])
    uptime_s = 0
    try:
        with open("/proc/uptime", "r", encoding="ascii") as fh:
            uptime_s = int(float(fh.read().split()[0]))
    except Exception:
        pass
    mem = {}
    try:
        info = {}
        with open("/proc/meminfo", "r", encoding="ascii") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                info[k] = int(v.strip().split()[0]) * 1024
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        if total:
            mem = {"total": total, "avail": avail,
                   "used": max(0, total - avail),
                   "pct": int(round((total - avail) * 100.0 / total))}
    except Exception:
        pass
    disks = []
    for mnt, label in (("/", "eMMC 系统分区"), ("/userdata", "eMMC 用户分区")):
        try:
            sv = os.statvfs(mnt)
            total = sv.f_blocks * sv.f_frsize
            free = sv.f_bavail * sv.f_frsize
            if total:
                disks.append({"label": label, "mount": mnt, "total": total,
                              "used": total - free,
                              "pct": int(round((total - free) * 100.0 / total))})
        except OSError:
            continue
    return {"hostname": host, "kernel": kernel, "uptime": uptime_s,
            "usb_address": addr, "mem": mem, "disks": disks}


def collect_status():
    now = time.time()
    if _status_cache["data"] and now - _status_cache["at"] < STATUS_TTL:
        return _status_cache["data"]
    addr = usb0_address()
    features, err = tspi_features()
    screens, fan = [], None
    if features:
        for f in features:
            if "screens" in (f.get("groups") or []):
                screens.append({
                    "id": f["id"], "name": f["name"],
                    "enabled": bool(f.get("enabled")),
                    "configured": bool(f.get("configured")),
                    "reboot_required": bool(f.get("reboot_required")),
                    "message": f.get("message"),
                })
            elif f.get("id") == "fan":
                fan = {"enabled": bool(f.get("enabled")),
                       "detail": f.get("detail") or {},
                       "message": f.get("message")}
    current = next((s for s in screens if s["enabled"]), None)
    data = {
        "generated_at": now,
        "tspi_error": err,
        "screens": screens,
        "current_screen": current["name"] if current else "未知",
        "running_screen": live_screen(),
        "fan": fan,
        "ssh": ssh_state(),
        "wifi": wifi_state(),
        "ethernet": ethernet_state(),
        "modem": modem_state(),
        "audio": audio_state(),
        "sd": sd_state(),
        "default_password": default_password_in_use(),
        "system": system_state(addr),
    }
    _status_cache["at"], _status_cache["data"] = now, data
    return data


def human_uptime(sec):
    d, rem = divmod(int(sec), 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d} 天 {h} 小时"
    if h:
        return f"{h} 小时 {m} 分"
    return f"{m} 分"


# ------------------------------------------------------------------- views

import base64

# 内置 logo 兜底：镜像资源漏装（v0.4.1 的 rootfs 早于资源提交，就会出现）时页面仍有 LOGO。
# 由 logo-small.png（sha256 99fc26a2…）生成一次嵌入；文件存在时以文件为准。
_LOGO_EMBED = (
    "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"
)
LOGO_DATA = ""
try:
    with open("/usr/local/share/tspi-web/logo-small.png", "rb") as _f:
        LOGO_DATA = "data:image/png;base64," + base64.b64encode(_f.read()).decode()
except Exception:
    pass
if not LOGO_DATA:
    LOGO_DATA = "data:image/png;base64," + _LOGO_EMBED


CSS = """
:root{
  --bg:#0a100d; --panel:rgba(18,26,22,.62); --panel-solid:#141d18;
  --ink:#f2f8f3; --ink-2:#c6d5c9; --ink-3:#8ea595;
  --line:rgba(242,248,243,.13); --line-2:rgba(242,248,243,.24);
  --copper:#c99055; --copper-dim:rgba(201,144,85,.16);
  --pulse:#82e6b4; --pulse-dim:rgba(130,230,180,.14);
  --bad:#e29090; --card-hover:rgba(24,34,28,.78); --r:14px;
}
html[data-theme="day"]{
  --bg:#ece7dc; --panel:rgba(255,253,247,.78); --panel-solid:#fffdf7;
  --ink:#141a16; --ink-2:#3d4a41; --ink-3:#6f7d73;
  --line:rgba(20,26,22,.14); --line-2:rgba(20,26,22,.28);
  --copper:#8a5a24; --copper-dim:rgba(138,90,36,.1);
  --pulse:#2f7a55; --pulse-dim:rgba(47,122,85,.1);
  --bad:#a34f4f; --card-hover:rgba(255,253,247,.97);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);min-height:100%;
  font:14px/1.75 "Alibaba PuHuiTi","PingFang SC","Microsoft YaHei",-apple-system,sans-serif;
  -webkit-font-smoothing:antialiased;transition:background .5s,color .5s}
.pcb{position:fixed;inset:0;z-index:0;pointer-events:none}
html[data-theme="day"] .pcb{opacity:.55}
.pcb svg{width:100%;height:100%;display:block}
.trace{fill:none;stroke:var(--copper);stroke-width:1.5;opacity:.30;stroke-linejoin:round}
.trace.t2{stroke-width:1;opacity:.22}
.trace.t3{stroke-width:2.4;opacity:.16}
.pad{fill:none;stroke:var(--copper);stroke-width:1.2;opacity:.4}
.pad-c{fill:var(--copper);opacity:.3}
.pulse{fill:none;stroke:var(--pulse);stroke-width:2.4;stroke-linecap:round;
  filter:drop-shadow(0 0 6px var(--pulse));opacity:.95;stroke-dasharray:44 2200;
  animation:flow 12s linear infinite}
@keyframes flow{from{stroke-dashoffset:0}to{stroke-dashoffset:-2244}}
.pulse:nth-child(2){animation-duration:9s;animation-delay:-2s}
.pulse:nth-child(3){animation-duration:15s;animation-delay:-5s}
.pulse:nth-child(4){animation-duration:11s;animation-delay:-8s}
.pulse:nth-child(5){animation-duration:17s;animation-delay:-3s}
.pulse:nth-child(6){animation-duration:10s;animation-delay:-6s}
.pulse:nth-child(7){animation-duration:13s;animation-delay:-9s}
.pulse:nth-child(8){animation-duration:8s;animation-delay:-1s}
.pulse:nth-child(9){animation-duration:16s;animation-delay:-11s}
.pulse:nth-child(10){animation-duration:12s;animation-delay:-4s}
.pulse:nth-child(11){animation-duration:14s;animation-delay:-7s}
.pulse:nth-child(12){animation-duration:9.5s;animation-delay:-10s}
.pulse:nth-child(13){animation-duration:18s;animation-delay:-12s}
.pulse:nth-child(14){animation-duration:11.5s;animation-delay:-13s}
.wrap{position:relative;z-index:1}
.top{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:14px;
  min-height:72px;padding:12px 24px;border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,rgba(10,16,13,.92),rgba(10,16,13,.55));backdrop-filter:blur(16px)}
html[data-theme="day"] .top{background:linear-gradient(180deg,rgba(236,231,220,.94),rgba(236,231,220,.6))}
.brand{display:flex;align-items:center;flex:none}
.brand img{height:46px;width:auto;display:block;margin-top:-2px}
html[data-theme="day"] .brand img{filter:invert(1) brightness(.18)}
.titles b{display:block;font-size:15px;font-weight:700;letter-spacing:.06em}
.titles span{display:block;font-size:11px;color:var(--ink-3);letter-spacing:.18em}
.grow{flex:1}
.state{display:inline-flex;align-items:center;gap:8px;font-size:12px;color:var(--ink-2);
  border:1px solid var(--line);padding:7px 13px;border-radius:8px;background:var(--panel);backdrop-filter:blur(8px)}
.state i{width:7px;height:7px;border-radius:50%;background:var(--pulse);box-shadow:0 0 8px var(--pulse);
  animation:blink 2.6s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
.tbtn{font:inherit;font-size:13px;font-weight:500;color:var(--ink-2);cursor:pointer;
  background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 14px;
  transition:.25s;backdrop-filter:blur(8px)}
.tbtn:hover{color:var(--ink);border-color:var(--copper);background:var(--copper-dim)}
.tbtn.primary{background:var(--copper);border-color:var(--copper);color:#150e05;font-weight:700}
.tbtn.primary:hover{filter:brightness(1.07)}
.page{max-width:1280px;margin:0 auto;padding:24px 24px 80px;display:grid;
  grid-template-columns:312px minmax(0,1fr);gap:18px;align-items:start}
aside{position:sticky;top:84px;display:grid;gap:18px}
.grid{display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.card{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  padding:20px;backdrop-filter:blur(9px) saturate(115%);
  box-shadow:0 1px 0 rgba(255,255,255,.05) inset, 0 20px 44px -30px #000;
  animation:rise .8s cubic-bezier(.2,.7,.2,1) both;transition:border-color .35s,background .35s}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.card:nth-child(2){animation-delay:.06s}.card:nth-child(3){animation-delay:.12s}
.card:nth-child(4){animation-delay:.18s}.card:nth-child(5){animation-delay:.24s}
.card:nth-child(6){animation-delay:.3s}
.card:hover{border-color:var(--line-2);background:var(--card-hover)}
.card::before,.card::after{content:"";position:absolute;width:7px;height:7px;border:1px solid var(--copper);opacity:.6}
.card::before{top:8px;left:8px;border-right:0;border-bottom:0}
.card::after{bottom:8px;right:8px;border-left:0;border-top:0}
.card h2{margin:0 0 14px;display:flex;align-items:center;gap:10px;font-size:11px;font-weight:600;
  letter-spacing:.22em;color:var(--ink-3)}
.card h2::after{content:"";flex:1;height:1px;background:var(--line)}
.lead{margin:0;font-size:26px;font-weight:700;line-height:1.3}
.lead small{display:block;font-size:12px;font-weight:400;color:var(--ink-3);margin-top:4px}
.note{margin:6px 0 0;font-size:12px;color:var(--ink-3)}
.rows{margin-top:12px}
.row{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:9px 0;
  border-top:1px solid var(--line);font-size:13px}
.row:first-child{border-top:0}
.row .k{color:var(--ink-3)}
.row .v{font-variant-numeric:tabular-nums}
.tag{font-size:12px;display:inline-flex;align-items:center;gap:7px}
.tag::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.tag.ok{color:var(--pulse)}.tag.warn{color:var(--copper)}.tag.off{color:var(--ink-3)}.tag.bad{color:var(--bad)}
.meter{height:4px;background:rgba(242,248,243,.1);margin:12px 0 4px;overflow:hidden;border-radius:2px}
html[data-theme="day"] .meter{background:rgba(20,26,22,.1)}
.meter i{display:block;height:100%;width:0;background:var(--pulse);box-shadow:0 0 10px var(--pulse);
  transition:width 1.2s cubic-bezier(.2,.7,.2,1)}
.meter.copper i{background:var(--copper);box-shadow:0 0 10px var(--copper)}
.meter-label{display:flex;justify-content:space-between;font-size:11px;color:var(--ink-3);margin-top:10px}
.act{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
.btn{font:inherit;font-size:13px;font-weight:500;cursor:pointer;padding:9px 15px;border-radius:8px;
  border:1px solid var(--line-2);background:transparent;color:var(--ink);transition:.22s}
.btn:hover{border-color:var(--pulse);color:var(--pulse);background:var(--pulse-dim)}
.btn.solid{background:var(--pulse);border-color:var(--pulse);color:#04140c;font-weight:700}
.btn.solid:hover{filter:brightness(1.06);color:#04140c}
html[data-theme="day"] .btn.solid{color:#fff}
html[data-theme="day"] .btn.solid:hover{color:#fff}
.btn.danger{color:var(--bad);border-color:rgba(226,144,144,.4)}
.btn.danger:hover{background:rgba(226,144,144,.12);border-color:var(--bad)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.seg{display:flex;border:1px solid var(--line);border-radius:8px;overflow:hidden;margin-top:14px}
.seg label{flex:1;text-align:center;font-size:12.5px;padding:9px 4px;cursor:pointer;color:var(--ink-3);
  border-right:1px solid var(--line);transition:.22s}
.seg label:last-child{border-right:0}
.seg input{display:none}
.seg input:checked+span{color:var(--pulse);font-weight:600}
.seg label:has(input:checked){background:var(--pulse-dim);color:var(--pulse)}
.seg label:hover{color:var(--ink)}
.list{margin:10px 0 0;padding:0;list-style:none;max-height:216px;overflow:auto}
.list li{display:flex;align-items:center;gap:10px;padding:9px 0;border-top:1px solid var(--line);font-size:12.5px}
.list li:first-child{border-top:0}
.list .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.list .meta{font-size:11px;color:var(--ink-3);font-variant-numeric:tabular-nums}
.list a{color:var(--ink);text-decoration:none}
.list a:hover{color:var(--pulse)}
.bars{display:flex;align-items:flex-end;gap:2px;height:12px}
.bars i{width:3px;background:var(--ink-3);opacity:.35;border-radius:1px}
.bars i.on{background:var(--pulse);opacity:1;box-shadow:0 0 6px var(--pulse)}
.mini{font:inherit;font-size:11.5px;color:var(--pulse);background:transparent;
  border:1px solid rgba(130,230,180,.4);border-radius:6px;padding:3px 9px;cursor:pointer;transition:.2s}
.mini:hover{background:var(--pulse-dim)}
.switch{display:inline-flex;align-items:center;gap:10px;cursor:pointer;user-select:none}
.switch .track{width:40px;height:20px;border:1px solid var(--line-2);border-radius:10px;position:relative;transition:.3s}
.switch .track::after{content:"";position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;
  background:var(--ink-3);transition:.3s cubic-bezier(.2,.7,.2,1)}
.switch.on .track{border-color:var(--pulse);background:var(--pulse-dim)}
.switch.on .track::after{left:22px;background:var(--pulse);box-shadow:0 0 8px var(--pulse)}
.switch span{font-size:12.5px;color:var(--ink-2)}
.wave{display:flex;align-items:center;gap:2px;height:44px;margin-top:14px}
.wave i{flex:1;background:var(--pulse);opacity:.55;border-radius:1px;animation:lvl 2.4s ease-in-out infinite}
@keyframes lvl{0%,100%{transform:scaleY(.3);opacity:.3}50%{transform:scaleY(1);opacity:.8}}
input[type=password],input[type=number],select{width:100%;padding:10px 12px;border-radius:8px;
  border:1px solid var(--line-2);background:var(--panel-solid);color:var(--ink);font:inherit;font-size:13px}
input[type=password]:focus,select:focus{outline:2px solid var(--pulse);outline-offset:1px}
input[type=range]{width:100%;accent-color:var(--pulse)}
label.fld{display:block;font-size:12px;color:var(--ink-3);margin:14px 0 6px}
.toasts{position:fixed;right:22px;bottom:22px;display:grid;gap:10px;z-index:60}
.toast{padding:12px 18px;border:1px solid var(--line-2);border-radius:10px;background:var(--panel-solid);
  color:var(--ink);font-size:13px;box-shadow:0 18px 40px -20px #000;animation:tin .45s both}
.toast.ok{border-color:var(--pulse);color:var(--pulse)}
.toast.err{border-color:var(--bad);color:var(--bad)}
.rec-player{display:flex;align-items:center;gap:8px;margin-top:10px}
.rec-bar{flex:1;height:6px;border-radius:3px;background:var(--line);cursor:pointer;position:relative;touch-action:none}
.rec-bar i{position:absolute;left:0;top:0;bottom:0;width:0;border-radius:3px;background:var(--pulse)}
.rec-time{font-size:11.5px;color:var(--ink-3);font-variant-numeric:tabular-nums;white-space:nowrap}
.recwave:empty{display:none}
html.js #rec-audio{display:none}
html:not(.js) #rec-audio{width:100%;margin-top:10px}
html:not(.js) .rec-player{display:none}
@keyframes tin{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
/* JS 开启时操作结果只走右下角 toast，正文内联行隐藏；JS 关闭时保留（无 JS 回退） */
html.js .flash-op{display:none}
/* 附近网络列表的「连接」是选中动作（靠 JS 填充表单），无 JS 时隐藏，避免点了没反应 */
.wifi-pick{display:none}
html.js .wifi-pick{display:inline-block}
.list li.sel{background:var(--pulse-dim);border-radius:8px}
.ok{color:var(--pulse);font-size:13px;margin:8px 0}
.err{color:var(--bad);font-size:13px;margin:8px 0}
.loginwrap{max-width:420px;margin:10vh auto;padding:0 20px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
table a{color:var(--ink);text-decoration:none}
table a:hover{color:var(--pulse)}
th,td{padding:9px 6px;border-bottom:1px solid var(--line);text-align:left}
th{color:var(--ink-3);font-weight:500;font-size:11px;letter-spacing:.1em}
@media (max-width:920px){
  .page{grid-template-columns:1fr;padding:16px 14px 60px}
  aside{position:static}
  .titles span{display:none}
  .brand img{height:38px}
}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

PCB = """
<div class="pcb" aria-hidden="true"><svg viewBox="0 0 1600 1000" preserveAspectRatio="xMidYMid slice">
<g>
<path class="trace" d="M-40 90 H240 L300 150 H620 L680 210 H1040 L1100 270 H1500"/>
<path class="trace t2" d="M-40 140 H220 L280 200 H600"/>
<path class="trace t3" d="M-40 230 H180 L240 290 H560 L620 350 H980"/>
<path class="trace" d="M-40 430 H160 L220 370 H480 L540 430 H840 L900 490 H1260 L1320 550 H1640"/>
<path class="trace t2" d="M-40 480 H140 L200 420 H460"/>
<path class="trace" d="M-40 700 H300 L360 640 H700 L760 700 H1120"/>
<path class="trace t2" d="M-40 760 H280 L340 700 H680"/>
<path class="trace t3" d="M-40 900 H420 L480 840 H860 L920 900 H1400"/>
<path class="trace" d="M1640 120 H1380 L1320 180 H1000 L940 240 H700"/>
<path class="trace t2" d="M1640 320 H1400 L1340 260 H1080"/>
<path class="trace" d="M1640 520 H1420 L1360 460 H1060 L1000 520 H760 L700 580 H420"/>
<path class="trace t2" d="M1640 820 H1300 L1240 760 H900"/>
<path class="trace" d="M200 1040 V760 L260 700 V470 L320 410 V220"/>
<path class="trace t2" d="M260 1040 V800"/>
<path class="trace" d="M760 1040 V840 L820 780 H1180"/>
<path class="trace" d="M1140 -40 V180 L1080 240 V520 L1020 580 V820"/>
<path class="trace t2" d="M1200 -40 V160"/>
<path class="trace" d="M420 -40 V210 L480 270 V540 L540 600 V880"/>
<path class="trace t2" d="M480 -40 V180"/>
<path class="trace" d="M900 -40 V120 L960 180 V420"/>
<path class="trace t3" d="M1480 -40 V260 L1420 320 V600 L1360 660 V940"/>
</g><g>
<path class="pulse" d="M-40 90 H240 L300 150 H620 L680 210 H1040 L1100 270 H1500"/>
<path class="pulse" d="M-40 430 H160 L220 370 H480 L540 430 H840 L900 490 H1260 L1320 550 H1640"/>
<path class="pulse" d="M-40 700 H300 L360 640 H700 L760 700 H1120"/>
<path class="pulse" d="M-40 900 H420 L480 840 H860 L920 900 H1400"/>
<path class="pulse" d="M1640 120 H1380 L1320 180 H1000 L940 240 H700"/>
<path class="pulse" d="M1640 520 H1420 L1360 460 H1060 L1000 520 H760 L700 580 H420"/>
<path class="pulse" d="M1640 820 H1300 L1240 760 H900"/>
<path class="pulse" d="M200 1040 V760 L260 700 V470 L320 410 V220"/>
<path class="pulse" d="M760 1040 V840 L820 780 H1180"/>
<path class="pulse" d="M1140 -40 V180 L1080 240 V520 L1020 580 V820"/>
<path class="pulse" d="M420 -40 V210 L480 270 V540 L540 600 V880"/>
<path class="pulse" d="M900 -40 V120 L960 180 V420"/>
<path class="pulse" d="M1480 -40 V260 L1420 320 V600 L1360 660 V940"/>
<path class="pulse" d="M-40 230 H180 L240 290 H560 L620 350 H980"/>
</g><g>
<circle class="pad" cx="240" cy="90" r="5"/><circle class="pad-c" cx="240" cy="90" r="2"/>
<circle class="pad" cx="620" cy="150" r="5"/><circle class="pad-c" cx="620" cy="150" r="2"/>
<circle class="pad" cx="1040" cy="210" r="5"/><circle class="pad-c" cx="1040" cy="210" r="2"/>
<circle class="pad" cx="480" cy="370" r="5"/><circle class="pad-c" cx="480" cy="370" r="2"/>
<circle class="pad" cx="840" cy="430" r="5"/><circle class="pad-c" cx="840" cy="430" r="2"/>
<circle class="pad" cx="1260" cy="490" r="5"/><circle class="pad-c" cx="1260" cy="490" r="2"/>
<circle class="pad" cx="700" cy="640" r="5"/><circle class="pad-c" cx="700" cy="640" r="2"/>
<circle class="pad" cx="860" cy="840" r="5"/><circle class="pad-c" cx="860" cy="840" r="2"/>
<circle class="pad" cx="1380" cy="120" r="5"/><circle class="pad-c" cx="1380" cy="120" r="2"/>
<circle class="pad" cx="1060" cy="460" r="5"/><circle class="pad-c" cx="1060" cy="460" r="2"/>
<circle class="pad" cx="260" cy="700" r="5"/><circle class="pad-c" cx="260" cy="700" r="2"/>
<circle class="pad" cx="1080" cy="240" r="5"/><circle class="pad-c" cx="1080" cy="240" r="2"/>
<circle class="pad" cx="480" cy="270" r="5"/><circle class="pad-c" cx="480" cy="270" r="2"/>
<circle class="pad" cx="960" cy="180" r="5"/><circle class="pad-c" cx="960" cy="180" r="2"/>
</g></svg></div>
"""



def esc(v):
    return html.escape("" if v is None else str(v))


def ec(v):
    return html.escape(v)
def page(title, body, extra_head=""):
    return f"""<!DOCTYPE html>
<html lang="zh-CN" data-theme="night">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<script>document.documentElement.classList.add('js')</script>
<title>{esc(title)} · 泰山派 1M 配置中心</title>
<style>{CSS}</style>{extra_head}
</head>
<body>
{PCB}
<div class="wrap">
{body}
</div>
<div class="toasts" id="toasts" aria-live="polite"></div>
{USB_JS}
</body>
</html>"""


def _brand():
    if LOGO_DATA:
        return f'<div class="brand"><img src="{LOGO_DATA}" alt="LCKFB 嘉立创开源硬件平台"></div>'
    return '<div class="brand" style="font-size:18px;letter-spacing:.2em;font-weight:700">LCKFB</div>'


def login_page(csrf, error=""):
    # 登录失败：页面加载后弹 toast（A）；正文保留同样文字作为无 JS 回退。
    err_toast = ""
    if error:
        err_toast = ('<script>window.addEventListener("load",function(){showResult(false,'
                     + json.dumps(error, ensure_ascii=False) + ');});</script>')
    body = f"""
<div class="loginwrap">
  <section class="card">
    <div style="display:flex;justify-content:center;margin-bottom:18px">{_brand()}</div>
    <h2 style="justify-content:center">登录 LOGIN</h2>
    <p class="note" style="text-align:center">用系统账号 {esc(LOGIN_USER)} 的密码登录</p>
    <form method="post" action="/login">
      <input type="hidden" name="csrf" value="{esc(csrf)}">
      <label class="fld" for="password">密码</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <p class="note" style="margin-top:10px">首次登录密码是 {esc(DEFAULT_PASSWORD)}（默认），登录后请立即修改。</p>
      {'<p class="err flash-op" role="alert">' + esc(error) + '</p>' if error else ''}
      {err_toast}
      <div class="act" style="justify-content:center"><button class="btn solid" type="submit">登录</button></div>
    </form>
  </section>
</div>"""
    return page("登录", body)


USB_JS = """
<script>
function toggleTheme(){
  var d=document.documentElement;
  var t = d.dataset.theme==='day' ? 'night' : 'day';
  d.dataset.theme = t;
  try{ localStorage.setItem('tspi-theme', t); }catch(e){}
}
try{
  var saved=localStorage.getItem('tspi-theme');
  if(saved){ document.documentElement.dataset.theme=saved; }
}catch(e){}
function initFx(){
  document.querySelectorAll('.meter i').forEach(function(el,i){
    setTimeout(function(){ el.style.width=(el.dataset.w||0)+'%'; }, 150+i*70);
  });
  document.querySelectorAll('.wave').forEach(function(w){
    if(w.classList.contains('recwave')){ return; }
    if(w.dataset.done){ return; }
    w.dataset.done='1';
    for(var i=0;i<48;i++){
      var b=document.createElement('i');
      b.style.height=(18+Math.random()*82)+'%';
      b.style.animationDelay=(Math.random()*2.4).toFixed(2)+'s';
      w.appendChild(b);
    }
  });
}
window.addEventListener('load',initFx);
// 录音回放：隐藏的 <audio> + 自定义一行控件（播放/暂停、可点击/拖动进度、时间）。
// 不自动播放；录音完成后由 APPLY['/audio/record'] 换 src 并归零。
(function(){
  var a=document.getElementById('rec-audio');
  var bar=document.getElementById('rec-bar');
  if(!a||!bar){ return; }
  var pb=document.getElementById('rec-play'), cur=document.getElementById('rec-cur'),
      dur=document.getElementById('rec-dur'), fill=document.getElementById('rec-fill');
  function fmt(t){
    if(!isFinite(t)||t<0){ t=0; }
    var m=Math.floor(t/60), s=Math.floor(t%60);
    return m+':'+(s<10?'0':'')+s;
  }
  function upd(){
    if(isFinite(a.duration)&&a.duration>0){ fill.style.width=(a.currentTime/a.duration*100)+'%'; }
    cur.textContent=fmt(a.currentTime);
  }
  a.addEventListener('loadedmetadata', function(){ dur.textContent=fmt(a.duration); upd(); });
  a.addEventListener('timeupdate', upd);
  a.addEventListener('ended', function(){
    pb.textContent='▶ 在电脑播放';
    fill.style.width='0%';
    cur.textContent='0:00';
  });
  function seek(e){
    if(!isFinite(a.duration)||!a.duration){ return; }
    var r=bar.getBoundingClientRect();
    var p=(e.clientX-r.left)/r.width;
    p=Math.max(0,Math.min(1,p));
    a.currentTime=p*a.duration;
    upd();
  }
  var drag=false;
  bar.addEventListener('pointerdown', function(e){
    drag=true;
    try{ bar.setPointerCapture(e.pointerId); }catch(ex){}
    seek(e);
  });
  bar.addEventListener('pointermove', function(e){ if(drag){ seek(e); } });
  bar.addEventListener('pointerup', function(){ drag=false; });
  bar.addEventListener('pointercancel', function(){ drag=false; });
  pb.addEventListener('click', function(){
    if(a.paused){ a.play(); pb.textContent='⏸ 暂停'; }
    else{ a.pause(); pb.textContent='▶ 在电脑播放'; }
  });
})();
function toast(msg,keep){
  var box=document.getElementById('toasts');
  if(!box){ return null; }
  var t=document.createElement('div');
  t.className='toast'; t.textContent=msg;
  box.appendChild(t);
  if(!keep){
    setTimeout(function(){t.style.opacity='0';t.style.transition='.4s';},2400);
    setTimeout(function(){t.remove();},2900);
  }
  return t;
}
function showResult(ok,text){
  var box=document.getElementById('toasts');
  if(!box){ return; }
  var t=document.createElement('div');
  t.className='toast '+(ok?'ok':'err');
  t.textContent=text;
  box.appendChild(t);
  setTimeout(function(){t.style.opacity='0';t.style.transition='.4s';},2500);
  setTimeout(function(){t.remove();},3000);
}
// 附近网络列表的「连接」是选中动作：把 SSID 填进下方表单、滚到表单并聚焦
// （开放网络聚焦提交按钮，加密网络聚焦密码框），真正的提交走下方表单。
document.addEventListener('click', function(e){
  var b=e.target.closest ? e.target.closest('.wifi-pick') : null;
  if(!b){ return; }
  var card=b.closest('.card'), f=card&&card.querySelector('form[action="/wifi/connect"]');
  if(!f){ return; }
  var inp=f.querySelector('input[name=ssid]'), pw=f.querySelector('input[name=password]');
  if(inp){ inp.value=b.getAttribute('data-ssid')||''; }
  var li=b.closest('li');
  card.querySelectorAll('.list li.sel').forEach(function(x){ x.classList.remove('sel'); });
  if(li){ li.classList.add('sel'); }
  if(f.scrollIntoView){ try{ f.scrollIntoView({behavior:'smooth',block:'center'}); }catch(ex){ f.scrollIntoView(); } }
  if(b.hasAttribute('data-open')){
    var sb=f.querySelector('button[type="submit"],button:not([type])');
    if(sb){ sb.focus(); }
  } else if(pw){
    pw.focus();
  }
});
// 操作表单统一 fetch 提交：进度 toast 不自动消失，结果按 ok/err 着色约 3 秒消失。
// 任何操作都不替换 .wrap/.page；有状态变化的只就地更新该操作自己的控件（APPLY），
// 无状态变化的操作（ping/各类测试/播放录音/重启）除 toast 外不动 DOM。
// /login、/logout 属于导航，不拦截；确认框取消（defaultPrevented）也不拦截。
var APPLY={
  '/fan':function(f,j){
    if(typeof j.fan_enabled!=='boolean'){ return; }
    var inp=f.querySelector('input[name=value]');
    if(inp){ inp.value=j.fan_enabled?'off':'on'; }
    var sw=document.getElementById('fan-switch');
    if(sw){
      sw.classList.toggle('on',j.fan_enabled);
      var tx=sw.lastElementChild;
      if(tx){ tx.textContent=j.fan_enabled?'已开启':'已关闭'; }
    }
    var row=document.getElementById('fan-pwm-row'), pv=document.getElementById('fan-pwm');
    if(row&&pv&&j.pwm!=null){ row.style.display=''; pv.textContent='PWM '+j.pwm; }
  },
  '/screen':function(f,j){
    if(typeof j.fid==='string'){
      f.querySelectorAll('input[name=screen]').forEach(function(r){ r.checked=(r.value===j.fid); });
    }
    var note=document.getElementById('screen-note');
    if(note&&typeof j.configured==='string'){
      note.textContent='已配置为 '+j.configured+'，重启后生效';
      note.style.display=j.pending?'':'none';
    }
  },
  '/wifi/scan':function(f,j){
    if(typeof j.list_html!=='string'){ return; }
    var card=f.closest('.card'), ul=card&&card.querySelector('ul.list');
    if(ul){ ul.innerHTML=j.list_html; }
  },
  '/wifi/connect':function(f,j){
    if(typeof j.lead_html!=='string'){ return; }
    var card=f.closest('.card'), lead=card&&card.querySelector('p.lead');
    if(lead){ lead.outerHTML=j.lead_html; }
  },
  '/audio/volume':function(f,j){
    if(typeof j.volume!=='number'){ return; }
    var v=String(j.volume);
    var lead=document.getElementById('vol-lead');
    if(lead&&lead.firstChild){ lead.firstChild.textContent=v+'%'; }
    var note=document.getElementById('vol-note');
    if(note){ note.textContent=v+'%'; }
    var inp=f.querySelector('input[name=value]');
    if(inp){ inp.value=v; }
  },
  '/audio/record':function(f,j){
    if(!j.ok){ return; }
    var blk=document.getElementById('rec-block'), emp=document.getElementById('rec-empty'),
        a=document.getElementById('rec-audio');
    if(!blk||!a){ return; }
    if(emp){ emp.style.display='none'; }
    blk.style.display='';
    if(j.rec&&j.rec.levels){
      var meta=document.getElementById('rec-meta');
      if(meta){ meta.textContent='最近一次录音 — '+(j.rec.at||'')+' · '+(j.rec.seconds||'')+' 秒 · 峰值 '+(j.rec.peak||''); }
      var w=document.getElementById('recwave');
      if(w){
        w.innerHTML='';
        for(var i=0;i<j.rec.levels.length;i++){
          var b=document.createElement('i');
          b.style.height=Math.max(6,Math.round(j.rec.levels[i]*100))+'%';
          b.style.animation='none';
          b.style.opacity='.8';
          w.appendChild(b);
        }
      }
    }
    if(typeof j.version==='string'&&j.version){ a.src='/audio/rec.wav?v='+encodeURIComponent(j.version); }
    a.load();
    var pb=document.getElementById('rec-play');
    if(pb){ pb.textContent='▶ 在电脑播放'; }
    var fill=document.getElementById('rec-fill');
    if(fill){ fill.style.width='0%'; }
    var cur=document.getElementById('rec-cur');
    if(cur){ cur.textContent='0:00'; }
    var dur=document.getElementById('rec-dur');
    if(dur){ dur.textContent='0:00'; }
  },
  '/sd/mount':function(f,j){
    if(typeof j.body_html!=='string'){ return; }
    var b=document.getElementById('sd-body');
    if(b){ b.innerHTML=j.body_html; }
  },
  '/sd/delete':function(f,j){
    if(!j.ok){ return; }
    var tr=f.closest('tr');
    if(tr){ tr.remove(); }
  }
};
document.addEventListener('submit', function(e){
  var f=e.target;
  if(e.defaultPrevented){ return; }
  var act=(f.getAttribute&&f.getAttribute('action'))||'';
  var p=location.pathname;
  var onHome=(p==='/'&&act!=='/login'&&act!=='/logout');
  var onOther=((p==='/password'&&act==='/password')||(p==='/sd/list'&&act==='/sd/delete'));
  if(!(onHome||onOther)){ return; }
  if((f.getAttribute('method')||'').toLowerCase()!=='post'){ return; }
  e.preventDefault();
  var busy=f.getAttribute('data-busy')||'正在执行…';
  var btn=f.querySelector('button[type="submit"],button:not([type])');
  // 风扇按钮内含开关 DOM，不能整体换成文字，只禁用
  var btnText=(btn&&!btn.firstElementChild)?btn.textContent:'';
  if(btn){ btn.disabled=true; if(btnText){ btn.textContent=busy; } }
  var bt=toast(busy,true);
  function done(){
    if(bt&&bt.parentNode){ bt.remove(); }
    if(btn){ btn.disabled=false; if(btnText){ btn.textContent=oldBtn; } }
  }
  var oldBtn=btnText;
  fetch(act,{method:'POST',body:new URLSearchParams(new FormData(f)),headers:{'X-Requested-With':'fetch'},cache:'no-store'})
    .then(function(r){
      var ct=r.headers.get('content-type')||'';
      if(ct.indexOf('json')<0){ location.reload(); return; }
      return r.json();
    })
    .then(function(j){
      if(!j){ return; }
      done();
      var ap=APPLY[act];
      if(ap){ try{ ap(f,j); }catch(ex){} }
      showResult(!!j.ok, j.message||(j.ok?'操作完成':'操作失败'));
    })
    .catch(function(){ done(); showResult(false,'网络错误或服务无响应'); });
});
// 带 ?msg= / ?err= / ?c=&ok=&m= 打开页面时（无 JS 回退提交后的跳转）：
// 逐条弹 toast，并清掉这些查询参数，刷新不重复弹。
(function(){
  var q=new URLSearchParams(location.search);
  var list=[];
  var m=q.get('msg'), err=q.get('err');
  if(m){ list.push([true,m]); }
  if(err){ list.push([false,err]); }
  if(location.pathname==='/' && q.get('c') && q.get('m')){
    list.push([(q.get('ok')||'1')==='1', q.get('m')]);
  }
  if(!list.length){ return; }
  q.delete('msg'); q.delete('err'); q.delete('c'); q.delete('ok'); q.delete('m');
  var s=q.toString();
  try{ history.replaceState(null,'',location.pathname+(s?'?'+s:'')); }catch(ex){}
  list.forEach(function(it,i){
    setTimeout(function(){ showResult(it[0],it[1]); }, 250+i*250);
  });
})();
(function(){
  var prev=null;
  function key(d){ return d.id+'|'+d.vidpid; }
  function poll(){
    fetch('/api/usb',{cache:'no-store'}).then(function(r){ return r.ok?r.json():null; }).then(function(j){
      if(!j){ return; }
      var cur=j.devices||[];
      if(prev){
        var p={},c={};
        prev.forEach(function(d){p[key(d)]=d;});
        cur.forEach(function(d){c[key(d)]=d;});
        cur.forEach(function(d){ if(!p[key(d)]){ toast('USB 已插入：'+d.name+'（'+d.vidpid+'）'); } });
        prev.forEach(function(d){ if(!c[key(d)]){ toast('USB 已拔出：'+d.name+'（'+d.vidpid+'）'); } });
      }
      prev=cur;
    }).catch(function(){});
  }
  poll(); setInterval(poll,3000);
})();
</script>
"""


def _cm(card_msg, card):
    item = (card_msg or {}).get(card)
    if not item:
        return ""
    ok, text = item
    cls = "ok" if ok else "err"
    return f'<p class="{cls} flash-op" role="status">{esc(text)}</p>'


def _wifi_lead_html(wifi):
    return (f'<p class="lead" id="wifi-lead">{esc(wifi.get("ssid") or "未连接")}'
            f'<small>{esc(wifi.get("device") or "-")} · {esc(wifi.get("state_zh") or "-")}'
            f' · {esc(wifi.get("ip") or "无 IP")}</small></p>')


def _wifi_list_html(nets):
    items = ""
    for n in nets:
        sig = n.get("signal") or 0
        on = max(1, min(4, int(round(sig / 25.0))))
        bars = "".join(
            f'<i style="height:{5 + i * 2}px" class="{"on" if i < on else ""}"></i>'
            for i in range(1, 5))
        sec = n.get("security") or "开放"
        # 列表里的「连接」只是选中动作（type=button + JS 填 SSID），无 JS 时整个按钮隐藏
        open_attr = ' data-open="1"' if sec == "开放" else ""
        items += (f'<li><span class="nm">{esc(n["ssid"])}</span>'
                  f'<span class="bars">{bars}</span>'
                  f'<span class="meta">{esc(sec)}</span>'
                  f'<button class="mini wifi-pick" type="button" data-ssid="{esc(n["ssid"])}"{open_attr}>连接</button></li>')
    if not items:
        items = '<li><span class="nm" style="color:var(--ink-3)">未扫描到网络</span></li>'
    return items


def _sd_body_html(sd, csrf):
    if sd.get("present"):
        size_gb = (sd.get("size") or 0) / (1024 ** 3)
        sd_body = (f'<p class="lead">{size_gb:.1f} GB<small>{esc(sd.get("mounted") or "未挂载")}</small></p>')
        if sd.get("mounted"):
            sd_body += (f'<div class="act"><a class="btn" href="/sd/list?path=/">浏览全部</a></div>'
                        f'<form method="post" action="/sd/test" data-busy="测试中…">'
                        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                        f'<div class="act"><button class="btn" type="submit">读写测试</button></div></form>')
        return sd_body
    return ('<p class="lead">未检测到 SD 卡</p>'
            + (f'<p class="note">{esc(sd.get("error"))}</p>' if sd.get("error") else ''))


def status_page(data, csrf, msg="", err_msg="", card_msg=None):
    screens = data.get("screens") or []
    running = data.get("running_screen") or "未知"
    configured = data.get("current_screen") or "未知"
    fan = data.get("fan") or {}
    wifi = data.get("wifi") or {}
    ssh = data.get("ssh") or {}
    eth = data.get("ethernet") or []
    modem = data.get("modem") or {}
    audio = data.get("audio") or {}
    sd = data.get("sd") or {}
    sysinfo = data.get("system") or {}
    pending = configured != running and configured != "未知"

    flash = ""
    if msg:
        flash += f'<p class="ok flash-op" role="status">{esc(msg)}</p>'
    if err_msg:
        flash += f'<p class="err flash-op" role="alert">{esc(err_msg)}</p>'
    if data.get("tspi_error"):
        flash += f'<p class="err" role="alert">{esc(data["tspi_error"])}</p>'
    if data.get("default_password"):
        flash += ('<p class="err" role="alert">当前仍是默认密码，点右上角「修改密码」修改</p>')

    # 屏幕
    radios = ""
    for s in screens:
        checked = " checked" if s["enabled"] else ""
        radios += (f'<label><input type="radio" name="screen" value="{esc(s["id"])}"{checked}>'
                   f'<span>{esc(s["name"])}</span></label>')
    rows = ""
    for s in screens:
        if s["name"] == running:
            tag = '<span class="tag ok">运行中</span>'
        elif s["enabled"]:
            tag = '<span class="tag warn">已配置 · 待重启</span>'
        else:
            tag = '<span class="tag off">未启用</span>'
        rows += f'<div class="row"><span class="k">{esc(s["name"])}</span>{tag}</div>'
    note_disp = "" if pending else "none"
    screen_card = f"""
    <section class="card">
      <h2>屏幕 DISPLAY</h2>
      <p class="lead">{esc(running)}<small>当前正在输出 · 实时读取设备树</small></p>
      <p class="note" id="screen-note" style="color:var(--copper);display:{note_disp}">已配置为 {esc(configured)}，重启后生效</p>
      <div class="rows">{rows}</div>
      <form method="post" action="/screen" data-busy="正在切换屏幕…">
        <input type="hidden" name="csrf" value="{esc(csrf)}">
        <div class="seg">{radios}</div>
        <div class="act"><button class="btn solid" type="submit">切换屏幕</button></div>
      </form>
    </section>"""

    # WiFi
    nets = wifi.get("networks") or []
    wifi_card = f"""
    <section class="card">
      <h2>WIFI 无线</h2>
      {_cm(card_msg, "wifi")}
      {_wifi_lead_html(wifi)}
      <p class="note">附近网络</p>
      <ul class="list">{_wifi_list_html(nets)}</ul>
      <form method="post" action="/wifi/connect" data-busy="连接中…" style="margin-top:14px">
        <input type="hidden" name="csrf" value="{esc(csrf)}">
        <label class="fld" for="wifi-ssid">WiFi 名称（SSID）</label>
        <input id="wifi-ssid" name="ssid" type="text" placeholder="点上方列表「连接」填入，或手动输入"
               style="width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--line-2);background:var(--panel-solid);color:var(--ink);font:inherit;font-size:13px">
        <label class="fld" for="wifi-pw">密码</label>
        <input id="wifi-pw" name="password" type="password" placeholder="WiFi 密码（开放网络留空）">
        <div class="act"><button class="btn solid" type="submit">连接</button></div>
      </form>
      <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">
        <form method="post" action="/wifi/scan" data-busy="扫描中…" style="margin:0">
          <input type="hidden" name="csrf" value="{esc(csrf)}">
          <button class="btn" type="submit">重新扫描</button>
        </form>
        <form method="post" action="/net/ping" data-busy="Ping 测试中…" style="margin:0">
          <input type="hidden" name="csrf" value="{esc(csrf)}">
          <input type="hidden" name="iface" value="{esc(wifi.get('device') or '')}">
          <input type="hidden" name="label" value="WiFi">
          <input type="hidden" name="card" value="wifi">
          <button class="btn" type="submit">Ping 测试</button>
        </form>
      </div>
    </section>"""

    # 4G
    sig = modem.get("signal")
    modem_body = ""
    if not modem.get("present", True):
        modem_body = '<p class="lead">未检测到 EC20</p>'
    else:
        modem_body = f"""
      <p class="lead">{esc(modem.get('operator') or '未注册')}<small>{esc(modem.get('reg') or '')}</small></p>
      <div class="rows">
        <div class="row"><span class="k">SIM 卡</span><span class="tag {'ok' if modem.get('sim') == '就绪' else 'off'}">{esc(modem.get('sim'))}</span></div>
        <div class="row"><span class="k">拨号</span><span class="tag {'ok' if modem.get('dialed') else 'off'}">{'已连接' if modem.get('dialed') else '未连接'}</span></div>
        <div class="row"><span class="k">IP 地址</span><span class="v">{esc(modem.get('ip') or '—')}</span></div>
      </div>
      <div class="meter copper"><i data-w="{sig if sig is not None else 0}"></i></div>
      <p class="note">信号 {sig if sig is not None else '—'}%（RSSI {esc(modem.get('rssi', '—'))}）</p>"""
    modem_card = f"""
    <section class="card">
      <h2>4G · EC20</h2>
      {_cm(card_msg, "4g")}
      {modem_body}
      <form method="post" action="/net/ping" data-busy="Ping 测试中…">
        <input type="hidden" name="csrf" value="{esc(csrf)}">
        <input type="hidden" name="iface" value="ec20">
        <input type="hidden" name="label" value="4G">
        <input type="hidden" name="card" value="4g">
        <div class="act"><button class="btn" type="submit">Ping 测试</button></div>
      </form>
    </section>"""

    # 音频
    vol = audio.get("volume")
    vol = 0 if vol is None else vol
    rec = audio.get("rec") or {}
    has_rec = os.path.exists(REC_FILE)
    # 回放区始终渲染（还没有录音时隐藏），录音完成后 APPLY['/audio/record'] 就地展开；
    # 只要 rec.wav 还在就显示，服务重启后不消失。
    if rec.get("levels"):
        bars = "".join(f'<i style="height:{max(6, int(v * 100))}%;animation:none;opacity:.8"></i>'
                       for v in rec["levels"])
        rec_meta = (f'最近一次录音 — {esc(rec.get("at"))} · '
                    f'{esc(rec.get("seconds"))} 秒 · 峰值 {esc(rec.get("peak"))}')
    else:
        bars = ""
        rec_meta = "最近一次录音"
    rec_src = ' src="/audio/rec.wav"' if has_rec else ""
    rec_block = f"""
      <p class="note" id="rec-empty" style="margin-top:10px;{'display:none' if has_rec else ''}">还没有录音</p>
      <div id="rec-block" style="{'display:none' if not has_rec else ''}">
        <p class="note" id="rec-meta" style="margin-top:12px">{rec_meta}</p>
        <div class="wave recwave" data-static="1" id="recwave">{bars}</div>
        <audio id="rec-audio" controls preload="metadata"{rec_src}></audio>
        <div class="rec-player">
          <button type="button" class="btn" id="rec-play">▶ 在电脑播放</button>
          <span class="rec-time" id="rec-cur">0:00</span>
          <div class="rec-bar" id="rec-bar"><i id="rec-fill"></i></div>
          <span class="rec-time" id="rec-dur">0:00</span>
        </div>
        <form method="post" action="/audio/play-rec" data-busy="回放中…">
          <input type="hidden" name="csrf" value="{esc(csrf)}">
          <div class="act"><button class="btn" type="submit">喇叭播放录音</button></div>
        </form>
      </div>"""
    audio_card = f"""
    <section class="card">
      <h2>音频 AUDIO</h2>
      <p class="lead" id="vol-lead">{vol}%<small>板载喇叭音量</small></p>
      <form method="post" action="/audio/volume" data-busy="设置中…">
        <input type="hidden" name="csrf" value="{esc(csrf)}">
        <label class="fld" for="vol">板载喇叭音量</label>
        <div style="display:flex;align-items:center;gap:10px">
          <input id="vol" name="value" type="range" min="0" max="100" value="{vol}" style="flex:1"
                 oninput="this.nextElementSibling.textContent=this.value+'%'" onchange="this.form.requestSubmit()">
          <span class="rec-time" id="vol-note">{vol}%</span>
        </div>
      </form>
      <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">
        <form method="post" action="/audio/record" data-busy="录音中…" style="margin:0;flex:1;min-width:150px">
          <input type="hidden" name="csrf" value="{esc(csrf)}">
          <input type="hidden" name="seconds" value="5">
          <button class="btn" type="submit" style="width:100%">用板载麦克风录音</button>
        </form>
        <form method="post" action="/audio/play" data-busy="播放中…" style="margin:0;flex:1;min-width:150px">
          <input type="hidden" name="csrf" value="{esc(csrf)}">
          <button class="btn solid" type="submit" style="width:100%">喇叭播放测试音</button>
        </form>
      </div>
      {rec_block}
    </section>"""

    # SD
    sd_card = f"""
    <section class="card">
      <h2>SD 卡 STORAGE</h2>
      <div id="sd-body">{_sd_body_html(sd, csrf)}</div>
      <form method="post" action="/sd/mount" data-busy="检测中…">
        <input type="hidden" name="csrf" value="{esc(csrf)}">
        <div class="act"><button class="btn" type="submit">重新检测并挂载</button></div>
      </form>
    </section>"""

    # 网口
    eth_items = ""
    for e in eth:
        carrier = e.get("carrier")
        eth_items += (f'<div class="row"><span class="k">{esc(e["device"])}</span>'
                      f'<span class="tag {"ok" if carrier else "off"}">'
                      f'{"已插网线" if carrier else "未接网线"}</span></div>'
                      f'<div class="row"><span class="k">链路 / 速率</span><span class="v">{esc(e["state"])}'
                      f'{(" · " + esc(e["speed"]) + " Mbps") if e.get("speed") and e["speed"] != "-1" else ""}</span></div>'
                      f'<div class="row"><span class="k">IP</span><span class="v">{esc(e.get("ip") or "—")}</span></div>'
                      f'<form method="post" action="/net/ping" data-busy="Ping 测试中…">'
                      f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                      f'<input type="hidden" name="iface" value="{esc(e["device"])}">'
                      f'<input type="hidden" name="label" value="{esc(e["device"])}">'
                      f'<input type="hidden" name="card" value="eth">'
                      f'<div class="act"><button class="btn" type="submit">Ping 测试（{esc(e["device"])}）</button></div></form>')
    if not eth_items:
        eth_items = '<p class="note">没有检测到有线网口</p>'
    eth_card = f"""
    <section class="card">
      <h2>网口 ETHERNET</h2>
      {_cm(card_msg, "eth")}
      {eth_items}
    </section>"""

    # 系统
    mem = sysinfo.get("mem") or {}
    disks = sysinfo.get("disks") or []
    fan_on = bool(fan.get("enabled"))
    pwm = (fan.get("detail") or {}).get("pwm1")
    res = ""
    if mem:
        res += (f'<div class="meter-label"><span>内存 DDR</span>'
                f'<span>{human_size(mem["used"])} / {human_size(mem["total"])} · {mem["pct"]}%</span></div>'
                f'<div class="meter"><i data-w="{mem["pct"]}"></i></div>')
    for d in disks:
        res += (f'<div class="meter-label"><span>{esc(d["label"])}</span>'
                f'<span>{human_size(d["used"])} / {human_size(d["total"])} · {d["pct"]}%</span></div>'
                f'<div class="meter copper"><i data-w="{d["pct"]}"></i></div>')
    sys_card = f"""
    <section class="card">
      <h2>系统 SYSTEM</h2>
      {_cm(card_msg, "sys")}
      <p class="lead">{esc(sysinfo.get('hostname'))}<small>Linux {esc(sysinfo.get('kernel'))} · 已运行 {esc(human_uptime(sysinfo.get('uptime') or 0))}</small></p>
      {res}
      <div class="rows">
        <div class="row"><span class="k">USB 网卡</span><span class="v">{esc(sysinfo.get('usb_address'))}</span></div>
        <div class="row"><span class="k">SSH</span><span class="tag {'ok' if ssh.get('active') else 'off'}">{'运行中' if ssh.get('active') else '已停止'} · {'自启' if ssh.get('enabled') else '不自启'}</span></div>
        <div class="row"><span class="k">散热风扇</span>
          <form method="post" action="/fan" style="margin:0" data-busy="切换中…">
            <input type="hidden" name="csrf" value="{esc(csrf)}">
            <input type="hidden" name="value" value="{'off' if fan_on else 'on'}">
            <button type="submit" style="all:unset;cursor:pointer">
              <span class="switch {'on' if fan_on else ''}" id="fan-switch"><span class="track"></span><span>{'已开启' if fan_on else '已关闭'}</span></span>
            </button>
          </form>
        </div>
        <div class="row" id="fan-pwm-row"{' style="display:none"' if not pwm else ''}><span class="k">风扇转速</span><span class="v" id="fan-pwm">PWM {esc(pwm)}</span></div>
      </div>
      <form method="post" action="/system/emmc-test" data-busy="eMMC 测试中…">
        <input type="hidden" name="csrf" value="{esc(csrf)}">
        <div class="act"><button class="btn" type="submit">eMMC 测试</button></div>
      </form>
      <form method="post" action="/system/ddr-test" data-busy="DDR 测试中…">
        <input type="hidden" name="csrf" value="{esc(csrf)}">
        <div class="act"><button class="btn" type="submit">DDR 测试</button></div>
      </form>
      <form method="post" action="/reboot" data-busy="重启中…"
            onsubmit="return confirm('确定要重启板子吗？')">
        <input type="hidden" name="csrf" value="{esc(csrf)}">
        <div class="act"><button class="btn danger" type="submit">重启系统</button></div>
      </form>
    </section>"""

    body = f"""
<header class="top">
  {_brand()}
  <div class="titles"><b>泰山派 1M · 配置中心</b><span>RK3566 / SINGLE DISPLAY</span></div>
  <div class="grow"></div>
  <div class="state"><i></i>{esc(sysinfo.get('usb_address') or '192.168.7.1')} 在线</div>
  <button class="tbtn" onclick="toggleTheme()">昼夜切换</button>
  <a class="tbtn" href="/password" style="text-decoration:none">修改密码</a>
  <form method="post" action="/logout" style="margin:0">
    <input type="hidden" name="csrf" value="{esc(csrf)}">
    <button class="tbtn primary" type="submit">退出</button>
  </form>
</header>
<div style="max-width:1280px;margin:0 auto;padding:12px 24px 0">{flash}</div>
<div class="page">
  <aside>
    {sys_card}
  </aside>
  <main class="grid">
    {screen_card}
    {wifi_card}
    {modem_card}
    {audio_card}
    {sd_card}
    {eth_card}
  </main>
</div>
"""
    return page("状态", body)


def password_page(csrf, msg="", err=""):
    flash = ""
    if msg:
        flash += f'<p class="ok flash-op">{esc(msg)}</p>'
    if err:
        flash += f'<p class="err flash-op">{esc(err)}</p>'
    body = f"""
<header class="top">
  {_brand()}
  <div class="titles"><b>修改密码</b><span>CHANGE PASSWORD</span></div>
  <div class="grow"></div>
  <a class="tbtn" href="/" style="text-decoration:none">返回</a>
</header>
<div class="loginwrap" style="margin-top:6vh">
  <section class="card">
    <h2>账号 {esc(LOGIN_USER)}</h2>
    {flash}
    <form method="post" action="/password" data-busy="保存中…">
      <input type="hidden" name="csrf" value="{esc(csrf)}">
      <label class="fld" for="old-pw">原密码</label>
      <input id="old-pw" name="old" type="password" required>
      <label class="fld" for="new-pw">新密码（至少 8 位）</label>
      <input id="new-pw" name="new" type="password" required>
      <label class="fld" for="new-pw2">再输一次</label>
      <input id="new-pw2" name="confirm" type="password" required>
      <div class="act"><button class="btn solid" type="submit">保存</button></div>
    </form>
    <p class="note">改完需要用新密码重新登录。默认密码是 {esc(DEFAULT_PASSWORD)}。</p>
  </section>
</div>"""
    return page("修改密码", body)


def sd_page(csrf, rel, items, msg="", err=""):
    rel = rel if rel.startswith("/") else "/" + rel
    parts = [p for p in rel.split("/") if p]
    crumbs = ['<a class="btn" href="/sd/list?path=/" style="text-decoration:none">根目录</a>']
    acc = ""
    for p in parts:
        acc += "/" + p
        crumbs.append(f'<a class="btn" href="/sd/list?path={quote(acc)}" style="text-decoration:none">{esc(p)}</a>')
    rows = ""
    for it in items:
        full = (rel.rstrip("/") + "/" + it["name"])
        name = esc(it["name"]) + ("/" if it["dir"] else "")
        if it["dir"]:
            label = f'<a href="/sd/list?path={quote(full)}">{name}</a>'
        else:
            label = f'<a href="/sd/download?path={quote(full)}">{name}</a>'
        rows += (f'<tr><td>{label}</td><td class="meta">{"" if it["dir"] else human_size(it["size"])}</td>'
                 f'<td class="meta">{esc(it["mtime"])}</td>'
                 f'<td><form method="post" action="/sd/delete" style="margin:0" data-busy="删除中…">'
                 f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                 f'<input type="hidden" name="path" value="{esc(full)}">'
                 f'<button class="mini" type="submit">删除</button></form></td></tr>')
    if not rows:
        rows = '<tr><td colspan="4" class="note">空目录</td></tr>'
    flash = ""
    if msg:
        flash += f'<p class="ok flash-op">{esc(msg)}</p>'
    if err:
        flash += f'<p class="err flash-op">{esc(err)}</p>'
    body = f"""
<header class="top">
  {_brand()}
  <div class="titles"><b>SD 卡文件</b><span>STORAGE / {esc(rel)}</span></div>
  <div class="grow"></div>
  <a class="tbtn" href="/" style="text-decoration:none">返回</a>
</header>
<div class="page" style="grid-template-columns:1fr">
  <section class="card">
    {flash}
    <div class="act" style="margin:0 0 14px">{''.join(crumbs)}</div>
    <div class="act">
      <input type="file" id="f" style="color:var(--ink);font:inherit;font-size:12px">
      <button class="btn" type="button" onclick="up()">上传到当前目录</button>
    </div>
    <p class="note" id="upmsg"></p>
  </section>
  <section class="card">
    <h2>当前目录</h2>
    <table><thead><tr><th>名称</th><th>大小</th><th>修改时间</th><th>操作</th></tr></thead>
    <tbody>{rows}</tbody></table>
  </section>
</div>
<script>
var CUR={json.dumps(rel)}; var CSRF={json.dumps(csrf)};
async function up(){{
  var f=document.getElementById('f').files[0], m=document.getElementById('upmsg');
  if(!f){{ m.textContent='先选一个文件'; return; }}
  var target=(CUR.replace(/\\/$/,'')+'/'+f.name);
  m.textContent='上传中：'+f.name;
  try{{
    var r=await fetch('/sd/upload?path='+encodeURIComponent(target),
      {{method:'PUT',headers:{{'X-CSRF':CSRF}},body:f}});
    if(r.ok){{ m.textContent='上传完成，刷新中…'; location.reload(); }}
    else {{ m.textContent='上传失败：HTTP '+r.status; }}
  }}catch(e){{ m.textContent='上传失败：'+e; }}
}}
</script>"""
    return page("SD 卡文件", body)


# ----------------------------------------------------------------- handler

class Handler(BaseHTTPRequestHandler):
    server_version = "tspi-web/0.4"
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- helpers
    def session(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "tspiweb":
                return get_session(v), v
        return None, None

    def send_html(self, code, text, headers=None):
        data = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, code, obj, headers=None):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, to):
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def want_json(self):
        return self.headers.get("X-Requested-With", "") == "fetch"

    def post_result(self, ok, message, card="", data=None):
        """操作结果：带 X-Requested-With: fetch 的请求回 JSON（data 为就地更新控件
        所需的新值，如 fan_enabled/pwm、list_html 等）；
        普通表单保持原 302 回状态页行为（无 JS 回退）。"""
        if self.want_json():
            payload = {"ok": ok, "message": message}
            if data:
                payload.update(data)
            self.send_json(200, payload, self.common_headers())
            return
        if card:
            self.redirect(f"/?c={quote(card)}&ok={'1' if ok else '0'}&m={quote(message)}")
        else:
            self.redirect(("/?msg=" if ok else "/?err=") + quote(message))

    def common_headers(self):
        return [("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
                ("Content-Security-Policy",
                 "default-src 'none'; style-src 'unsafe-inline'; "
                 "script-src 'unsafe-inline'; img-src 'self' data:; "
                 "media-src 'self'; connect-src 'self'; form-action 'self'")]

    # -- routes
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/login":
            self.send_html(200, login_page(new_csrf()), self.common_headers())
            return
        sess, token = self.session()
        if path == "/password":
            if not sess:
                self.redirect("/login")
                return
            query = parse_qs(urlparse(self.path).query)
            self.send_html(200, password_page(sess["csrf"],
                                              (query.get("msg") or [""])[0],
                                              (query.get("err") or [""])[0]),
                           self.common_headers())
            return
        if path == "/audio/rec.wav":
            if not sess:
                self.redirect("/login")
                return
            if not os.path.exists(REC_FILE):
                self.send_html(404, page("未找到", '<main><div class="card">还没有录音</div></main>'),
                               self.common_headers())
                return
            with open(REC_FILE, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "audio/wav")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for k, v in self.common_headers():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/sd/list":
            if not sess:
                self.redirect("/login")
                return
            q = parse_qs(urlparse(self.path).query)
            rel = (q.get("path") or ["/"])[0]
            items = sd_list(rel)
            if items is None:
                self.send_html(404, page("SD 卡", '<main><div class="card">'
                                              'SD 卡未挂载或目录不存在，先回首页点「重新检测并挂载」</div></main>'),
                               self.common_headers())
                return
            self.send_html(200, sd_page(sess["csrf"], rel, items,
                                        (q.get("msg") or [""])[0],
                                        (q.get("err") or [""])[0]),
                           self.common_headers())
            return
        if path == "/sd/download":
            if not sess:
                self.redirect("/login")
                return
            q = parse_qs(urlparse(self.path).query)
            full = sd_safe((q.get("path") or [""])[0])
            if not full or not os.path.isfile(full):
                self.send_html(404, page("未找到", '<main><div class="card">文件不存在</div></main>'),
                               self.common_headers())
                return
            size = os.path.getsize(full)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition",
                             'attachment; filename="%s"' % os.path.basename(full))
            for k, v in self.common_headers():
                self.send_header(k, v)
            self.end_headers()
            with open(full, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            return
        if path == "/api/usb":
            if not sess:
                self.send_json(401, {"ok": False, "error": "未登录"}, self.common_headers())
                return
            self.send_json(200, {"devices": usb_devices()}, self.common_headers())
            return
        if path == "/api/status":
            if not sess:
                self.send_json(401, {"ok": False, "error": "未登录"}, self.common_headers())
                return
            self.send_json(200, {"ok": True, "data": collect_status()}, self.common_headers())
            return
        if path == "/":
            if not sess:
                self.redirect("/login")
                return
            query = parse_qs(urlparse(self.path).query)
            msg = (query.get("msg") or [""])[0]
            err_msg = (query.get("err") or [""])[0]
            card_msg = {}
            card = (query.get("c") or [""])[0]
            if card:
                card_msg[card] = ((query.get("ok") or ["1"])[0] == "1",
                                  (query.get("m") or [""])[0])
            self.send_html(200, status_page(collect_status(), sess["csrf"], msg, err_msg,
                                            card_msg),
                           self.common_headers())
            return
        self.send_html(404, page("未找到", '<main><div class="card">页面不存在</div></main>'),
                       self.common_headers())

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 8192)).decode("utf-8", "replace")
        form = parse_qs(body)
        ip = self.client_address[0]

        if path == "/login":
            if not check_csrf((form.get("csrf") or [""])[0]):
                self.send_html(400, login_page(new_csrf(), "页面已过期，请重新提交"),
                               self.common_headers())
                return
            if rate_limited(ip):
                self.send_html(429, login_page(new_csrf(), "尝试次数过多，请 5 分钟后再试"),
                               self.common_headers())
                return
            password = (form.get("password") or [""])[0]
            if verify_password(LOGIN_USER, password):
                clear_failures(ip)
                token, csrf = new_session()
                cookie = (f"tspiweb={token}; Path=/; HttpOnly; SameSite=Strict; "
                          f"Max-Age={SESSION_TTL}")
                self.redirect_with_cookie("/", cookie)
            else:
                note_failure(ip)
                self.send_html(401, login_page(new_csrf(), "密码不正确"), self.common_headers())
            return

        if path == "/logout":
            sess, token = self.session()
            if sess:
                csrf = (form.get("csrf") or [""])[0]
                if not hmac.compare_digest(csrf, sess["csrf"]):
                    self.send_html(400, page("错误", '<main><div class="card">请求校验失败</div></main>'),
                                   self.common_headers())
                    return
                drop_session(token)
            self.redirect_with_cookie("/login", "tspiweb=; Path=/; Max-Age=0; HttpOnly")
            return

        if path in ("/password", "/wifi/scan", "/wifi/connect",
                    "/audio/volume", "/audio/play", "/audio/record", "/audio/play-rec",
                    "/sd/mount", "/sd/delete", "/sd/test",
                    "/screen", "/fan", "/reboot", "/net/ping",
                    "/system/emmc-test", "/system/ddr-test"):
            sess, _ = self.session()
            if not sess:
                self.redirect("/login")
                return
            if not hmac.compare_digest((form.get("csrf") or [""])[0], sess["csrf"]):
                self.send_html(400, page("错误", '<main><div class="card">请求校验失败</div></main>'),
                               self.common_headers())
                return
            if path == "/password":
                old = (form.get("old") or [""])[0]
                new = (form.get("new") or [""])[0]
                confirm = (form.get("confirm") or [""])[0]
                if new != confirm:
                    if self.want_json():
                        self.send_json(200, {"ok": False, "message": "两次输入的新密码不一致"},
                                       self.common_headers())
                        return
                    self.redirect("/password?err=" + quote("两次输入的新密码不一致"))
                    return
                ok, message = change_password(old, new)
                if self.want_json():
                    self.send_json(200, {"ok": ok, "message": message}, self.common_headers())
                    return
                self.redirect(("/password?msg=" + quote(message)) if ok
                              else ("/password?err=" + quote(message)))
                return
            if path == "/wifi/scan":
                wifi_scan()
                _status_cache["at"] = 0.0
                nets = wifi_state().get("networks") or []
                self.post_result(True, "扫描完成", "wifi",
                                 {"list_html": _wifi_list_html(nets)})
                return
            if path == "/wifi/connect":
                ssid = (form.get("ssid") or [""])[0].strip()
                password = (form.get("password") or [""])[0]
                ok, message = wifi_connect(ssid, password)
                _status_cache["at"] = 0.0
                self.post_result(ok, message, "wifi",
                                 {"lead_html": _wifi_lead_html(wifi_state())})
                return
            if path == "/audio/volume":
                raw = (form.get("value") or ["0"])[0]
                ok, message, pct = audio_set_volume(raw)
                self.post_result(ok, message, data={"volume": pct})
                return
            if path == "/audio/play":
                ok, message = audio_play_default()
                self.post_result(ok, message)
                return
            if path == "/audio/record":
                ok, message = audio_record((form.get("seconds") or ["5"])[0])
                rec_data = dict(_last_rec) if ok and _last_rec["at"] else None
                self.post_result(ok, message, data={"rec": rec_data, "version": rec_version()})
                return
            if path == "/audio/play-rec":
                ok, message = audio_play_recording()
                self.post_result(ok, message)
                return
            if path == "/sd/mount":
                _status_cache["at"] = 0.0
                st = sd_state()
                body = {"body_html": _sd_body_html(st, sess["csrf"])}
                if st.get("mounted"):
                    self.post_result(True, "已挂载到 " + st["mounted"], data=body)
                else:
                    self.post_result(False, st.get("error") or "没有检测到 SD 卡", data=body)
                return
            if path == "/sd/delete":
                rel = (form.get("path") or [""])[0]
                full = sd_safe(rel)
                parent = os.path.dirname(rel.rstrip("/")) or "/"
                try:
                    if not full or not os.path.exists(full):
                        raise OSError("文件不存在")
                    if os.path.isdir(full):
                        os.rmdir(full)
                    else:
                        os.remove(full)
                    if self.want_json():
                        self.send_json(200, {"ok": True, "message": "已删除"},
                                       self.common_headers())
                        return
                    self.redirect("/sd/list?path=" + quote(parent) + "&msg=" + quote("已删除"))
                except OSError as exc:
                    if self.want_json():
                        self.send_json(200, {"ok": False, "message": "删除失败：" + str(exc)[:80]},
                                       self.common_headers())
                        return
                    self.redirect("/sd/list?path=" + quote(parent)
                                  + "&err=" + quote("删除失败：" + str(exc)[:80]))
                return
            if path == "/sd/test":
                w, r = sd_speed_test()
                self.post_result(True, f"SD 读写测试：写入 {w} MB/s，读取 {r} MB/s")
                return
            if path == "/screen":
                fid = (form.get("screen") or [""])[0]
                if not fid:
                    self.redirect("/?err=" + quote("没有选择屏幕"))
                    return
                # 单屏互斥：先关掉 HDMI 和其它屏，再打开目标屏
                steps = []
                if fid != "hdmi":
                    steps.append(["disable", "hdmi"])
                for other in ("mipi-3inch1", "mipi-10inch", "edp"):
                    if other != fid:
                        steps.append(["disable", other])
                steps.append(["enable", fid])
                fail = None
                for cmd in steps:
                    rc, out, errout = run_full(["tspi-config"] + cmd, timeout=25)
                    if rc != 0 and cmd[0] == "enable":
                        detail = (errout or out or "无输出").splitlines()[-1][:120]
                        fail = f"切换失败（退出码 {rc}）：{detail}"
                        break
                _status_cache["at"] = 0.0
                names = {"hdmi": "HDMI", "mipi-3inch1": "3.1 寸 MIPI",
                         "mipi-10inch": "10 寸 MIPI", "edp": "10 寸 eDP"}
                if fail:
                    # 切换失败时单选钮停在用户点的那一项，把真实配置回给客户端纠正
                    feats, _ = tspi_features()
                    cur = next((f for f in (feats or [])
                                if f.get("enabled") and "screens" in (f.get("groups") or [])), None)
                    self.post_result(False, fail,
                                     data={"fid": (cur or {}).get("id", ""),
                                           "configured": (cur or {}).get("name", "未知"),
                                           "pending": (cur or {}).get("name", "未知") != live_screen()})
                else:
                    self.post_result(True,
                                     f"已切换到 {names.get(fid, fid)}（其它屏已关闭），重启后生效",
                                     data={"fid": fid, "configured": names.get(fid, fid),
                                           "pending": names.get(fid, fid) != live_screen()})
                return
            if path == "/fan":
                val = (form.get("value") or [""])[0]
                cmd = "enable" if val == "on" else "disable"
                rc, out, errout = run_full(["tspi-config", cmd, "fan"], timeout=25)
                _status_cache["at"] = 0.0
                if rc == 0:
                    feats, _ = tspi_features()
                    fan = next((f for f in (feats or []) if f.get("id") == "fan"), None) or {}
                    self.post_result(True, "风扇已" + ("开启" if val == "on" else "关闭"), "sys",
                                     {"fan_enabled": bool(fan.get("enabled")),
                                      "pwm": (fan.get("detail") or {}).get("pwm1")})
                else:
                    detail = (errout or out or "无输出").splitlines()[-1][:120]
                    self.post_result(False, f"风扇操作失败（退出码 {rc}）：{detail}", "sys")
                return
            if path == "/system/emmc-test":
                w, r = emmc_speed_test()
                self.post_result(True, f"eMMC 读写测试：写入 {w} MB/s，读取 {r} MB/s")
                return
            if path == "/system/ddr-test":
                ok, msg = ddr_test()
                self.post_result(ok, msg)
                return
            if path == "/net/ping":
                iface = (form.get("iface") or [""])[0].strip()
                label = (form.get("label") or [iface])[0]
                card = (form.get("card") or [""])[0]
                ok, msg = ping_test(iface)
                self.post_result(ok, f"{label}：{msg}", card)
                return
            if path == "/reboot":
                subprocess.Popen(["/bin/sh", "-c", "sleep 2; systemctl reboot"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if self.want_json():
                    self.send_json(200, {"ok": True,
                                         "message": "板子正在重启，约 30-60 秒后刷新本页。"},
                                   self.common_headers())
                else:
                    self.send_html(200, page("正在重启", '<main><div class="card">'
                                             '板子正在重启，约 30-60 秒后刷新本页。</div></main>'),
                                   self.common_headers())
                return

        self.send_html(404, page("未找到", '<main><div class="card">页面不存在</div></main>'),
                       self.common_headers())

    def do_PUT(self):
        path = urlparse(self.path).path
        if path != "/sd/upload":
            self.send_json(404, {"ok": False, "error": "not found"}, self.common_headers())
            return
        sess, _ = self.session()
        if not sess:
            self.send_json(401, {"ok": False, "error": "未登录"}, self.common_headers())
            return
        if not hmac.compare_digest(self.headers.get("X-CSRF", ""), sess["csrf"]):
            self.send_json(403, {"ok": False, "error": "CSRF"}, self.common_headers())
            return
        q = parse_qs(urlparse(self.path).query)
        target = sd_safe((q.get("path") or [""])[0])
        if not target:
            self.send_json(400, {"ok": False, "error": "路径非法"}, self.common_headers())
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 512 * 1024 * 1024:
            self.send_json(413, {"ok": False, "error": "文件为空或超过 512MB"}, self.common_headers())
            return
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            remaining = length
            with open(target, "wb") as fh:
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    fh.write(chunk)
                    remaining -= len(chunk)
        except OSError as exc:
            self.send_json(500, {"ok": False, "error": str(exc)[:120]}, self.common_headers())
            return
        self.send_json(200, {"ok": True, "path": target, "size": length}, self.common_headers())

    def redirect_with_cookie(self, to, cookie):
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        for k, v in self.common_headers():
            self.send_header(k, v)
        self.end_headers()


class Server(ThreadingHTTPServer):
    """HTTPServer without the reverse-DNS lookup in server_bind().

    BaseHTTPServer calls socket.getfqdn() on the bind address; on this board
    that blocks for a long time before the socket starts listening.
    """

    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port


def _modem_prewarm():
    """Keep the modem cache warm so page loads never wait on AT commands."""
    while True:
        try:
            modem_state()
        except Exception:
            pass
        time.sleep(8)


def main():
    port = int(os.environ.get("TSPI_WEB_PORT", PORT))
    httpd = None
    for attempt in range(60):
        addr = usb0_address()
        try:
            httpd = Server((addr, port), Handler)
            break
        except OSError as exc:
            sys.stderr.write(f"tspi-web: bind {addr}:{port} failed ({exc}), retry\n")
            time.sleep(2)
    if httpd is None:
        sys.stderr.write("tspi-web: cannot bind to usb0, giving up\n")
        return 1
    httpd.daemon_threads = True
    threading.Thread(target=_modem_prewarm, daemon=True).start()
    sys.stderr.write(f"tspi-web listening on {addr}:{port}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
