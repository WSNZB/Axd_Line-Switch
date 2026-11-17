#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Axd_Line_Switch —— 告警触发线路自动切换系统（单文件 Python 标准库实现）

功能：
  1. 对外提供 POST /api/alert，AIOps 告警回调传入告警标题；
  2. 按告警标题匹配"切换动作"（关键词包含 / 正则），定位站点+线路方向；
  3. 登录对应网络设备（telnet socket / ssh pty），逐条下发命令块，
     每条命令等待提示符回归后再发下一条；'#' 开头行为注释自动跳过；
  4. 站点、设备、匹配关系、命令块全部由 Web 页面维护。

环境变量（均可缺省）：
  LS_PORT       监听端口        默认 8090
  LS_DB         SQLite 路径     默认 ./line_switch.db
  LS_SECRET     密码加密主密钥  默认内置值（生产请务必修改）
  LS_BIND       监听地址        默认 0.0.0.0

仅使用标准库；设备登录不依赖 sshpass（ssh 密码经 pty 写入，不进进程列表）。
"""

import base64
import hashlib
import hmac
import json
import os
import fcntl
import pty
import queue
import re
import select
import socket
import termios
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta

# --------------------------------------------------------------- 配置 ----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LS_PORT = int(os.environ.get("LS_PORT") or "8090")
LS_BIND = (os.environ.get("LS_BIND") or "0.0.0.0").strip()
LS_DB = (os.environ.get("LS_DB") or os.path.join(BASE_DIR, "line_switch.db")).strip()
LS_SECRET = (os.environ.get("LS_SECRET") or "axd-line-switch-default-secret").strip()

DEFAULT_PROMPT = r'[<\[][\w\-.:/@]+[>\]]\s*$'   # 华为/H3C 默认提示符
MATCH_POLICY_FIRST = "first"                     # 多命中策略：只执行第一个

# AIOps 告警接口（用于"匹配预检/回放"，可选功能）
AIOPS_API = os.environ.get("AIOPS_API") or "https://aiops.livecom.ltd/api/monitor/alarm/search"
AIOPS_TOKEN = os.environ.get("AIOPS_TOKEN") or ""

_DB_LOCK = threading.Lock()
_EXEC_QUEUE = queue.Queue()
_DEV_LOCKS = {}          # device_id -> Lock，保证同一设备串行
_DEV_LOCKS_GUARD = threading.Lock()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _git_version():
    """版本号 = WAITSUN_V1.0.<提交次数>（git rev-list --count HEAD）。
    第 13 次提交后启动即显示 WAITSUN_V1.0.13。"""
    try:
        r = subprocess.run(["git", "rev-list", "--count", "HEAD"], cwd=BASE_DIR,
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip().isdigit():
            return "WAITSUN_V1.0.%s" % r.stdout.strip()
        return "unknown"
    except Exception:
        return "unknown"


VERSION = _git_version()
STARTED_AT = now()


# --------------------------------------------------------------- 加密 ----
def _derive_key():
    return hashlib.pbkdf2_hmac("sha256", LS_SECRET.encode(), b"axd-line-switch-salt", 20000)


_ENC_KEY = _derive_key()


def _keystream(nonce, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hmac.new(_ENC_KEY, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        counter += 1
    return out[:length]


def encrypt_pw(plain):
    if plain is None or plain == "":
        return ""
    nonce = os.urandom(16)
    raw = plain.encode("utf-8")
    ks = _keystream(nonce, len(raw))
    ct = bytes(a ^ b for a, b in zip(raw, ks))
    return base64.b64encode(nonce + ct).decode()


def decrypt_pw(enc):
    if not enc:
        return ""
    try:
        blob = base64.b64decode(enc)
        nonce, ct = blob[:16], blob[16:]
        ks = _keystream(nonce, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks)).decode("utf-8")
    except Exception:
        return ""


def mask_pw(s):
    return "******" if s else ""


# --------------------------------------------------------------- 数据库 --
def get_db():
    conn = sqlite3.connect(LS_DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS sites(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        remark TEXT DEFAULT '',
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS devices(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER DEFAULT 23,
        protocol TEXT DEFAULT 'telnet',
        username TEXT DEFAULT '',
        password_enc TEXT DEFAULT '',
        enable_password_enc TEXT DEFAULT '',
        init_command TEXT DEFAULT 'screen-length 0 temporary',
        prompt TEXT DEFAULT '',
        timeout INTEGER DEFAULT 10,
        status_command TEXT DEFAULT 'display ip routing-table',
        current_regex TEXT DEFAULT '',
        line_map TEXT DEFAULT '',
        enabled INTEGER DEFAULT 1,
        remark TEXT DEFAULT '',
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS lines(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        alarm_keywords TEXT DEFAULT '',
        nexthop_ip TEXT DEFAULT '',
        priority INTEGER DEFAULT 1,
        enabled INTEGER DEFAULT 1,
        remark TEXT DEFAULT '',
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS actions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER,
        name TEXT NOT NULL,
        device_id INTEGER,
        match_type TEXT DEFAULT 'contains',
        match_keywords TEXT DEFAULT '',
        command_block TEXT DEFAULT '',
        rollback_block TEXT DEFAULT '',
        verify_block TEXT DEFAULT '',
        expect_keywords TEXT DEFAULT '',
        target_line TEXT DEFAULT '',
        cooldown INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        remark TEXT DEFAULT '',
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS exec_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action_id INTEGER,
        action_name TEXT DEFAULT '',
        device_id INTEGER,
        device_name TEXT DEFAULT '',
        trigger TEXT DEFAULT 'api',
        alarm_title TEXT DEFAULT '',
        dry_run INTEGER DEFAULT 0,
        rollback INTEGER DEFAULT 0,
        status TEXT DEFAULT 'running',
        precheck_line TEXT DEFAULT '',
        session_log TEXT DEFAULT '',
        source_line TEXT DEFAULT '',
        decision_note TEXT DEFAULT '',
        error TEXT DEFAULT '',
        matched_note TEXT DEFAULT '',
        started_at TEXT,
        finished_at TEXT
    );
    CREATE TABLE IF NOT EXISTS exec_steps(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_id INTEGER,
        seq INTEGER,
        command TEXT,
        output TEXT DEFAULT '',
        raw_output TEXT DEFAULT '',
        ok INTEGER DEFAULT 1,
        ts TEXT
    );
    CREATE TABLE IF NOT EXISTS kv(
        k TEXT PRIMARY KEY,
        v TEXT
    );
    """)
    # 兼容旧库：补列
    for tbl, col, ddl in [
        ("devices", "status_command", "TEXT DEFAULT 'display ip routing-table'"),
        ("devices", "current_regex", "TEXT DEFAULT ''"),
        ("devices", "line_map", "TEXT DEFAULT ''"),
        ("actions", "verify_block", "TEXT DEFAULT ''"),
        ("actions", "expect_keywords", "TEXT DEFAULT ''"),
        ("actions", "target_line", "TEXT DEFAULT ''"),
        ("exec_logs", "precheck_line", "TEXT DEFAULT ''"),
        ("exec_logs", "session_log", "TEXT DEFAULT ''"),
        ("exec_logs", "source_line", "TEXT DEFAULT ''"),
        ("exec_logs", "decision_note", "TEXT DEFAULT ''"),
        ("exec_logs", "timeline", "TEXT DEFAULT ''"),
        ("lines", "nexthop_ip", "TEXT DEFAULT ''"),
        ("exec_steps", "raw_output", "TEXT DEFAULT ''"),
    ]:
        cols = [r[1] for r in c.execute("PRAGMA table_info(%s)" % tbl)]
        if col not in cols:
            c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (tbl, col, ddl))
    # 默认设置
    for k, v in [("web_password", "admin123"),
                 ("api_token", "lsk-" + uuid.uuid4().hex[:24]),
                 ("global_cooldown", "300"),
                 ("continue_on_error", "0"),
                 ("aiops_url", AIOPS_API),
                 ("aiops_token", AIOPS_TOKEN),
                 ("active_window_min", "30")]:
        c.execute("INSERT OR IGNORE INTO kv(k,v) VALUES(?,?)", (k, v))
    conn.commit()
    conn.close()


def db():
    """每个请求线程独立连接（ThreadingHTTPServer）。"""
    return get_db()


def kv_get(conn, key, default=""):
    row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return row["v"] if row else default


def kv_set(conn, key, value):
    conn.execute("INSERT INTO kv(k,v) VALUES(?,?) "
                 "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
    conn.commit()


# --------------------------------------------------------------- 匹配 ----
def match_actions(conn, title):
    """返回 (命中的动作列表)。contains: 逗号分隔关键词全部包含(不区分大小写)；regex: re.search。"""
    return [m["action"] for m in match_detail(conn, title)]


def match_detail(conn, title):
    """返回命中明细 [{'action': Row, 'reason': '...'}]，reason 说明哪几个关键词命中。"""
    t = (title or "").strip()
    if not t:
        return []
    hits = []
    for a in conn.execute("SELECT * FROM actions WHERE enabled=1 ORDER BY id"):
        kw = (a["match_keywords"] or "").strip()
        if not kw:
            continue
        try:
            if a["match_type"] == "regex":
                if re.search(kw, t, re.IGNORECASE):
                    hits.append({"action": a, "reason": "正则匹配: %s" % kw})
            else:
                words = [w.strip() for w in kw.split(",") if w.strip()]
                if words and all(w.lower() in t.lower() for w in words):
                    hits.append({"action": a, "reason": "关键词全部命中: %s" % ",".join(words)})
        except re.error as e:
            hits.append({"action": a, "reason": "正则语法错误: %s" % e})
    return hits


def fetch_aiops_alarms(conn, minutes=30, max_items=300):
    """拉取近 N 分钟告警明细（含 is_recover 状态），用于站点线路互斥判定。"""
    import urllib.parse
    import urllib.request
    token = (kv_get(conn, "aiops_token", "") or "").strip()
    api = (kv_get(conn, "aiops_url", "") or "").strip() or AIOPS_API
    if not token:
        raise RuntimeError("未配置 AIOps Token")
    start = (datetime.now() - timedelta(minutes=int(minutes))).strftime("%Y-%m-%d %H:%M:%S")
    end = (datetime.now() + timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")
    sul = json.dumps([{"attr": "create_time", "search": [start, end], "operator": "="}],
                     ensure_ascii=False)
    out, offset = [], 0
    while offset < max_items:
        params = {"offset": offset, "limit": min(200, max_items - offset), "search_unit_list": sul}
        req = urllib.request.Request(api + "?" + urllib.parse.urlencode(params),
                                     headers={"token": token})
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read().decode("utf-8"))
        if d.get("code") != 0:
            raise RuntimeError("AIOps 接口返回错误: %s" % str(d)[:160])
        items = (d.get("data") or {}).get("list") or []
        out.extend(items)
        total = (d.get("data") or {}).get("count")
        if not items or (total is not None and len(out) >= total):
            break
        offset += 200
    return out


def _kw_match(keywords, text):
    """线路告警关键词匹配：逗号分隔，全部包含(不区分大小写)视为命中。"""
    words = [w.strip() for w in (keywords or "").split(",") if w.strip()]
    if not words:
        return False
    t = (text or "").lower()
    return all(w.lower() in t for w in words)


def judge_site_alarms(conn, title, action):
    """站点线路互斥判定。
    返回 (allow, reason, detail)：
      - 站点未配线路 → 放行（不做互斥判定）
      - 站点多条线路同时在告警 → 拦截
      - 故障线路之外的线路也在告警 → 拦截
      - 标题未匹配出故障线路 → 拦截（无法确认哪条线路故障）
    AIOps 查询失败时放行并记录原因，避免因外部接口异常导致完全不动作。"""
    site_id = action["site_id"]
    lines = conn.execute("SELECT * FROM lines WHERE site_id=? AND enabled=1 ORDER BY priority,id",
                         (site_id,)).fetchall()
    detail = {"fault_lines": [], "active_lines": [], "window_min": 0, "note": ""}
    if not lines:
        detail["note"] = "站点未配置线路，未做互斥判定"
        return True, "", detail
    window = int(kv_get(conn, "active_window_min", "30") or 30)
    detail["window_min"] = window
    fault_lines = [ln["name"] for ln in lines if _kw_match(ln["alarm_keywords"], title)]
    detail["fault_lines"] = fault_lines
    if not fault_lines:
        detail["note"] = "告警标题未匹配到本站点任何线路关键词"
        return False, ("无法确认故障线路：告警标题未匹配站点下任何线路（%s）"
                       % "、".join(ln["name"] for ln in lines)), detail
    try:
        alarms = fetch_aiops_alarms(conn, window)
    except Exception as e:
        detail["note"] = "AIOps 活跃告警查询失败，已放行: %s" % e
        return True, "", detail
    active = {}
    for a in alarms:
        if a.get("is_recover") == 1:
            continue
        t = a.get("alarm_title") or ""
        for ln in lines:
            if _kw_match(ln["alarm_keywords"], t):
                active.setdefault(ln["name"], []).append(t)
    detail["active_lines"] = list(active.keys())
    detail["active_detail"] = {k: v[:3] for k, v in active.items()}
    detail["alarms_total"] = len(alarms)
    detail["checked_lines"] = {ln["name"]: len(active.get(ln["name"], [])) for ln in lines}
    if len(active) >= 2:
        return False, ("站点多条线路同时告警（%s），切换无效，不执行"
                       % "、".join(active.keys())), detail
    others = [n for n in active if n not in fault_lines]
    if others:
        return False, ("其它线路同时告警（%s），不执行切换" % "、".join(others)), detail
    detail["note"] = "仅故障线路 %s 在告警，允许切换" % "、".join(fault_lines)
    return True, "", detail


def fetch_aiops_titles(conn, days=7, max_items=1000):
    """从 AIOps 拉取近 N 天告警标题（去重前）。用于匹配回放校验。"""
    token = (kv_get(conn, "aiops_token", "") or "").strip()
    api = (kv_get(conn, "aiops_url", "") or "").strip() or AIOPS_API
    if not token:
        raise RuntimeError("未配置 AIOps Token，请在「全局设置」中填写")
    import urllib.parse
    import urllib.request
    start = (datetime.now() - timedelta(days=int(days))).strftime("%Y-%m-%d 00:00:00")
    end = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")
    sul = json.dumps([{"attr": "create_time", "search": [start, end], "operator": "="}],
                     ensure_ascii=False)
    out, offset, total = [], 0, None
    while offset < max_items:
        params = {"offset": offset, "limit": min(200, max_items - offset), "search_unit_list": sul}
        req = urllib.request.Request(api + "?" + urllib.parse.urlencode(params),
                                     headers={"token": token})
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read().decode("utf-8"))
        if d.get("code") != 0:
            raise RuntimeError("AIOps 接口返回错误: %s" % str(d)[:200])
        items = (d.get("data") or {}).get("list") or []
        total = (d.get("data") or {}).get("count")
        out.extend(x.get("alarm_title", "") for x in items)
        if not items or (total is not None and len(out) >= total):
            break
        offset += 200
    return out, total or len(out)


# ------------------------------------------------------- 设备会话驱动 ----
IAC, DONT, DO, WONT, WILL, SB, SE = 243, 244, 245, 246, 247, 250, 252


def _strip_iac(buf):
    """剥离 telnet 协商字节 (IAC xx / IAC SB ... IAC SE)。"""
    out = bytearray()
    i, n = 0, len(buf)
    while i < n:
        b = buf[i]
        if b == IAC:
            if i + 1 >= n:
                break
            cmd = buf[i + 1]
            if cmd in (DO, DONT, WILL, WONT):
                i += 3
            elif cmd == SB:
                j = buf.find(bytes([IAC, SE]), i)
                i = n if j < 0 else j + 2
            elif cmd == IAC:
                out.append(IAC)
                i += 2
            else:
                i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


class DeviceSession(object):
    """网络设备交互会话。telnet: socket 直连(剥离 IAC)；ssh: pty + 系统 ssh。"""

    def __init__(self, dev, password_plain):
        self.kind = (dev["protocol"] or "telnet").lower()
        self.host = dev["host"]
        self.port = int(dev["port"] or (22 if self.kind == "ssh" else 23))
        self.user = dev["username"] or ""
        self.password = password_plain
        self.init_command = (dev["init_command"] or "").strip()
        self.timeout = int(dev["timeout"] or 10)
        self.prompt = (dev["prompt"] or "").strip() or DEFAULT_PROMPT
        self.prompt_re = re.compile(self.prompt)
        self.enable_password = decrypt_pw(dev["enable_password_enc"])
        self.buf = b""
        self.sock = None
        self.proc = None
        self.master_fd = None
        self.logged_in = False
        self.log_lines = []      # 登录阶段过程记录
        self.transcript = []     # 完整会话原文 [(方向, 文本), ...] 排障用
        self.login_raw = ""      # 登录阶段原始输出
        self.last_raw = ""       # 最近一条命令的原始回显

    # ---- 底层 ----
    def _read_some(self, wait):
        if self.kind == "telnet":
            r, _, _ = select.select([self.sock], [], [], wait)
            if not r:
                return b""
            try:
                return self.sock.recv(4096)
            except OSError as e:
                raise RuntimeError("telnet 连接已断开: %s | 设备输出尾部: %s"
                                   % (e, self.buf.decode("utf-8", "replace")[-200:].strip() or "(无)"))
        else:
            r, _, _ = select.select([self.master_fd], [], [], wait)
            if not r:
                return b""
            try:
                return os.read(self.master_fd, 4096)
            except OSError:
                # pty 已关闭 = ssh 子进程退出（认证失败/算法协商失败/连接被拒等）
                code = self.proc.poll() if self.proc else None
                tail = self.buf.decode("utf-8", "replace")[-300:].strip() or "(设备无任何输出)"
                raise RuntimeError("SSH 进程已退出(退出码=%s)。设备输出尾部: %s" % (code, tail))

    def _read_until(self, patterns, timeout):
        """读到任一 pattern 匹配缓冲尾部即返回缓冲文本；超时返回 None。patterns: [compiled]"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            text = self.buf.decode("utf-8", "replace")
            for p in patterns:
                m = p.search(text)
                if m:
                    return text
            chunk = self._read_some(0.2)
            if chunk:
                self.buf += _strip_iac(chunk) if self.kind == "telnet" else chunk
            # 丢掉过大的历史缓冲，只留尾部（避免长回显拖慢匹配）
            if len(self.buf) > 65536:
                self.buf = self.buf[-16384:]
        return None

    def _send(self, text):
        shown = "******" if text == self.password and self.password else text
        self.transcript.append(("TX", shown))
        data = (text + "\r\n") if self.kind == "telnet" else (text + "\n")
        if self.kind == "telnet":
            self.sock.sendall(data.encode("utf-8"))
        else:
            os.write(self.master_fd, data.encode("utf-8"))

    # ---- 登录 ----
    @staticmethod
    def _ssh_child_setup():
        """子进程（fork 后、exec 前）：脱离原会话并把 pty slave 设为控制终端。
        关键：ssh 读/写密码提示走 /dev/tty（控制终端）而非 stdin/stdout——
        不做 TIOCSCTTY 时守护进程下 ssh 无法交互输密，认证必然失败
        （表现即 Permission denied 且会话中无任何密码提示）。"""
        os.setsid()
        try:
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)   # fd 0 = pty slave
        except OSError:
            pass

    def _open_transport(self):
        """建立 telnet 连接或启动 ssh 子进程。
        SSH 算法参数与已验证的 netdevice_config_backup.py 对齐（老款华为/H3C 兼容）；
        认证允许 keyboard-interactive（华为 stelnet 原生方式，提示经 SSH 通道回传）。"""
        if self.kind == "telnet":
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock.setblocking(True)
            return
        self.master_fd, slave = pty.openpty()
        # 运维逃生口：环境变量追加任意 ssh -o 选项，应对其它协商问题
        extra = (os.environ.get("SSH_EXTRA_OPTS") or "").strip().split()
        cmd = ["ssh", "-tt",
               "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null",
               "-o", "ConnectTimeout=%d" % max(5, self.timeout),
               "-o", "ServerAliveInterval=15",
               # 兼容老网络设备：新版 OpenSSH 默认禁用旧算法，导致协商失败
               "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1",
               "-o", "HostKeyAlgorithms=+ssh-rsa",
               "-o", "Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc",
               "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
               # 关掉公钥探测：老设备 SSH 服务端常在收到公钥探测时直接断开连接
               "-o", "PubkeyAuthentication=no",
               "-o", "NumberOfPasswordPrompts=2",
               # password 方式优先：实测老款华为（S6720 V200R011 等）的
               # keyboard-interactive 握手对 "User Authentication" 两段式提示应答
               # 会被设备拒绝（sshpass 同现象），而标准 password 方式一次即通过；
               # 仅支持 keyboard-interactive 的设备由 OpenSSH 自动回落，登录循环应答。
               "-o", "PreferredAuthentications=password,keyboard-interactive"]
        cmd += extra
        cmd += ["-p", str(self.port), "-l", self.user or "admin", self.host]
        self.proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave,
                                     close_fds=True, preexec_fn=self._ssh_child_setup)
        os.close(slave)

    def connect(self):
        self._open_transport()
        self._login()

    def _login(self):
        login_re = re.compile(r"(ogin:|sername:|user name:)", re.IGNORECASE)
        # 华为/H3C 设备 SSH(stelnet) 的密码提示是 "User Authentication"（非标准 Password:）
        passwd_re = re.compile(r"(assword:|User Authentication)", re.IGNORECASE)
        yes_re = re.compile(r"yes/no", re.IGNORECASE)
        err_re = re.compile(r"( refused|timed out|unreachable|failed|denied|错误|失败)", re.IGNORECASE)
        prompt_re = self.prompt_re

        deadline = time.time() + max(20, self.timeout * 2)
        saw_password = False
        try:
            while time.time() < deadline:
                text = self.buf.decode("utf-8", "replace")
                tail = text[-400:]
                if prompt_re.search(tail):
                    self.logged_in = True
                    break
                if err_re.search(text) and not saw_password:
                    extra_hint = ""
                    if re.search(r"Permission denied", text, re.IGNORECASE):
                        extra_hint = ("（认证被拒且未出现密码提示：请确认账号密码正确；"
                                      "若设备仅支持 password 认证请确保服务以可交互方式运行）")
                    raise RuntimeError("连接失败: " + tail.strip()[-200:] + extra_hint)
                if self.proc and self.proc.poll() is not None:
                    # ssh 客户端已退出（认证失败/算法协商失败/连接被拒等）
                    raise RuntimeError("SSH 进程已退出(退出码=%s)。设备输出尾部: %s"
                                       % (self.proc.returncode,
                                          self.buf.decode("utf-8", "replace")[-300:].strip() or "(设备无任何输出)"))
                if yes_re.search(tail):
                    self._send("yes")
                    self.buf = b""
                    continue
                if passwd_re.search(tail):
                    if saw_password:
                        raise RuntimeError("认证失败（用户名或密码错误）")
                    self.log_lines.append("发送密码")
                    self._send(self.password)
                    self.buf = b""
                    saw_password = True
                    continue
                if login_re.search(tail) and not saw_password:
                    self.log_lines.append("发送用户名: %s" % (self.user or "(空)"))
                    self._send(self.user or "\r")
                    self.buf = b""
                    continue
                chunk = self._read_some(0.3)
                if chunk:
                    self.buf += _strip_iac(chunk) if self.kind == "telnet" else chunk
            else:
                raise RuntimeError("登录超时（%ds 内未出现设备提示符）" % max(20, self.timeout * 2))
        finally:
            # 无论成功失败都保存登录阶段原文，供排障
            self.login_raw = self.buf.decode("utf-8", "replace")
            self.transcript.append(("RX", "[登录阶段]\n" + self.login_raw))

        if not self.logged_in:
            raise RuntimeError("登录失败（口令错误或提示符不匹配）")

        # enable 提权（配置了 enable_password 且当前是 > 提示符时尝试）
        if self.enable_password:
            tail = text[-200:]
            if re.search(r'>\s*$', tail):
                self._send("enable")
                time.sleep(0.3)
                self._read_until([re.compile(r"assword:")], 5)
                self._send(self.enable_password)
                self.buf = b""
                self._read_until([self.prompt_re], self.timeout)

        # 登录后初始命令（关闭分页）
        if self.init_command and self.init_command.lower() not in ("none", "-"):
            try:
                self.send_cmd(self.init_command)
            except Exception:
                pass
        return True

    def send_cmd(self, cmd, no_wait=False):
        """发送一条命令。no_wait=True 时(quit/exit 类)发送后不等待提示符回归。"""
        self.buf = b""
        try:
            self._send(cmd)
        except (BrokenPipeError, OSError):
            if no_wait:
                self.log_lines.append("> " + cmd + "  (会话已断开)")
                self.last_raw = "(会话已断开，无法获取回显)"
                return "(session closed)"
            raise
        if no_wait:
            # quit/exit 等断开类命令：设备会话关闭，无提示符可等
            self.log_lines.append("> " + cmd + "  (断开会话)")
            self.last_raw = "(该命令不等待回显，会话已断开)"
            return "(session closed)"
        time.sleep(0.15)
        text = self._read_until([self.prompt_re], self.timeout)
        if text is None:
            raw = self.buf.decode("utf-8", "replace")
            self.last_raw = raw
            self.transcript.append(("RX", raw))
            raise RuntimeError("命令超时未回归提示符: %s | 尾部回显: %s" % (cmd, raw[-200:].replace("\n", " | ")))
        self.last_raw = text
        self.transcript.append(("RX", text))
        # 清理回显：去掉命令 echo 行、整行提示符，并剥离行尾粘连的提示符（保留正文）
        prompt_only = re.compile(r'^[<\[][\w\-.:/@]+[>\]]$')
        prompt_tail = re.compile(r'[<\[][\w\-.:/@]+[>\]]\s*$')
        cleaned = []
        for ln in text.splitlines():
            s = ln.strip()
            if not s:
                continue
            if prompt_only.match(s):
                continue
            if s == cmd or s.endswith(cmd):
                continue
            s2 = prompt_tail.sub("", s).strip()
            if not s2:
                continue
            cleaned.append(s2)
        self.log_lines.append("> " + cmd)
        return "\n".join(cleaned)

    def close(self):
        try:
            if self.kind == "telnet" and self.sock:
                self._send("quit")
                time.sleep(0.2)
                self.sock.close()
        except Exception:
            pass
        try:
            if self.proc:
                self._send("quit")
                time.sleep(0.2)
                self.proc.terminate()
        except Exception:
            pass
        try:
            if self.master_fd:
                os.close(self.master_fd)
        except Exception:
            pass


def parse_block(block):
    """命令块 → 命令列表：去空行、'#' 注释行。"""
    cmds = []
    for ln in (block or "").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        cmds.append(s)
    return cmds


def parse_line_map(text):
    """线路映射文本 → dict，每行 'IP=线路名' 或 'IP:线路名'，'#' 注释。"""
    m = {}
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        sep = "=" if "=" in s else (":" if ":" in s else None)
        if not sep:
            continue
        k, v = s.split(sep, 1)
        m[k.strip()] = v.strip()
    return m


def parse_current_line(output, line_map_text, custom_regex="", with_ip=False, extra_map=None):
    """从状态命令回显中解析当前生效线路。
    优先用自定义正则(捕获组1)；否则默认解析 0.0.0.0/0 路由行的 NextHop(排除 Direct/127.x)。
    再经线路映射转换为线路名；无映射时返回原始标识。
    extra_map: 补充映射（如站点线路关键词中的 IP→线路名），优先级低于设备线路映射。
    with_ip=True 且命中映射时返回「线路名 (IP)」展示形式（仅用于界面展示，
    判定比较仍用不带 IP 的规范值）。"""
    ident = None
    if (custom_regex or "").strip():
        try:
            mm = re.search(custom_regex, output or "")
            if mm:
                ident = mm.group(1) if mm.groups() else mm.group(0)
        except re.error:
            pass
    if not ident:
        for ln in (output or "").splitlines():
            s = ln.strip()
            if s.startswith("0.0.0.0/0") or re.match(r"^0\.0\.0\.0(\s|/0)", s):
                if "Direct" in s or "InLoop" in s:
                    continue
                ips = [x for x in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", s)
                       if not x.startswith("127.") and x != "0.0.0.0"]
                if ips:
                    ident = ips[0]
                    break
    if not ident:
        return ""
    lm = parse_line_map(line_map_text)
    if extra_map:
        for k, v in extra_map.items():
            lm.setdefault(k, v)
    name = lm.get(ident, ident)
    if with_ip and name != ident:
        return "%s (%s)" % (name, ident)
    return name


def site_line_ip_map(conn, site_id):
    """线路映射的唯一维护处 = 站点线路：
    ① 线路的「下一跳IP」字段（精确，优先）；
    ② 告警关键词中出现的 IP（兼容旧填法，回退）。
    设备未关联站点时，扫描全部站点线路做兜底解析。"""
    m = {}
    sql = ("SELECT name,alarm_keywords,nexthop_ip FROM lines WHERE enabled=1"
           + (" AND site_id=?" if site_id else "")
           + " ORDER BY " + ("priority,id" if site_id else "site_id,priority,id"))
    rows = conn.execute(sql, (site_id,) if site_id else ()).fetchall()
    for ln in rows:
        ip = (ln["nexthop_ip"] or "").strip()
        if ip:
            m.setdefault(ip, ln["name"])
    for ln in rows:
        for w in (ln["alarm_keywords"] or "").split(","):
            w = w.strip()
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", w):
                m.setdefault(w, ln["name"])
    return m


# --------------------------------------------------------------- 执行器 --
def _dev_lock(device_id):
    with _DEV_LOCKS_GUARD:
        if device_id not in _DEV_LOCKS:
            _DEV_LOCKS[device_id] = threading.Lock()
        return _DEV_LOCKS[device_id]


def _with_dev_lock(device_id, timeout, fn):
    """同一设备的会话串行化：切换执行、查线路、连通测试共用一把锁，避免提示符互相打乱。"""
    lk = _dev_lock(device_id)
    if not lk.acquire(timeout=timeout):
        raise RuntimeError("设备正被其它任务占用（等待超过 %ds），请稍后重试" % timeout)
    try:
        return fn()
    finally:
        lk.release()


def _run_session(dev, conn, log_id, cmds, dry_run, verify_cmds=None, expect_kws=None,
                 require_line=""):
    """登录设备：查当前线路 →（条件满足才）下发切换命令 → 执行验证命令。
    返回 (ok, error, 登录过程文本, 切换前当前线路, 验证是否通过, 跳过原因)。
    require_line 非空时：仅当当前生效线路等于该故障线路才下发切换命令。"""
    password = decrypt_pw(dev["password_enc"])
    sess = DeviceSession(dev, password)
    login_note = ""
    try:
        tl_append(conn, log_id, "登录设备：%s (%s://%s:%s)"
                  % (dev["name"], dev["protocol"], dev["host"], dev["port"]))
        sess.connect()
        tl_append(conn, log_id, "登录成功", "ok")
        login_note = "\n".join(sess.log_lines)
        precheck_line = ""
        precheck_disp = ""
        # 切换前：查询当前生效线路（演练也执行，用于"只看不切"）
        if (dev["status_command"] or "").strip():
            tl_append(conn, log_id, "查询当前生效线路")
            scmd = dev["status_command"].strip()
            out, qok, qerr = "", 1, ""
            try:
                out = sess.send_cmd(scmd)
                emap = site_line_ip_map(conn, dev["site_id"])
                precheck_line = parse_current_line(out, "", dev["current_regex"], extra_map=emap)
                # 展示值带线路名与 IP，便于人工判断；判定比较仍用规范值
                precheck_disp = parse_current_line(out, "", dev["current_regex"], with_ip=True, extra_map=emap)
                login_note += "\n[切换前] 当前生效线路: %s" % (precheck_disp or "未识别(见上方回显)")
                tl_append(conn, log_id, "当前生效线路：%s" % (precheck_disp or "未识别"),
                          evidence="命令: %s\n\n%s" % (scmd, out), step=True)
            except Exception as e:
                qok, qerr = 0, str(e)
                login_note += "\n[切换前] 状态查询失败: %s" % e
                tl_append(conn, log_id, "当前线路查询失败：%s" % e, "warn")
            conn.execute("INSERT INTO exec_steps(log_id,seq,command,output,raw_output,ok,ts) "
                         "VALUES(?,0,?,?,?,?,?)",
                         (log_id, "[线路查询] " + scmd, (out or qerr)[:8000],
                          (sess.last_raw or "")[:20000], qok, now()))
            conn.commit()
        conn.execute("UPDATE exec_logs SET precheck_line=? WHERE id=?", (precheck_disp, log_id))
        conn.commit()
        if dry_run:
            tl_append(conn, log_id, "演练模式：不下发切换命令", "ok")
            return True, "", login_note + "\n[dry-run] 登录成功，未下发切换命令", precheck_line, True, ""
        # 条件判断：当前生效线路必须是故障线路，否则无需切换
        if require_line and precheck_line:
            req = [x.strip() for x in require_line.split(",") if x.strip()]
            if req and precheck_line not in req:
                tl_append(conn, log_id, "当前线路 %s 非故障线路（%s），跳过"
                          % (precheck_disp or precheck_line, "/".join(req)), "warn")
                return (True, "", login_note + "\n[跳过] 当前生效线路为 %s，非故障线路 %s，无需切换"
                        % (precheck_disp or precheck_line, "/".join(req)), precheck_line, True,
                        "当前生效线路为 %s（非故障线路 %s），无需切换" % (precheck_disp or precheck_line, "/".join(req)))
            if req:
                tl_append(conn, log_id, "满足切换条件，下发切换命令（%d 条）" % len(cmds), "ok")
        else:
            tl_append(conn, log_id, "下发切换命令（%d 条）" % len(cmds), "ok")
        main_outs = []
        for i, cmd in enumerate(cmds, 1):
            seq_row = conn.execute("SELECT COALESCE(MAX(seq),0)+1 FROM exec_steps WHERE log_id=?",
                                   (log_id,)).fetchone()
            out, ok, err = "", 1, ""
            no_wait = cmd.lower().rstrip() in ("quit", "exit", "logout")
            try:
                out = sess.send_cmd(cmd, no_wait=no_wait)
                # 常见错误回显检测（华为/H3C）
                if re.search(r"(% (Unrecognized|Incomplete|Wrong|invalid)|Error:|未识别|错误命令|无效)", out, re.IGNORECASE):
                    ok, err = 0, "设备回显疑似错误: " + out[-200:]
            except Exception as e:
                ok, err = 0, str(e)
            main_outs.append(out or "")
            conn.execute("INSERT INTO exec_steps(log_id,seq,command,output,raw_output,ok,ts) "
                         "VALUES(?,?,?,?,?,?,?)",
                         (log_id, i, cmd, (out or err)[:8000], (sess.last_raw or "")[:20000], ok, now()))
            conn.commit()
            tl_append(conn, log_id, "执行命令：%s" % cmd, "ok" if ok else "bad",
                      evidence=((out or "") + (("\n" + err) if err else "")) or "(无回显)", step=True)
            if not ok:
                return (False, "第 %d 条命令失败: %s | %s" % (i, cmd, err),
                        login_note, precheck_line, False, "")
        # 切换后验证：用独立会话重新登录执行（切换命令块的 quit 可能已断开会话）
        verify_ok = True
        verr = ""
        if expect_kws and not verify_cmds:
            tl_append(conn, log_id, "验证：检查命令回显中的期望内容 %s" % "、".join(expect_kws))
            # 未配置验证命令块：直接在切换命令的回显中查找期望内容（省去重新登录）
            vtext = "\n".join(main_outs)
            missing = [k for k in expect_kws if k.lower() not in vtext.lower()]
            if missing:
                verify_ok = False
                verr = ("切换命令已下发，但命令回显中未找到期望内容 %s"
                        "（切换前线路: %s，请检查命令块输出或改在验证命令块配置查询命令）"
                        % (",".join(missing), precheck_disp or precheck_line or "未知"))
                tl_append(conn, log_id, "验证未通过：回显未包含 %s" % "、".join(missing), "bad")
            else:
                tl_append(conn, log_id, "验证通过", "ok")
        elif verify_cmds or expect_kws:
            tl_append(conn, log_id, "验证：重新登录设备执行验证命令" if verify_cmds
                      else "验证：重新登录设备检查期望内容")
            vsess = None
            try:
                vsess = DeviceSession(dev, password)
                vsess.connect()
                vout_all = []
                for j, vcmd in enumerate(verify_cmds or [], 1):
                    try:
                        vout = vsess.send_cmd(vcmd)
                        vok = 1
                    except Exception as e:
                        vout, vok = str(e), 0
                    vout_all.append(vout or "")
                    seq = conn.execute("SELECT COALESCE(MAX(seq),0)+1 FROM exec_steps WHERE log_id=?",
                                       (log_id,)).fetchone()[0]
                    conn.execute("INSERT INTO exec_steps(log_id,seq,command,output,raw_output,ok,ts) "
                                 "VALUES(?,?,?,?,?,?,?)",
                                 (log_id, seq, "[验证] " + vcmd, (vout or "")[:8000],
                                  (vsess.last_raw or "")[:20000], vok, now()))
                    conn.commit()
                    tl_append(conn, log_id, "验证命令：%s" % vcmd, "ok" if vok else "bad",
                              evidence=vout or "(无回显)", step=True)
                    if not vok:
                        verify_ok = False
                        verr = "验证命令执行失败: %s | %s" % (vcmd, vout[-150:])
                if verify_ok and expect_kws:
                    vtext = "\n".join(vout_all)
                    missing = [k for k in expect_kws if k.lower() not in vtext.lower()]
                    if missing:
                        verify_ok = False
                        verr = ("切换命令已下发，但验证未通过：路由表/回显中未找到期望内容 %s"
                                "（切换前线路: %s，可能路由未收敛或切换失败）"
                                % (",".join(missing), precheck_disp or precheck_line or "未知"))
                        tl_append(conn, log_id, "验证未通过：路由表未包含 %s" % "、".join(missing), "bad")
                    else:
                        tl_append(conn, log_id, "验证通过：路由表指向目标线路（%s）"
                                  % "、".join(expect_kws), "ok")
            except Exception as e:
                verify_ok = False
                verr = "验证会话登录失败: %s" % e
                tl_append(conn, log_id, "验证会话登录失败：%s" % e, "bad")
            finally:
                if vsess:
                    # 验证会话的完整收发并入主会话原文
                    sess.transcript.append(("--", "[验证会话开始：重新登录设备]"))
                    sess.transcript.extend(vsess.transcript)
                    vsess.close()
        return True, verr, login_note, precheck_line, verify_ok, ""
    finally:
        # 保存完整会话原文（含登录 banner / 每条命令收发 / 验证会话），排障用
        try:
            parts = []
            for direction, text in sess.transcript:
                if direction == "--":
                    parts.append("\n" + text)
                else:
                    parts.append("[%s] %s" % (direction, text))
            conn.execute("UPDATE exec_logs SET session_log=? WHERE id=?",
                         ("\n".join(parts)[:100000], log_id))
            conn.commit()
        except Exception:
            pass
        sess.close()


def execute_action(log_id):
    conn = get_db()
    try:
        log = conn.execute("SELECT * FROM exec_logs WHERE id=?", (log_id,)).fetchone()
        if not log:
            return
        dev = conn.execute("SELECT * FROM devices WHERE id=?", (log["device_id"],)).fetchone()
        act = conn.execute("SELECT * FROM actions WHERE id=?", (log["action_id"],)).fetchone()
        if not dev or not act:
            tl_append(conn, log_id, "设备或动作不存在，任务终止", "bad")
            conn.execute("UPDATE exec_logs SET status='failed', error='设备或动作不存在', finished_at=? WHERE id=?",
                         (now(), log_id))
            conn.commit()
            return
        block = (act["rollback_block"] if log["rollback"] else act["command_block"]) or ""
        cmds = parse_block(block)
        if not cmds and not log["dry_run"]:
            tl_append(conn, log_id, "命令块为空，任务终止", "bad")
            conn.execute("UPDATE exec_logs SET status='failed', error='命令块为空', finished_at=? WHERE id=?",
                         (now(), log_id))
            conn.commit()
            return
        verify_cmds = parse_block(act["verify_block"]) if not log["rollback"] else []
        expect_kws = [k.strip() for k in (act["expect_keywords"] or "").split(",") if k.strip()]
        try:
            ok, err, note, precheck_line, verify_ok, skip_reason = _with_dev_lock(
                dev["id"], 180, lambda: _run_session(
                    dev, conn, log_id, cmds, log["dry_run"], verify_cmds, expect_kws,
                    require_line=(log["source_line"] or "")))
        except Exception as e:
            ok, err, note, precheck_line, verify_ok, skip_reason = False, str(e), "", "", False, ""
            tl_append(conn, log_id, "执行异常：%s" % e, "bad")
        if skip_reason:
            status = "skipped"
            err = skip_reason
        elif ok and verify_ok:
            status = "success"
        elif ok and not verify_ok:
            status = "verify_failed"
        else:
            status = "failed"
        _FINISH_TXT = {"success": "任务完成", "verify_failed": "任务结束：验证未通过",
                       "failed": "任务失败", "skipped": "任务结束：未切换"}
        tl_append(conn, log_id, _FINISH_TXT.get(status, "任务结束: %s" % status),
                  "ok" if status == "success" else ("bad" if status in ("failed", "verify_failed") else "warn"))
        conn.execute("UPDATE exec_logs SET status=?, error=?, matched_note=?, finished_at=? WHERE id=?",
                     (status, err or "", note or "", now(), log_id))
        conn.commit()
    finally:
        conn.close()


def _worker():
    while True:
        log_id = _EXEC_QUEUE.get()
        try:
            execute_action(log_id)
        except Exception as e:
            try:
                c = get_db()
                c.execute("UPDATE exec_logs SET status='failed', error=?, finished_at=? WHERE id=?",
                          ("执行器异常: %s" % e, now(), log_id))
                c.commit()
                c.close()
            except Exception:
                pass


def tl_append(conn, log_id, text, kind="info", evidence="", step=False):
    """向执行记录时间线追加一条带时间戳的关键步骤（全链路过程可视化）。
    evidence: 该步骤的原始证据（设备回显 / 接口数据片段），前端可展开查看。"""
    try:
        row = conn.execute("SELECT timeline FROM exec_logs WHERE id=?", (log_id,)).fetchone()
        try:
            tl = json.loads(row["timeline"] or "[]") if row and row["timeline"] else []
        except ValueError:
            tl = []
        item = {"ts": now(), "text": text, "kind": kind}
        if evidence:
            item["ev"] = str(evidence)[:4000]
        if step:
            item["step"] = 1
        tl.append(item)
        conn.execute("UPDATE exec_logs SET timeline=? WHERE id=?",
                     (json.dumps(tl, ensure_ascii=False), log_id))
        conn.commit()
    except Exception:
        pass


def submit_action(conn, action, trigger, title, dry_run=0, rollback=0,
                  source_line="", decision_note="", init_tl=None):
    """创建执行记录并入队。返回 (log_id, skip_reason)。冷却/串行判断在此。
    init_tl: 告警接入阶段已产生的时间线条目列表。"""
    dev = conn.execute("SELECT * FROM devices WHERE id=?", (action["device_id"],)).fetchone()
    if not dev:
        return None, "设备不存在"
    if not dev["enabled"]:
        return None, "设备已停用"
    # 冷却判断（演练 dry_run 不受冷却限制）
    g_cooldown = int(kv_get(conn, "global_cooldown", "300") or 0)
    cooldown = action["cooldown"] or g_cooldown
    if cooldown > 0 and not dry_run:
        row = conn.execute(
            "SELECT started_at FROM exec_logs WHERE action_id=? AND status IN ('running','success') "
            "ORDER BY id DESC LIMIT 1", (action["id"],)).fetchone()
        if row and row["started_at"]:
            try:
                t0 = datetime.strptime(row["started_at"], "%Y-%m-%d %H:%M:%S")
                if (datetime.now() - t0).total_seconds() < cooldown:
                    return None, "冷却期内（%ds）" % cooldown
            except Exception:
                pass
    tl = list(init_tl or [])
    mode = "演练" if dry_run else ("回切" if rollback else "切换")
    tl.append({"ts": now(), "kind": "info",
               "text": "任务入队（模式：%s，设备：%s）" % (mode, dev["name"])})
    cur = conn.execute(
        "INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,alarm_title,"
        "dry_run,rollback,status,precheck_line,source_line,decision_note,started_at,timeline) "
        "VALUES(?,?,?,?,?,?,?,?, 'running', '', ?,?,?,?)",
        (action["id"], action["name"], dev["id"], dev["name"], trigger, title or "",
         dry_run, rollback, source_line, decision_note, now(), json.dumps(tl, ensure_ascii=False)))
    conn.commit()
    log_id = cur.lastrowid
    _EXEC_QUEUE.put(log_id)
    return log_id, ""


# --------------------------------------------------------------- HTTP ----
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

WEB_COOKIE = "ls_session"


def _sign_session(ts):
    return hmac.new(_ENC_KEY, ("sess|%s" % ts).encode(), hashlib.sha256).hexdigest()[:32]


def check_session(cookie_val):
    if not cookie_val or "|" not in cookie_val:
        return False
    ts, sig = cookie_val.split("|", 1)
    try:
        if time.time() - float(ts) > 86400 * 7:
            return False
    except ValueError:
        return False
    return hmac.compare_digest(_sign_session(ts), sig)


class Handler(BaseHTTPRequestHandler):
    server_version = "AxdLineSwitch/1.0"

    def log_message(self, fmt, *args):
        sys.stdout.write("[%s] %s\n" % (now(), fmt % args))

    # ---- helpers ----
    def _send_json(self, obj, status=200, headers=None):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    def _authorized(self, need_admin=True):
        """cookie 或 API token 任一通过。"""
        cookie = self.headers.get("Cookie") or ""
        val = ""
        for part in cookie.split(";"):
            if part.strip().startswith(WEB_COOKIE + "="):
                val = part.strip().split("=", 1)[1]
        if check_session(val):
            return True
        token = self.headers.get("X-API-Token") or ""
        conn = get_db()
        try:
            ok = bool(token) and hmac.compare_digest(token, kv_get(conn, "api_token", ""))
        finally:
            conn.close()
        return ok

    # ---- GET ----
    def do_GET(self):
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        if path == "/" or path == "/index.html":
            return self._page()
        if not path.startswith("/api/"):
            return self._send_json({"error": "not found"}, 404)
        if path == "/api/login":
            return self._send_json({"ok": True})
        if not self._authorized():
            return self._send_json({"error": "unauthorized"}, 401)
        conn = get_db()
        try:
            if path == "/api/session":
                return self._send_json({"ok": True})
            if path == "/api/config":
                keys = ["web_password", "api_token", "global_cooldown", "continue_on_error",
                        "aiops_url", "aiops_token", "active_window_min"]
                cfg = {k: kv_get(conn, k) for k in keys}
                cfg["web_password"] = mask_pw(cfg["web_password"])
                cfg["aiops_token"] = mask_pw(cfg["aiops_token"])
                return self._send_json(cfg)
            if path == "/api/stats":
                total = conn.execute("SELECT COUNT(*) c FROM exec_logs").fetchone()["c"]
                ok = conn.execute("SELECT COUNT(*) c FROM exec_logs WHERE status='success'").fetchone()["c"]
                failed = conn.execute("SELECT COUNT(*) c FROM exec_logs WHERE status='failed'").fetchone()["c"]
                running = conn.execute("SELECT COUNT(*) c FROM exec_logs WHERE status='running'").fetchone()["c"]
                skipped = conn.execute("SELECT COUNT(*) c FROM exec_logs WHERE status='skipped'").fetchone()["c"]
                vfailed = conn.execute("SELECT COUNT(*) c FROM exec_logs WHERE status='verify_failed'").fetchone()["c"]
                return self._send_json({"total": total, "success": ok, "failed": failed,
                                        "running": running, "skipped": skipped,
                                        "verify_failed": vfailed, "version": VERSION,
                                        "started_at": STARTED_AT})
            if path == "/api/sites":
                rows = conn.execute("SELECT * FROM sites ORDER BY id").fetchall()
                return self._send_json([dict(r) for r in rows])
            if path == "/api/devices":
                rows = conn.execute(
                    "SELECT d.*, s.name AS site_name FROM devices d LEFT JOIN sites s ON d.site_id=s.id ORDER BY d.id").fetchall()
                out = []
                for r in rows:
                    d = dict(r)
                    d.pop("password_enc", None)
                    d.pop("enable_password_enc", None)
                    d["has_password"] = True
                    out.append(d)
                return self._send_json(out)
            if path == "/api/lines":
                sid = (qs.get("site_id") or [None])[0]
                if sid:
                    rows = conn.execute("SELECT * FROM lines WHERE site_id=? ORDER BY priority,id",
                                        (int(sid),)).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT l.*, s.name AS site_name FROM lines l LEFT JOIN sites s ON l.site_id=s.id "
                        "ORDER BY l.site_id, l.priority, l.id").fetchall()
                return self._send_json([dict(r) for r in rows])
            if path == "/api/actions":
                rows = conn.execute(
                    "SELECT a.*, d.name AS device_name, d.protocol, d.host, s.name AS site_name "
                    "FROM actions a LEFT JOIN devices d ON a.device_id=d.id "
                    "LEFT JOIN sites s ON a.site_id=s.id ORDER BY a.id").fetchall()
                return self._send_json([dict(r) for r in rows])
            if path == "/api/logs":
                limit = int((qs.get("limit") or ["50"])[0])
                limit = max(1, min(limit, 300))
                aid = (qs.get("action_id") or [None])[0]
                if aid:
                    rows = conn.execute("SELECT * FROM exec_logs WHERE action_id=? ORDER BY id DESC LIMIT ?",
                                        (int(aid), limit)).fetchall()
                else:
                    rows = conn.execute("SELECT * FROM exec_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
                return self._send_json([dict(r) for r in rows])
            m = re.match(r"^/api/logs/(\d+)$", path)
            if m:
                log = conn.execute("SELECT * FROM exec_logs WHERE id=?", (int(m.group(1)),)).fetchone()
                if not log:
                    return self._send_json({"error": "not found"}, 404)
                steps = conn.execute("SELECT * FROM exec_steps WHERE log_id=? ORDER BY seq", (log["id"],)).fetchall()
                d = dict(log)
                d["steps"] = [dict(s) for s in steps]
                return self._send_json(d)
            m = re.match(r"^/api/task/(\d+)$", path)
            if m:
                log = conn.execute("SELECT id,status,error,finished_at FROM exec_logs WHERE id=?",
                                   (int(m.group(1)),)).fetchone()
                if not log:
                    return self._send_json({"error": "not found"}, 404)
                return self._send_json(dict(log))
            return self._send_json({"error": "not found"}, 404)
        finally:
            conn.close()

    # ---- POST ----
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._body() if self.method_has_body() else {}
        if path == "/api/login":
            conn = get_db()
            try:
                pw = kv_get(conn, "web_password", "admin123")
            finally:
                conn.close()
            if hmac.compare_digest(str(body.get("password") or ""), pw):
                ts = str(time.time())
                val = "%s|%s" % (ts, _sign_session(ts))
                return self._send_json({"ok": True}, headers={
                    "Set-Cookie": "%s=%s; Path=/; HttpOnly" % (WEB_COOKIE, val)})
            return self._send_json({"error": "密码错误"}, 401)
        if not self._authorized():
            return self._send_json({"error": "unauthorized"}, 401)
        conn = get_db()
        try:
            if path == "/api/alert":
                title = (body.get("title") or body.get("alarm_title") or body.get("name")
                         or (parse_qs(parsed.query).get("title") or [""])[0]).strip()
                if not title:
                    return self._send_json({"matched": False, "error": "缺少告警标题 title"}, 400)
                hits = match_actions(conn, title)
                t_recv = now()
                init_tl = [{"ts": t_recv, "kind": "info", "text": "收到告警：%s" % title}]
                if not hits:
                    init_tl.append({"ts": now(), "kind": "warn", "text": "未命中任何启用中的动作，流程结束"})
                    return self._send_json({"matched": False, "title": title})
                act = hits[0]
                site_row = conn.execute("SELECT name FROM sites WHERE id=?", (act["site_id"] or 0,)).fetchone() \
                    if act["site_id"] else None
                init_tl.append({"ts": now(), "kind": "ok",
                                "text": "命中动作：%s（站点：%s）"
                                % (act["name"], site_row["name"] if site_row else "未关联")})
                dry_run = 1 if str(body.get("dry_run", "")).lower() in ("1", "true", "yes") else 0
                # 站点线路互斥判定：多条线路同时告警 / 无法确认故障线路 → 不切换
                if conn.execute("SELECT 1 FROM lines WHERE site_id=? AND enabled=1 LIMIT 1",
                                (act["site_id"] or 0,)).fetchone():
                    init_tl.append({"ts": now(), "kind": "info",
                                    "text": "互斥判定：查询站点近 %s 分钟活跃告警"
                                    % (kv_get(conn, "active_window_min", "30") or 30)})
                allow, reason, decision = judge_site_alarms(conn, title, act)
                if decision.get("fault_lines"):
                    _ad = decision.get("active_detail") or {}
                    _cl = decision.get("checked_lines") or {}
                    _ev = ("AIOps 窗口 %s 分钟内告警共 %s 条，逐线路关键词匹配结果：\n%s"
                           % (decision.get("window_min"), decision.get("alarms_total"),
                              "\n".join("  %s：%s 条活跃告警%s"
                                         % (k, v, ("←" + " | ".join(_ad[k])) if _ad.get(k) else "（无）")
                                         for k, v in _cl.items())))
                    init_tl.append({"ts": now(), "kind": "info",
                                    "text": "故障线路：%s；活跃告警线路：%s"
                                    % ("、".join(decision["fault_lines"]),
                                       "、".join(decision.get("active_lines") or []) or "无"),
                                    "ev": _ev})
                dev = conn.execute("SELECT name,host FROM devices WHERE id=?", (act["device_id"],)).fetchone()
                base = {"matched": True, "title": title,
                        "action": {"id": act["id"], "name": act["name"], "site_id": act["site_id"]},
                        "device": dict(dev) if dev else None,
                        "matched_total": len(hits),
                        "decision": {"allow": allow, "reason": reason,
                                     "fault_lines": decision.get("fault_lines"),
                                     "active_lines": decision.get("active_lines"),
                                     "window_min": decision.get("window_min"),
                                     "note": decision.get("note")}}
                if not allow:
                    # 记录跳过原因，便于排障与统计
                    init_tl.append({"ts": now(), "kind": "bad", "text": "判定不切换：%s" % reason})
                    cur = conn.execute(
                        "INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,"
                        "alarm_title,dry_run,rollback,status,source_line,decision_note,started_at,finished_at,timeline) "
                        "VALUES(?,?,?,?, 'api', ?,?,0, 'skipped', ?,? ,?,?,?,?)",
                        (act["id"], act["name"], act["device_id"], dev["name"] if dev else "",
                         title, dry_run, ",".join(decision.get("fault_lines") or []),
                         (reason + " | " + decision.get("note", "")), now(), now(),
                         json.dumps(init_tl, ensure_ascii=False)))
                    conn.commit()
                    base.update({"task_id": None, "executed": False, "skip_reason": reason,
                                 "skip_reason_code": "site_alarm_condition"})
                    return self._send_json(base)
                init_tl.append({"ts": now(), "kind": "ok", "text": "互斥判定通过"})
                log_id, skip = submit_action(conn, act, "api", title, dry_run=dry_run,
                                             source_line=",".join(decision.get("fault_lines") or []),
                                             decision_note=decision.get("note", ""), init_tl=init_tl)
                base["task_id"] = log_id
                if skip:
                    base["executed"] = False
                    base["skip_reason"] = skip
                else:
                    base["executed"] = True
                return self._send_json(base)
            if path == "/api/logout":
                return self._send_json({"ok": True}, headers={
                    "Set-Cookie": "%s=deleted; Path=/; Max-Age=0" % WEB_COOKIE})
            # ---- CRUD: sites ----
            if path == "/api/sites":
                name = (body.get("name") or "").strip()
                if not name:
                    return self._send_json({"error": "站点名称必填"}, 400)
                cur = conn.execute("INSERT INTO sites(name,remark,created_at) VALUES(?,?,?)",
                                   (name, body.get("remark") or "", now()))
                conn.commit()
                return self._send_json({"id": cur.lastrowid})
            m = re.match(r"^/api/devices(?:/(\d+))?/?(test|exec)?$", path)
            if path == "/api/devices":
                return self._crud_device(conn, body, None)
            m2 = re.match(r"^/api/devices/(\d+)/(test|status)$", path)
            if m2:
                return self._device_test(conn, int(m2.group(1)),
                                         want_status=(m2.group(2) == "status"))
            # ---- CRUD: lines ----
            if path == "/api/lines":
                name = (body.get("name") or "").strip()
                if not name or not body.get("site_id"):
                    return self._send_json({"error": "线路名称与所属站点必填"}, 400)
                cur = conn.execute(
                    "INSERT INTO lines(site_id,name,alarm_keywords,nexthop_ip,priority,enabled,remark,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (int(body["site_id"]), name, body.get("alarm_keywords") or "",
                     (body.get("nexthop_ip") or "").strip(),
                     int(body.get("priority") or 1), 1 if body.get("enabled", 1) else 0,
                     body.get("remark") or "", now()))
                conn.commit()
                return self._send_json({"id": cur.lastrowid})
            # ---- CRUD: actions ----
            if path == "/api/actions":
                return self._crud_action(conn, body, None)
            m3 = re.match(r"^/api/exec/(\d+)$", path)
            if m3:
                act = conn.execute("SELECT * FROM actions WHERE id=?", (int(m3.group(1)),)).fetchone()
                if not act:
                    return self._send_json({"error": "动作不存在"}, 404)
                dry_run = 1 if str(body.get("dry_run", "")).lower() in ("1", "true", "yes") else 0
                rollback = 1 if str(body.get("rollback", "")).lower() in ("1", "true", "yes") else 0
                log_id, skip = submit_action(conn, act, "manual", body.get("title") or "",
                                             dry_run=dry_run, rollback=rollback,
                                             init_tl=[{"ts": now(), "kind": "info",
                                                       "text": "页面手动触发「%s」" % act["name"]}])
                if log_id is None:
                    return self._send_json({"executed": False, "skip_reason": skip}, 409)
                return self._send_json({"executed": True, "task_id": log_id})
            m4 = re.match(r"^/api/config$", path)
            if m4:
                for k in ("global_cooldown", "continue_on_error", "api_token", "aiops_url",
                          "aiops_token", "active_window_min"):
                    if k in body and body[k] is not None and body[k] != "":
                        kv_set(conn, k, str(body[k]))
                if body.get("web_password"):
                    kv_set(conn, "web_password", str(body["web_password"]))
                return self._send_json({"ok": True})
            # ---- 匹配预检 / 回放校验 ----
            if path == "/api/match/test":
                title = (body.get("title") or "").strip()
                hits = match_detail(conn, title)
                out = []
                for h in hits:
                    a = h["action"]
                    site = conn.execute("SELECT name FROM sites WHERE id=?", (a["site_id"],)).fetchone()
                    dev = conn.execute("SELECT name,host FROM devices WHERE id=?", (a["device_id"],)).fetchone()
                    out.append({"action_id": a["id"], "action_name": a["name"],
                                "site": site["name"] if site else "", "reason": h["reason"],
                                "device": dict(dev) if dev else None,
                                "command_lines": len(parse_block(a["command_block"]))})
                return self._send_json({"title": title, "matched": bool(out),
                                        "would_execute": out[0]["action_name"] if out else None,
                                        "hits": out})
            if path == "/api/match/replay":
                days = int(body.get("days") or 7)
                days = max(1, min(days, 30))
                try:
                    titles, total = fetch_aiops_titles(conn, days, max_items=int(body.get("max_items") or 1000))
                except Exception as e:
                    return self._send_json({"error": str(e)}, 400)
                per_action = {}
                unmatched = {}
                matched_cnt = 0
                for t in titles:
                    hits = match_detail(conn, t)
                    if not hits:
                        k = (t or "").strip() or "(空标题)"
                        unmatched[k] = unmatched.get(k, 0) + 1
                    else:
                        matched_cnt += 1
                        for h in hits:
                            nm = h["action"]["name"]
                            per_action[nm] = per_action.get(nm, 0) + 1
                unl = sorted(unmatched.items(), key=lambda x: -x[1])
                return self._send_json({
                    "days": days, "fetched": len(titles), "aiops_total": total,
                    "matched": matched_cnt, "unmatched": len(titles) - matched_cnt,
                    "per_action": sorted(per_action.items(), key=lambda x: -x[1]),
                    "unmatched_titles": [{"title": k, "count": v} for k, v in unl[:80]],
                    "unmatched_kinds": len(unl),
                })
            return self._send_json({"error": "not found"}, 404)
        finally:
            conn.close()

    def method_has_body(self):
        return True

    def _crud_device(self, conn, body, dev_id):
        if dev_id is None and body.get("id"):
            dev_id = int(body["id"])
        if dev_id:
            row = conn.execute("SELECT * FROM devices WHERE id=?", (dev_id,)).fetchone()
            if not row:
                return self._send_json({"error": "设备不存在"}, 404)
        fields = {}
        for k in ("site_id", "name", "host", "port", "protocol", "username",
                  "init_command", "prompt", "timeout", "enabled", "remark",
                  "status_command", "current_regex", "line_map"):
            if k in body:
                fields[k] = body[k]
        if body.get("password"):
            fields["password_enc"] = encrypt_pw(str(body["password"]))
        if body.get("enable_password"):
            fields["enable_password_enc"] = encrypt_pw(str(body["enable_password"]))
        if dev_id:
            sets = ",".join("%s=?" % k for k in fields)
            conn.execute("UPDATE devices SET %s WHERE id=?" % sets, list(fields.values()) + [dev_id])
            conn.commit()
            return self._send_json({"id": dev_id})
        if not fields.get("name") or not fields.get("host"):
            return self._send_json({"error": "设备名称与 host 必填"}, 400)
        cols = list(fields.keys())
        cur = conn.execute("INSERT INTO devices(%s,created_at) VALUES(%s,?)" %
                           (",".join(cols), ",".join(["?"] * len(cols))),
                           [fields[c] for c in cols] + [now()])
        conn.commit()
        return self._send_json({"id": cur.lastrowid})

    def _crud_action(self, conn, body, act_id):
        if act_id is None and body.get("id"):
            act_id = int(body["id"])
        if act_id:
            row = conn.execute("SELECT * FROM actions WHERE id=?", (act_id,)).fetchone()
            if not row:
                return self._send_json({"error": "动作不存在"}, 404)
        fields = {}
        for k in ("site_id", "name", "device_id", "match_type", "match_keywords",
                  "command_block", "rollback_block", "verify_block", "expect_keywords",
                  "target_line", "cooldown", "enabled", "remark"):
            if k in body:
                fields[k] = body[k]
        if act_id:
            sets = ",".join("%s=?" % k for k in fields)
            conn.execute("UPDATE actions SET %s WHERE id=?" % sets, list(fields.values()) + [act_id])
            conn.commit()
            return self._send_json({"id": act_id})
        if not fields.get("name"):
            return self._send_json({"error": "动作名称必填"}, 400)
        cols = list(fields.keys())
        cur = conn.execute("INSERT INTO actions(%s,created_at) VALUES(%s,?)" %
                           (",".join(cols), ",".join(["?"] * len(cols))),
                           [fields[c] for c in cols] + [now()])
        conn.commit()
        return self._send_json({"id": cur.lastrowid})

    def _device_test(self, conn, dev_id, want_status=False):
        dev = conn.execute("SELECT * FROM devices WHERE id=?", (dev_id,)).fetchone()
        if not dev:
            return self._send_json({"error": "设备不存在"}, 404)
        sess = None
        try:
            def _do():
                nonlocal sess
                s = DeviceSession(dev, decrypt_pw(dev["password_enc"]))
                sess = s
                s.connect()
                if want_status:
                    scmd = (dev["status_command"] or "").strip() or "display ip routing-table"
                    out = s.send_cmd(scmd)
                    emap = site_line_ip_map(conn, dev["site_id"])
                    line = parse_current_line(out, "", dev["current_regex"], extra_map=emap)
                    line_disp = parse_current_line(out, "", dev["current_regex"], with_ip=True, extra_map=emap)
                    s.close()
                    note = s.log_lines
                    if line and line_disp == line and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", line):
                        note = note + ["下一跳 %s 未匹配线路名，请在站点线路中配置下一跳IP" % line]
                    return {"ok": True, "current_line": line_disp or "未识别",
                            "command": scmd, "note": note, "banner": out[:800]}
                ver = ""
                try:
                    ver = s.send_cmd("display version")[:500]
                except Exception:
                    pass
                s.close()
                return {"ok": True, "note": s.log_lines, "banner": ver}
            return self._send_json(_with_dev_lock(dev_id, 60, _do))
        except Exception as e:
            # 失败时附带会话原文尾部（ssh 全过程），便于判断到底卡在哪一步
            tail = ""
            if sess is not None:
                try:
                    raw = sess.login_raw or "\n".join(t for _, t in sess.transcript)
                    tail = raw[-600:]
                except Exception:
                    tail = ""
            return self._send_json({"ok": False, "error": str(e), "session_tail": tail})

    # ---- PUT/DELETE ----
    def do_PUT(self):
        path = urlparse(self.path).path
        if not self._authorized():
            return self._send_json({"error": "unauthorized"}, 401)
        body = self._body()
        conn = get_db()
        try:
            m = re.match(r"^/api/sites/(\d+)$", path)
            if m:
                name = (body.get("name") or "").strip()
                if name:
                    conn.execute("UPDATE sites SET name=?, remark=? WHERE id=?",
                                 (name, body.get("remark") or row_remark(conn, "sites", m.group(1)), int(m.group(1))))
                else:
                    conn.execute("UPDATE sites SET remark=? WHERE id=?",
                                 (body.get("remark") or "", int(m.group(1))))
                conn.commit()
                return self._send_json({"ok": True})
            m = re.match(r"^/api/lines/(\d+)$", path)
            if m:
                fields = {}
                for k in ("name", "alarm_keywords", "nexthop_ip", "priority", "enabled", "remark", "site_id"):
                    if k in body:
                        fields[k] = body[k]
                if fields:
                    sets = ",".join("%s=?" % k for k in fields)
                    conn.execute("UPDATE lines SET %s WHERE id=?" % sets,
                                 list(fields.values()) + [int(m.group(1))])
                    conn.commit()
                return self._send_json({"ok": True})
            m = re.match(r"^/api/devices/(\d+)$", path)
            if m:
                return self._crud_device(conn, body, int(m.group(1)))
            m = re.match(r"^/api/actions/(\d+)$", path)
            if m:
                return self._crud_action(conn, body, int(m.group(1)))
            return self._send_json({"error": "not found"}, 404)
        finally:
            conn.close()

    def do_DELETE(self):
        path = urlparse(self.path).path
        if not self._authorized():
            return self._send_json({"error": "unauthorized"}, 401)
        conn = get_db()
        try:
            m = re.match(r"^/api/sites/(\d+)$", path)
            if m:
                conn.execute("DELETE FROM sites WHERE id=?", (int(m.group(1)),))
                conn.commit()
                return self._send_json({"ok": True})
            m = re.match(r"^/api/lines/(\d+)$", path)
            if m:
                conn.execute("DELETE FROM lines WHERE id=?", (int(m.group(1)),))
                conn.commit()
                return self._send_json({"ok": True})
            m = re.match(r"^/api/devices/(\d+)$", path)
            if m:
                conn.execute("DELETE FROM devices WHERE id=?", (int(m.group(1)),))
                conn.commit()
                return self._send_json({"ok": True})
            m = re.match(r"^/api/actions/(\d+)$", path)
            if m:
                conn.execute("DELETE FROM actions WHERE id=?", (int(m.group(1)),))
                conn.commit()
                return self._send_json({"ok": True})
            return self._send_json({"error": "not found"}, 404)
        finally:
            conn.close()

    # ---- 页面 ----
    def _page(self):
        html = PAGE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


def row_remark(conn, table, rid):
    r = conn.execute("SELECT remark FROM %s WHERE id=?" % table, (rid,)).fetchone()
    return (r["remark"] if r else "") or ""


# --------------------------------------------------------------- 页面 ----
PAGE_HTML = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>线路切换平台 - 控制台</title>
<style>
/* ============ 企业级后台视觉（参考 slate + indigo 规范） ============ */
:root{
  --primary:#4f46e5; --primary-hover:#4338ca; --primary-bg:#e0e7ff;
  --bg-body:#f4f6f8; --bg-card:#ffffff;
  --text-main:#1e293b; --text-muted:#64748b; --text-faint:#94a3b8;
  --border:#e2e8f0; --border2:#cbd5e1;
  --sidebar-bg:#1e293b; --sidebar-text:#94a3b8; --sidebar-active-bg:#334155; --sidebar-active-text:#fff;
  --success:#10b981; --success-bg:#d1fae5; --success-d:#047857;
  --danger:#ef4444; --danger-bg:#fee2e2; --danger-d:#b91c1c;
  --warn:#f59e0b; --warn-bg:#fef3c7; --warn-d:#b45309;
  --info:#3b82f6; --info-bg:#dbeafe; --info-d:#1d4ed8;
  --purple:#8b5cf6; --purple-bg:#ede9fe;
}
*{box-sizing:border-box;margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",Roboto,Helvetica,Arial,sans-serif}
body{display:flex;flex-direction:column;height:100vh;background:var(--bg-body);color:var(--text-main);font-size:14px;overflow:hidden}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#94a3b8}

/* ============ 顶部一级菜单 ============ */
.headerbar{height:60px;background:var(--sidebar-bg);display:flex;align-items:center;padding:0 24px;gap:8px;flex-shrink:0;z-index:30;box-shadow:0 1px 4px rgba(15,23,42,.25)}
.logo-icon{width:30px;height:30px;background:var(--primary);border-radius:6px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:bold;font-size:16px;flex-shrink:0}
.brand{color:#fff;font-size:15px;font-weight:600;letter-spacing:.5px;margin-right:28px;white-space:nowrap}
.top-nav{display:flex;gap:4px}
.top-nav button{border:none;background:none;color:var(--sidebar-text);font-size:14px;padding:9px 20px;border-radius:6px;cursor:pointer;transition:all .2s;position:relative}
.top-nav button:hover{color:#fff;background:rgba(255,255,255,.06)}
.top-nav button.active{color:#fff;font-weight:600;background:var(--sidebar-active-bg)}
.header-actions{margin-left:auto;display:flex;align-items:center;gap:14px}
.ver-top{font-size:11px;color:#64748b;white-space:nowrap}
.btn-logout{display:flex;align-items:center;gap:6px;padding:7px 14px;background:transparent;color:var(--sidebar-text);border:1px solid rgba(255,255,255,.12);border-radius:6px;font-size:12px;cursor:pointer;transition:all .2s;white-space:nowrap}
.btn-logout:hover{background:rgba(239,68,68,.12);color:var(--danger);border-color:rgba(239,68,68,.25)}

/* ============ 左侧二级菜单 ============ */
.app-row{flex:1;display:flex;min-height:0;overflow:hidden}
.sidebar{width:196px;background:var(--bg-card);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;overflow-y:auto}
.side-nav{padding:16px 12px}
.side-title{color:var(--text-faint);font-size:11px;font-weight:600;margin-bottom:10px;padding-left:10px;letter-spacing:1px}
.nav-item{display:flex;align-items:center;padding:9px 12px;color:#475569;font-size:13px;border-radius:6px;margin-bottom:4px;transition:all .2s;cursor:pointer;border:none;background:none;width:100%;text-align:left}
.nav-item svg{margin-right:10px;width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.nav-item:hover{color:var(--text-main);background:#f1f5f9}
.nav-item.active{color:var(--primary);background:var(--primary-bg);font-weight:600}

/* ============ 主区 ============ */
.main-container{flex:1;display:flex;flex-direction:column;min-width:0}
.content-scroll{flex:1;overflow-y:auto;padding:24px 32px}
.page-view{display:none;width:100%;max-width:1800px;margin:0 auto}
.page-view.active{display:block;animation:fadeIn .2s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}

/* ============ 卡片 ============ */
.card{background:var(--bg-card);border-radius:8px;border:1px solid var(--border);box-shadow:0 1px 3px rgba(0,0,0,.02);margin-bottom:24px}
.card-header{padding:16px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px}
.card-header h3{font-size:15px;font-weight:600}
.card-body{padding:24px}
.card-body.tight{padding:18px 24px}

/* ============ 按钮 ============ */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 16px;font-size:13px;font-weight:500;border-radius:6px;cursor:pointer;transition:all .2s;border:1px solid transparent;white-space:nowrap}
.btn-primary{background:var(--primary);color:#fff}
.btn-primary:hover{background:var(--primary-hover)}
.btn-secondary{background:#fff;color:var(--text-main);border-color:var(--border2)}
.btn-secondary:hover{background:#f8fafc;border-color:#94a3b8}
.btn-success{background:var(--success);color:#fff}
.btn-success:hover{filter:brightness(.94)}
.btn-warning{background:var(--warn);color:#fff}
.btn-warning:hover{filter:brightness(.94)}
.btn-danger{background:#fff;color:var(--danger);border-color:#fecaca}
.btn-danger:hover{background:var(--danger-bg);border-color:var(--danger)}
.btn-sm{padding:6px 12px;font-size:12px;border-radius:5px}

/* ============ 表格 ============ */
.table-responsive{width:100%;overflow-x:auto}
.data-table{width:100%;border-collapse:collapse;font-size:13px;text-align:left}
.data-table th{background:#f8fafc;color:#475569;font-weight:500;padding:14px 24px;border-bottom:1px solid var(--border);white-space:nowrap}
.data-table td{padding:16px 24px;border-bottom:1px solid var(--border);vertical-align:middle;color:var(--text-main)}
.data-table tbody tr:nth-child(even){background-color:#fcfcfd}
.data-table tbody tr:hover{background-color:#f1f5f9}
.data-table tr:last-child td{border-bottom:none}
.data-table tr.clickable{cursor:pointer}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.empty{padding:40px 24px;text-align:center;color:var(--text-faint);font-size:13px}
.empty svg{width:32px;height:32px;display:block;margin:0 auto 10px;opacity:.5;fill:none;stroke:currentColor;stroke-width:1.5}

/* 表格内元素 */
.status-cell{display:flex;align-items:center;gap:8px;font-weight:500;white-space:nowrap}
.dot-green{width:8px;height:8px;background:var(--success);border-radius:50%;flex-shrink:0}
.dot-red{width:8px;height:8px;background:var(--danger);border-radius:50%;flex-shrink:0}
.device-info{display:flex;flex-direction:column;gap:4px}
.device-name{font-weight:600;color:var(--text-main)}
.device-host{font-size:12px;color:var(--text-muted)}
.tag{padding:2px 8px;border-radius:4px;font-size:12px;font-weight:500;background:var(--primary-bg);color:var(--primary-hover);white-space:nowrap;display:inline-block}
.tag.ok{background:var(--success-bg);color:var(--success-d)}
.tag.bad{background:var(--danger-bg);color:var(--danger-d)}
.tag.warn{background:var(--warn-bg);color:var(--warn-d)}
.tag.info{background:var(--info-bg);color:var(--info-d)}
.tag.gray{background:#f1f5f9;color:#64748b}
.keyword-text{color:#334155;line-height:1.5;max-width:400px;display:inline-block;word-break:break-all}
.ops-cell{display:flex;gap:8px;justify-content:flex-end}
.err-text{color:var(--danger);font-size:12px;line-height:1.6;word-break:break-word}

/* ============ 统计卡 ============ */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-grid.stat-6{grid-template-columns:repeat(6,1fr)}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:18px 20px;display:flex;align-items:center;gap:14px;box-shadow:0 1px 3px rgba(0,0,0,.02)}
.stat-ic{width:42px;height:42px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.stat-ic svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.stat-card b{font-size:24px;font-weight:700;display:block;line-height:1.2;font-variant-numeric:tabular-nums}
.stat-card span{color:var(--text-muted);font-size:12px}

/* ============ 表单 ============ */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
label{display:block;font-size:12px;color:#475569;margin:14px 0 6px;font-weight:500}
input,select,textarea{width:100%;border:1px solid var(--border2);border-radius:6px;padding:9px 12px;font-size:13px;font-family:inherit;color:var(--text-main);background:#fff;transition:border .2s,box-shadow .2s;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(79,70,229,.12)}
input::placeholder,textarea::placeholder{color:#a3aec2}
textarea{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.6;resize:vertical}
select{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%2364748b' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;padding-right:32px}
.kv{display:grid;grid-template-columns:210px 1fr;gap:16px;align-items:center;margin:14px 0}
.kv label{margin:0;text-align:right;color:#475569}
.kv .ctl{display:flex;gap:12px;align-items:center}
.kv .ctl input,.kv .ctl select{flex:1}
.tip{font-size:12px;color:var(--text-faint);margin-top:4px}
.hint{font-size:12.5px;color:var(--text-muted);background:#f8fafc;border:1px solid var(--border);border-radius:6px;padding:10px 14px;margin-bottom:14px;line-height:1.7}
.hint code{background:#eef2f7;border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:#334155}
.sw{display:inline-flex;align-items:center;gap:8px;cursor:pointer;user-select:none;font-size:13px;margin-top:28px;color:var(--text-main)}
.sw input{width:16px;height:16px;accent-color:var(--primary);cursor:pointer}

/* 预检工具行（参考稿样式） */
.toolbar-row{display:flex;align-items:center;gap:16px;width:100%}
.input-group{display:flex;flex:1;max-width:800px}
.input-group input{flex:1;padding:10px 16px;font-size:14px;border:1px solid var(--border2);border-right:none;border-radius:6px 0 0 6px;outline:none;transition:border-color .2s}
.input-group input:focus{border-color:var(--primary)}
.input-group .btn{border-radius:0 6px 6px 0;padding:0 24px}
.action-buttons{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.action-buttons select{padding:9px 12px;border:1px solid var(--border2);border-radius:6px;font-size:13px;outline:none;background:#fff;width:auto}
.q{position:relative;display:inline-flex;align-items:center;justify-content:center;width:15px;height:15px;border-radius:50%;border:1px solid #b6c2d4;color:#64748b;font-size:10px;font-weight:700;cursor:help;margin-left:7px;vertical-align:middle;flex-shrink:0;line-height:1}
.q:hover{border-color:var(--primary);color:var(--primary);background:var(--primary-bg)}
.qtip{position:fixed;background:#0f172a;color:#e2e8f0;font-size:12px;font-weight:400;line-height:1.65;padding:8px 12px;border-radius:6px;white-space:pre-line;width:max-content;max-width:320px;box-shadow:0 6px 20px rgba(15,23,42,.28);pointer-events:none;z-index:500;display:none}
.qtip.show{display:block}
.qtip .qarrow{position:absolute;width:10px;height:10px;background:#0f172a;transform:rotate(45deg)}

/* ============ 弹窗 ============ */
.modal{position:fixed;inset:0;background:rgba(15,23,42,.55);display:none;align-items:flex-start;justify-content:center;z-index:100;overflow:auto;padding:48px 16px}
.modal.show{display:flex;animation:fadeIn .18s ease}
.modal .box{background:#fff;border-radius:10px;width:780px;max-width:100%;box-shadow:0 24px 60px rgba(15,23,42,.35);animation:rise .22s cubic-bezier(.2,.9,.3,1.15)}
@keyframes rise{from{transform:translateY(14px);opacity:0}to{transform:none;opacity:1}}
.mhd{display:flex;align-items:center;padding:18px 24px;border-bottom:1px solid var(--border);gap:10px}
.mhd h3{font-size:15px;font-weight:600;flex:1}
.mx{border:none;background:#f1f5f9;color:#64748b;width:28px;height:28px;border-radius:6px;cursor:pointer;font-size:14px;line-height:1;display:flex;align-items:center;justify-content:center;transition:all .2s}
.mx:hover{background:var(--danger-bg);color:var(--danger)}
.mbd{padding:8px 24px 8px;max-height:calc(100vh - 230px);overflow-y:auto}
.mfoot{padding:16px 24px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end;align-items:center}
.mfoot .sp{flex:1}

/* ============ 终端输出 ============ */
pre.out{background:#0f172a;color:#cbd5e1;padding:14px 16px;border-radius:8px;font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;line-height:1.65;overflow:auto;max-height:280px;white-space:pre-wrap;border:1px solid #1e293b}
pre.out .err{color:#fca5a5}

/* ---- 执行详情：结构化元数据 / 折叠面板 / 终端窗口（参考稿样式） ---- */
.meta-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;background:#f8fafc;padding:16px;border-radius:8px;border:1px solid var(--border);margin-bottom:20px}
.meta-item{display:flex;flex-direction:column;gap:4px}
.meta-label{font-size:12px;color:var(--text-muted)}
.meta-value{font-size:14px;font-weight:500;color:var(--text-main);word-break:break-all}
.meta-value.title{color:var(--primary);font-weight:600}
.accordion{border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:16px;background:#fff}
.accordion-header{padding:14px 16px;background:#fff;display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none;transition:background .2s;font-size:14px;font-weight:500;color:var(--text-main)}
.accordion-header:hover{background:#f8fafc}
.accordion-header svg{width:16px;height:16px;color:var(--text-muted);transition:transform .3s ease;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.accordion.open .accordion-header svg{transform:rotate(180deg)}
.accordion-content{max-height:0;overflow:hidden;transition:max-height .3s ease-out;background:#fff}
.accordion.open .accordion-content{max-height:4000px;transition:max-height .5s ease-in}
.accordion-content .plain{padding:16px;border-top:1px solid var(--border);font-size:13px;color:var(--text-muted);white-space:pre-wrap;line-height:1.7;word-break:break-all}
.terminal-wrapper{padding:16px;border-top:1px solid var(--border)}
.tag-ok{background:var(--success-bg);color:var(--success);border:1px solid #a7f3d0;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}
.tag-fail{background:var(--danger-bg);color:var(--danger);border:1px solid #fecaca;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}
.command-text{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;color:var(--text-main);font-weight:500;background:#f1f5f9;padding:2px 8px;border-radius:4px;word-break:break-all}
.terminal-window{background:#0f172a;border-radius:8px;overflow:hidden;box-shadow:inset 0 0 0 1px rgba(255,255,255,.05)}
.terminal-header{background:#1e293b;padding:10px 16px;display:flex;align-items:center;border-bottom:1px solid #334155}
.mac-dots{display:flex;gap:6px}
.dot{width:10px;height:10px;border-radius:50%}
.dot.red{background:#ef4444}.dot.yellow{background:#f59e0b}.dot.green{background:#10b981}
.terminal-title{margin-left:16px;font-size:11px;color:#94a3b8}
.terminal-body{padding:16px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;line-height:1.6;color:#e2e8f0;overflow:auto;max-height:320px;white-space:pre-wrap;word-break:break-all}
.err-banner{margin-bottom:0}

/* ---- 执行过程时间线 ---- */
.timeline{position:relative;padding-left:22px;margin-bottom:20px}
.timeline::before{content:"";position:absolute;left:6px;top:6px;bottom:6px;width:2px;background:var(--border)}
.tl-item{position:relative;padding:0 0 14px 6px}
.tl-item:last-child{padding-bottom:0}
.tl-dot{position:absolute;left:-22px;top:3px;width:12px;height:12px;border-radius:50%;background:#fff;border:2.5px solid var(--text-faint);z-index:1}
.tl-item.ok .tl-dot{border-color:var(--success)}
.tl-item.warn .tl-dot{border-color:var(--warn)}
.tl-item.bad .tl-dot{border-color:var(--danger)}
.tl-text{font-size:13px;color:var(--text-main);line-height:1.55}
.tl-item.ok .tl-text{color:#047857}
.tl-item.warn .tl-text{color:var(--warn-d)}
.tl-item.bad .tl-text{color:var(--danger-d);font-weight:500}
.tl-ts{font-size:11px;color:var(--text-faint);font-family:ui-monospace,Menlo,Consolas,monospace;margin-top:2px}
.tl-ev{margin-top:6px}
.timeline-title{font-size:14px;font-weight:600;margin-bottom:12px}
details{margin:8px 0}
details summary{cursor:pointer;color:var(--text-muted);font-size:12.5px;padding:4px 0;outline:none}
details summary:hover{color:var(--primary)}
.err-banner{color:var(--danger-d);background:var(--danger-bg);border:1px solid #fecaca;border-radius:6px;padding:10px 14px;margin-bottom:12px;font-size:13px}
.hit-ok{background:var(--success-bg);color:var(--success-d);border:1px solid #a7f3d0;border-radius:6px;padding:10px 14px;margin-bottom:10px;font-size:13px;line-height:1.6}
.hit-bad{background:var(--danger-bg);color:var(--danger-d);border:1px solid #fecaca;border-radius:6px;padding:10px 14px;margin-bottom:10px;font-size:13px}

/* ============ 登录 ============ */
.login{position:fixed;inset:0;background:radial-gradient(720px 420px at 20% 15%,rgba(79,70,229,.35),transparent 65%),radial-gradient(640px 420px at 80% 85%,rgba(59,130,246,.25),transparent 65%),var(--sidebar-bg);display:none;align-items:center;justify-content:center;z-index:200}
.login.show{display:flex}
.login .box{background:#fff;border-radius:12px;padding:36px 34px;width:360px;box-shadow:0 32px 80px rgba(0,0,0,.45)}
.login .lg-logo{width:48px;height:48px;border-radius:10px;background:var(--primary);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:bold;font-size:24px;margin-bottom:16px}
.login h3{font-size:18px;margin-bottom:4px}
.login .ls{font-size:12.5px;color:var(--text-muted);margin-bottom:22px}
.login input{padding:11px 13px;font-size:14px}
.login .btn{width:100%;padding:11px;font-size:14px;margin-top:12px}
#lg_err{color:var(--danger);margin-top:10px;font-size:12.5px}

/* ============ Toast ============ */
#toast-container{position:fixed;top:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{display:flex;align-items:center;gap:10px;min-width:250px;max-width:420px;padding:12px 16px;background:#fff;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,.15);font-size:13px;font-weight:500;border-left:4px solid var(--success);transform:translateX(120%);transition:transform .3s cubic-bezier(.68,-.55,.265,1.55);word-break:break-all}
.toast.show{transform:translateX(0)}
.toast.error{border-left-color:var(--danger)}
.toast .ti{font-weight:bold}

@media (max-width:1000px){
  .brand{margin-right:12px}
  .top-nav button{padding:8px 12px;font-size:13px}
  .sidebar{width:56px;flex-basis:56px}
  .side-title,.nav-item span{display:none}
  .nav-item{justify-content:center;padding:11px}
  .nav-item svg{margin-right:0}
  .stat-grid,.grid2,.grid3,.kv{grid-template-columns:1fr}
  .stat-grid.stat-6{grid-template-columns:repeat(3,1fr)}
  .kv label{text-align:left}
  .content-scroll{padding:16px}
}
</style>
</head>
<body>

<div id="toast-container"></div>
<div class="qtip" id="qtip"><div class="qarrow" id="qarrow"></div><span id="qtipText"></span></div>

<!-- 顶部一级菜单 -->
<header class="headerbar">
  <div class="logo-icon">A</div>
  <div class="brand">线路切换平台</div>
  <nav class="top-nav" id="topNav">
    <button class="active" data-g="monitor">监控中心</button>
    <button data-g="config">切换配置</button>
    <button data-g="resource">资源管理</button>
    <button data-g="system">系统设置</button>
  </nav>
  <div class="header-actions">
    <span class="ver-top" id="ver"></span>
    <button class="btn-logout" onclick="logout()"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></svg>退出</button>
  </div>
</header>

<div class="app-row">
<!-- 左侧二级菜单 -->
<aside class="sidebar">
  <div class="side-nav" id="sideNav"></div>
</aside>

<!-- 主内容 -->
<main class="main-container">
  <div class="content-scroll">

  <!-- 执行记录 -->
  <div class="page-view active" id="p-dash">
    <div class="stat-grid stat-6" id="stat"></div>
    <div class="card">
      <div class="card-header"><h3>执行记录<span class="q" data-tip="每 30 秒自动刷新">?</span></h3><button class="btn btn-secondary btn-sm" onclick="loadStats();loadLogs()">刷新</button></div>
      <div class="table-responsive"><table class="data-table" style="table-layout:fixed">
      <colgroup><col style="width:44px"><col style="width:138px"><col style="width:52px"><col style="width:220px"><col style="width:96px"><col style="width:84px"><col style="width:58px"><col style="width:88px"><col></colgroup>
      <thead><tr>
        <th>ID</th><th>时间</th><th>触发</th><th>告警标题</th>
        <th>动作</th><th>设备</th><th>模式</th><th>状态</th><th>错误</th></tr></thead>
      <tbody id="logtb"></tbody></table></div>
    </div>
  </div>

  <!-- 匹配预检 -->
  <div class="page-view" id="p-match">
    <div class="card">
      <div class="card-body" style="display:flex;flex-direction:column;gap:16px">
        <div class="toolbar-row">
          <div class="input-group">
            <input id="mt_title" placeholder="输入告警标题，如 【ICMP中断】41.243.21.170-华刚卢本-Airtel" onkeydown="if(event.key=='Enter')matchTest()">
            <button class="btn btn-primary" onclick="matchTest()">检测规则</button>
          </div>
        </div>
        <div id="mt_out"></div>
        <div class="action-buttons" style="border-top:1px dashed var(--border);padding-top:16px">
          <select id="rp_days"><option value="1">近 1 天</option><option value="7" selected>近 7 天</option><option value="14">近 14 天</option><option value="30">近 30 天</option></select>
          <button class="btn btn-secondary" onclick="replayRun()">拉取 AIOps 标题并回放<span class="q" style="margin-left:8px" data-tip="以真实告警校验规则覆盖情况；未命中标题用于补充关键词">?</span></button>
        </div>
        <div id="rp_out"></div>
      </div>
    </div>
  </div>

  <!-- 切换动作 -->
  <div class="page-view" id="p-actions">
    <div class="card">
      <div class="card-header"><h3>动作规则<span class="q" data-tip="包含模式：逗号分隔关键词，全部包含才命中；正则模式：单个正则。&#10;命令块中 # 开头行为注释，执行时跳过。">?</span></h3><button class="btn btn-primary" onclick="editAction(0)">＋ 新建动作</button></div>
      <div class="table-responsive"><table class="data-table"><thead><tr>
        <th style="width:90px">状态</th><th style="width:220px">动作名 / 设备</th><th style="width:90px">匹配方式</th>
        <th>关键词 / 正则</th><th style="width:80px">冷却</th><th style="width:300px;text-align:right">执行操作</th></tr></thead>
      <tbody id="acttb"></tbody></table></div>
    </div>
  </div>

  <!-- 设备管理 -->
  <div class="page-view" id="p-devices">
    <div class="card">
      <div class="card-header"><h3>设备列表</h3><button class="btn btn-primary" onclick="editDevice(0)">＋ 新建设备</button></div>
      <div class="table-responsive"><table class="data-table"><thead><tr>
        <th style="width:90px">状态</th><th style="width:220px">设备名 / 地址</th><th style="width:110px">站点</th>
        <th style="width:80px">协议</th><th style="width:100px">账号</th><th style="width:70px">超时</th>
        <th style="width:240px;text-align:right">操作</th></tr></thead>
      <tbody id="devtb"></tbody></table></div>
    </div>
  </div>

  <!-- 站点管理 -->
  <div class="page-view" id="p-sites">
    <div class="card">
      <div class="card-header"><h3>站点列表</h3><button class="btn btn-primary" onclick="editSite(0)">＋ 新建站点</button></div>
      <div class="table-responsive"><table class="data-table"><thead><tr>
        <th style="width:220px">站点名称</th><th>线路</th><th style="width:220px">备注</th><th style="width:220px;text-align:right">操作</th></tr></thead>
      <tbody id="sitetb"></tbody></table></div>
    </div>
  </div>

  <!-- 全局设置 -->
  <div class="page-view" id="p-settings">
    <div class="card">
      <div class="card-body">
        <div class="kv"><label>Web 登录密码</label><div class="ctl"><input type="password" id="s_pwd" placeholder="留空不修改"></div></div>
        <div class="kv"><label>API Token<span class="q" data-tip="AIOps 回调本系统时携带 X-API-Token 请求头。&#10;回调接口：POST /api/alert，Body: {&quot;title&quot;:&quot;告警标题&quot;}">?</span></label><div class="ctl"><input id="s_token"></div></div>
        <div class="kv"><label>全局冷却(秒)</label><div class="ctl"><input id="s_cd" type="number" style="max-width:220px"></div></div>
        <div class="kv"><label>AIOps 告警接口</label><div class="ctl"><input id="s_aiops_url"></div></div>
        <div class="kv"><label>AIOps Token</label><div class="ctl"><input id="s_aiops_tok" placeholder="留空不修改"></div></div>
        <div class="kv"><label>活跃告警判定窗口(分钟)<span class="q" data-tip="收到告警时查询窗口内未恢复告警，判断其它线路是否同时告警">?</span></label><div class="ctl"><input id="s_window" type="number" placeholder="30" style="max-width:220px"></div></div>
        <button class="btn btn-primary" onclick="saveCfg()">保存设置</button>
      </div>
    </div>
  </div>

  <!-- 回调测试 -->
  <div class="page-view" id="p-alerttest">
    <div class="card">
      <div class="card-body">
        <div class="kv"><label>告警标题</label><div class="ctl"><input id="t_title" placeholder="如 站点A-4G专线中断"></div></div>
        <div style="margin-left:226px"><button class="btn btn-secondary" onclick="testAlert()">发送测试</button></div>
        <pre class="out" id="t_out" style="display:none;margin-top:14px"></pre>
      </div>
    </div>
  </div>

  </div>
</main>
</div><!-- /app-row -->

<!-- 登录 -->
<div class="login" id="loginBox">
  <div class="box">
    <div class="lg-logo">A</div>
    <h3>线路切换平台</h3>
    <div class="ls">告警驱动 · 线路自动切换控制台</div>
    <input type="password" id="lg_pwd" placeholder="Web 登录密码" onkeydown="if(event.key=='Enter')doLogin()">
    <button class="btn btn-primary" onclick="doLogin()">登 录</button>
    <div id="lg_err"></div>
  </div>
</div>

<!-- 动作编辑 -->
<div class="modal" id="mAct"><div class="box">
  <div class="mhd"><h3 id="mActTitle">切换动作</h3><button class="mx" onclick="closeM('mAct')">✕</button></div>
  <div class="mbd">
  <input type="hidden" id="a_id">
  <div class="grid2">
    <div><label>动作名称 *</label><input id="a_name" placeholder="如：切到4G"></div>
    <div><label>所属站点</label><select id="a_site"></select></div>
  </div>
  <div class="grid2">
    <div><label>目标设备 *</label><select id="a_device"></select></div>
    <div><label>匹配方式</label><select id="a_mtype"><option value="contains">包含关键词</option><option value="regex">正则表达式</option></select></div>
  </div>
  <label>匹配关键词 / 正则（包含模式逗号分隔多个，全部包含才命中）*</label>
  <input id="a_kw" placeholder="如：站点A,4G  或正则  站点A.*4G">
  <label>切换命令块（每行一条命令，# 开头为注释）<span class="q" data-tip="建议一个方向一个动作：命令块内先 undo 掉其它所有方向的策略，再添加本方向，形成「完整状态」——从任意当前状态切过来结果都确定，无需系统排序。">?</span></label>
  <textarea id="a_cmd" rows="10"></textarea>
  <label>回切命令块（可选，手动触发用）</label>
  <textarea id="a_rb" rows="5"></textarea>
  <label>验证命令块（可选，切换完成后重新登录执行并检查期望内容）</label>
  <textarea id="a_verify" rows="2" placeholder="display ip routing-table"></textarea>
  <div class="grid2">
    <div><label>目标线路（切换到哪条，用于日志/判定展示）</label><input id="a_target" placeholder="如 Vodacom"></div>
    <div><label>期望关键词（逗号分隔，须全部出现在验证回显中）</label><input id="a_expect" placeholder="如：192.168.130.2"></div>
  </div>
  <div class="grid2">
    <div><label>冷却时间(秒，0=用全局)</label><input id="a_cd" type="number" value="0"></div>
    <label class="sw"><input type="checkbox" id="a_en" checked><span>启用该动作</span></label>
  </div>
  </div>
  <div class="mfoot">
    <button class="btn btn-secondary" onclick="closeM('mAct')">取消</button>
    <span class="sp"></span>
    <button class="btn btn-primary" onclick="saveAction()">保存</button>
  </div>
</div></div>

<!-- 设备编辑 -->
<div class="modal" id="mDev"><div class="box">
  <div class="mhd"><h3 id="mDevTitle">设备</h3><button class="mx" onclick="closeM('mDev')">✕</button></div>
  <div class="mbd">
  <input type="hidden" id="d_id">
  <div class="grid2">
    <div><label>设备名称 *</label><input id="d_name"></div>
    <div><label>所属站点</label><select id="d_site"></select></div>
  </div>
  <div class="grid3">
    <div><label>地址 Host *</label><input id="d_host"></div>
    <div><label>端口</label><input id="d_port" type="number" value="23"></div>
    <div><label>协议</label><select id="d_proto"><option value="telnet">telnet</option><option value="ssh">ssh</option></select></div>
  </div>
  <div class="grid3">
    <div><label>账号</label><input id="d_user"></div>
    <div><label>密码</label><input id="d_pwd" type="password" placeholder="留空不修改"></div>
    <div><label>enable 密码(可选)</label><input id="d_epwd" type="password" placeholder="留空不修改"></div>
  </div>
  <div class="grid3">
    <div><label>登录后初始命令</label><input id="d_init" value="screen-length 0 temporary"></div>
    <div><label>提示符正则(空=默认)</label><input id="d_prompt" placeholder="默认华为/H3C"></div>
    <div><label>超时(秒)</label><input id="d_to" type="number" value="10"></div>
  </div>
  <div class="grid2">
    <div><label>状态查询命令(查当前生效线路)</label><input id="d_scmd" value="display ip routing-table" placeholder="留空则用 display ip routing-table"></div>
    <div><label>当前线路正则(空=默认解析 0.0.0.0/0 下一跳)</label><input id="d_cregex" placeholder="如: 0\.0\.0\.0.*?(\d+\.\d+\.\d+\.\d+)"></div>
  </div>
  <label class="sw"><input type="checkbox" id="d_en" checked><span>启用该设备</span></label>
  <pre class="out" id="d_test" style="display:none;margin-top:12px"></pre>
  </div>
  <div class="mfoot">
    <button class="btn btn-secondary" onclick="closeM('mDev')">取消</button>
    <span class="sp"></span>
    <button class="btn btn-success" onclick="testDevice()">测试连接</button>
    <button class="btn btn-warning" onclick="queryDeviceLine()">查当前线路</button>
    <button class="btn btn-primary" onclick="saveDevice()">保存</button>
  </div>
</div></div>

<!-- 站点编辑 -->
<div class="modal" id="mSite"><div class="box" style="width:460px">
  <div class="mhd"><h3 id="mSiteTitle">站点</h3><button class="mx" onclick="closeM('mSite')">✕</button></div>
  <div class="mbd">
  <input type="hidden" id="si_id">
  <label>站点名称 *</label><input id="si_name" placeholder="如：站点A">
  <label>备注</label><input id="si_rm">
  </div>
  <div class="mfoot">
    <button class="btn btn-secondary" onclick="closeM('mSite')">取消</button>
    <span class="sp"></span>
    <button class="btn btn-primary" onclick="saveSite()">保存</button>
  </div>
</div></div>

<!-- 站点线路 -->
<div class="modal" id="mLine"><div class="box" style="width:780px">
  <div class="mhd"><h3 id="mLineTitle">站点线路</h3><span class="q" data-tip="线路是全站统一配置：告警关键词用于①识别告警说的是哪条线路②查 AIOps 判断是否多条线路同时告警；下一跳IP用于识别设备当前运行在哪条线路上（线路映射只在此维护）。">?</span><button class="mx" onclick="closeM('mLine')">✕</button></div>
  <div class="mbd">
  <input type="hidden" id="l_site">
  <div class="table-responsive"><table class="data-table"><thead><tr><th>线路名</th><th>告警关键词</th><th>下一跳IP<span class="q" data-tip="该线路生效时路由表 0.0.0.0/0 的下一跳地址，用于识别「当前运行在哪条线路上」">?</span></th><th style="width:90px">优先级</th><th style="width:90px">状态</th><th style="width:100px;text-align:right">操作</th></tr></thead>
  <tbody id="ltb"></tbody></table></div>
  <div class="grid2" style="margin-top:14px">
    <div><label>线路名</label><input id="l_name" placeholder="如 Airtel"></div>
    <div><label>下一跳IP（该线路生效时 0.0.0.0/0 的 NextHop）</label><input id="l_ip" placeholder="如 192.168.130.10"></div>
  </div>
  <div class="grid2">
    <div><label>告警关键词(逗号分隔)</label><input id="l_kw" placeholder="如 41.243.21.170,Airtel"></div>
    <div><label>优先级(1最高)</label><input id="l_pri" type="number" value="1"></div>
  </div>
  </div>
  <div class="mfoot">
    <button class="btn btn-secondary" onclick="closeM('mLine')">关闭</button>
    <span class="sp"></span>
    <button class="btn btn-primary" onclick="addLine()">添加线路</button>
  </div>
</div></div>

<!-- 日志详情 -->
<div class="modal" id="mLog"><div class="box" style="width:900px">
  <div class="mhd"><h3 id="mLogTitle">执行详情</h3><button class="mx" onclick="closeM('mLog')">✕</button></div>
  <div class="mbd" id="mLogBody"></div>
  <div class="mfoot"><button class="btn btn-secondary" onclick="closeM('mLog')">关闭</button></div>
</div></div>

<script>
let DATA={sites:[],devices:[],actions:[],logs:[]};
const $=id=>document.getElementById(id);
const esc=s=>(s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function api(m,u,b){return fetch(u,{method:m,headers:{"Content-Type":"application/json"},body:b?JSON.stringify(b):undefined}).then(r=>{
  if(r.status==401){$("loginBox").classList.add("show");throw new Error("unauthorized")}
  return r.json()})}
function closeM(id){$(id).classList.remove("show")}

// ---- Toast（替代 alert） ----
function showToast(msg,isError){
  const t=document.createElement("div");
  t.className="toast"+(isError?" error":"");
  t.innerHTML='<div class="ti" style="color:'+(isError?"var(--danger)":"var(--success)")+'">'+(isError?"✕":"✓")+'</div><div>'+esc(msg)+'</div>';
  $("toast-container").appendChild(t);
  setTimeout(()=>t.classList.add("show"),10);
  setTimeout(()=>{t.classList.remove("show");setTimeout(()=>t.remove(),350)},isError?9000:6000)}

// ---- 登录 ----
function doLogin(){api("POST","/api/login",{password:$("lg_pwd").value}).then(()=>{
  $("loginBox").classList.remove("show");$("lg_err").textContent="";boot()}).catch(()=>{$("lg_err").textContent="密码错误"})}
function logout(){api("POST","/api/logout").then(()=>location.reload())}

// ---- 导航：顶部一级 + 左侧二级 ----
const PAGE_INFO={dash:["执行记录","切换任务执行历史与结果"],match:["匹配预检","校验告警标题与动作规则的对应关系"],
  actions:["切换动作","动作规则与命令块维护"],
  devices:["设备管理","站点设备连接与线路识别"],sites:["站点管理","站点与线路配置"],
  settings:["全局设置","接口、令牌与判定参数"],alerttest:["回调测试","模拟告警回调验证链路"]};
const NAV_GROUPS={
  monitor:{title:"监控中心",items:[["dash","执行记录",'<path d="M3 12h4l3-8 5 16 3-8h4"/>']]},
  config:{title:"切换配置",items:[["actions","切换动作",'<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>'],["match","匹配预检",'<circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>']]},
  resource:{title:"资源管理",items:[["devices","设备管理",'<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>'],["sites","站点管理",'<path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>']]},
  system:{title:"系统设置",items:[["settings","全局设置",'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>'],["alerttest","回调测试",'<path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/>']]}};
let CUR_PAGE="dash";
function buildSideNav(g){
  const grp=NAV_GROUPS[g];
  $("sideNav").innerHTML='<div class="side-title">'+grp.title+'</div>'+
    grp.items.map(it=>`<button class="nav-item${it[0]==CUR_PAGE?" active":""}" data-p="${it[0]}"><svg viewBox="0 0 24 24">${it[2]}</svg><span>${it[1]}</span></button>`).join("");
  document.querySelectorAll("#sideNav .nav-item").forEach(b=>b.onclick=()=>openPage(b.dataset.p));
}
function openPage(p){
  CUR_PAGE=p;
  document.querySelectorAll(".nav-item").forEach(x=>x.classList.toggle("active",x.dataset.p==p));
  document.querySelectorAll(".page-view").forEach(v=>v.classList.remove("active"));
  $("p-"+p).classList.add("active");
  refresh(p)}
document.querySelectorAll("#topNav button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#topNav button").forEach(x=>x.classList.remove("active"));b.classList.add("active");
  buildSideNav(b.dataset.g);
  const grp=NAV_GROUPS[b.dataset.g];
  const first=grp.items.some(it=>it[0]==CUR_PAGE)?CUR_PAGE:grp.items[0][0];
  openPage(first)});
function gotoGroup(g,p){const tb=document.querySelector('#topNav button[data-g="'+g+'"]');if(tb)tb.click();if(p)openPage(p)}
function refresh(p){
  if(p=="dash"){loadStats();loadLogs()}
  if(p=="actions")loadActions();
  if(p=="devices")loadDevices();
  if(p=="sites")loadSites();
  if(p=="settings")loadCfg()}
// match / alerttest 为纯交互页，无需预加载

// ---- 仪表盘 ----
const STAT=[
 ["total","总执行","#4f46e5","#e0e7ff",'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8M16 17H8"/>'],
 ["success","成功","#10b981","#d1fae5",'<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/>'],
 ["failed","失败","#ef4444","#fee2e2",'<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>'],
 ["running","执行中","#f59e0b","#fef3c7",'<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>'],
 ["skipped","条件不满足","#64748b","#e2e8f0",'<path d="M5 12h14"/><path d="M13 5l7 7-7 7"/>'],
 ["verify_failed","验证未过","#f97316","#ffedd5",'<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>']];
function loadStats(){api("GET","/api/stats").then(s=>{
  $("ver").textContent=s.version;
  $("stat").innerHTML=STAT.map(x=>`<div class="stat-card">
    <div class="stat-ic" style="background:${x[3]};color:${x[2]}"><svg viewBox="0 0 24 24">${x[4]}</svg></div>
    <div><b>${s[x[0]]}</b><span>${x[1]}</span></div></div>`).join("")})}
const ST_TAG={success:["成功","ok"],failed:["失败","bad"],running:["执行中","info"],cooldown_skip:["冷却跳过","gray"],
  verify_failed:["验证未过","warn"],skipped:["条件不满足","gray"],cooldown:["冷却中","warn"]};
function loadLogs(){api("GET","/api/logs?limit=100").then(ls=>{DATA.logs=ls;
  $("logtb").innerHTML=ls.length?ls.map(l=>{const st=ST_TAG[l.status]||[esc(l.status),"gray"];
    return `<tr class="clickable" onclick="showLog(${l.id})">
    <td class="mono" style="color:var(--text-muted)">#${l.id}</td>
    <td class="mono" style="white-space:nowrap;color:var(--text-muted)">${esc(l.started_at)}</td>
    <td><span class="tag ${l.trigger=="api"?"info":"gray"}">${l.trigger=="api"?"API":"手动"}</span></td>
    <td style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><span class="keyword-text" title="${esc(l.alarm_title)}">${esc(l.alarm_title)||"-"}</span></td>
    <td style="overflow:hidden"><b>${esc(l.action_name)}</b></td><td style="overflow:hidden">${esc(l.device_name)}</td>
    <td>${l.dry_run?"演练":(l.rollback?"回切":"切换")}</td>
    <td><span class="tag ${st[1]}">${st[0]}</span></td>
    <td style="overflow:hidden"><span class="err-text">${esc(l.error)||"-"}</span></td></tr>`}).join(""):'<tr><td colspan=9><div class="empty"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 5 16 3-8h4"/></svg>暂无执行记录</div></td></tr>'})}
function showLog(id){api("GET","/api/logs/"+id).then(l=>{
  $("mLogTitle").innerHTML=`执行详情 <span>#${l.id} · ${esc(l.action_name)} · ${(ST_TAG[l.status]||[l.status])[0]}</span>`;
  const ARROW='<svg viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>';
  const term=(title,text,open)=>`<div class="accordion${open?" open":""}"><div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">${title}${ARROW}</div><div class="accordion-content"><div class="terminal-wrapper" style="padding-top:0;border-top:none"><div class="terminal-window"><div class="terminal-header"><div class="mac-dots"><div class="dot red"></div><div class="dot yellow"></div><div class="dot green"></div></div><span class="terminal-title">Session Transcript</span></div><div class="terminal-body">${esc(text)}</div></div></div></div></div>`;
  let h=`<div class="meta-grid">
    <div class="meta-item"><span class="meta-label">告警标题</span><span class="meta-value title">${esc(l.alarm_title)||"-"}</span></div>
    <div class="meta-item"><span class="meta-label">故障线路</span><span class="meta-value">${esc(l.source_line)||"-"}</span></div>
    <div class="meta-item"><span class="meta-label">切换前当前线路</span><span class="meta-value">${esc(l.precheck_line)||"未查询"}</span></div>
    <div class="meta-item"><span class="meta-label">开始时间</span><span class="meta-value">${esc(l.started_at)}</span></div>
    <div class="meta-item"><span class="meta-label">结束时间</span><span class="meta-value">${esc(l.finished_at)||"-"}</span></div>
    <div class="meta-item"><span class="meta-label">设备</span><span class="meta-value">${esc(l.device_name)||"-"}</span></div>
  </div>`;
  let tl=[];try{tl=JSON.parse(l.timeline||"[]")}catch(e){}
  if(tl.length)h+=`<div class="timeline-title">执行过程</div><div class="timeline">`+
    tl.map(t=>`<div class="tl-item ${t.kind||""}"><div class="tl-dot"></div>
      <div class="tl-text">${esc(t.text)}</div><div class="tl-ts">${esc((t.ts||"").slice(11))}</div>
      ${t.ev?`<div class="tl-ev"><div class="terminal-window" style="margin-top:6px"><div class="terminal-header"><div class="mac-dots"><div class="dot red"></div><div class="dot yellow"></div><div class="dot green"></div></div><span class="terminal-title">${t.step?"Command Output":"证据"}</span></div><div class="terminal-body" style="max-height:240px">${esc(t.ev)}</div></div></div>`:""}</div>`).join("")+`</div>`;
  if(l.error)h+=`<div class="err-banner">错误：${esc(l.error)}</div>`;
  if(l.session_log)h+=term("会话原文",l.session_log,false);
  if((l.steps||[]).length&&!tl.some(t=>t.step))h+=`<div class="timeline-title">命令执行<span class="q" data-tip="旧版记录的回退展示">?</span></div>`+
    l.steps.map(s=>`<div class="accordion${s.ok?"":" open"}">
    <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
      <span style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><span class="${s.ok?"tag-ok":"tag-fail"}">${s.ok?"OK":"FAIL"}</span><span class="command-text">${esc(s.command)}</span></span>${ARROW}</div>
    <div class="accordion-content"><div class="terminal-wrapper" style="padding-top:0;border-top:none">
      <div class="terminal-window">
        <div class="terminal-header"><div class="mac-dots"><div class="dot red"></div><div class="dot yellow"></div><div class="dot green"></div></div><span class="terminal-title">Router Output</span></div>
        <div class="terminal-body ${s.ok?"":"err"}">${esc(s.output)||"(无回显)"}</div>
      </div>
    </div></div></div>`).join("");
  $("mLogBody").innerHTML=h;$("mLog").classList.add("show")})}

// ---- 动作 ----
function loadActions(){Promise.all([api("GET","/api/actions"),api("GET","/api/sites"),api("GET","/api/devices")]).then(([a,s,d])=>{
  DATA.actions=a;DATA.sites=s;DATA.devices=d;
  $("acttb").innerHTML=a.length?a.map(x=>`<tr>
    <td><div class="status-cell"><div class="${x.enabled?"dot-green":"dot-red"}"></div>${x.enabled?"启用":"停用"}</div></td>
    <td><div class="device-info"><span class="device-name">${esc(x.name)}</span>
      <span class="device-host">${esc(x.site_name?x.site_name+" · ":"")}${esc(x.protocol||"")}://${esc(x.host||"")}</span></div></td>
    <td><span class="tag ${x.match_type=="regex"?"":"info"}">${x.match_type=="regex"?"正则":"包含"}</span></td>
    <td><span class="keyword-text">${esc(x.match_keywords)}</span></td>
    <td>${x.cooldown||"全局"}</td>
    <td><div class="ops-cell">
      <button class="btn btn-sm btn-primary" onclick="execAction(${x.id})">执行</button>
      <button class="btn btn-sm btn-secondary" onclick="execAction(${x.id},true)">演练</button>
      <button class="btn btn-sm btn-secondary" onclick="execAction(${x.id},false,true)">回切</button>
      <button class="btn btn-sm btn-secondary" onclick="editAction(${x.id})">编辑</button>
      <button class="btn btn-sm btn-danger" onclick="delAction(${x.id})">删除</button></div></td></tr>`).join(""):
    '<tr><td colspan=6><div class="empty"><svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>暂无动作</div></td></tr>'})}
function fillSelect(sel,list,labelFirst){$(sel).innerHTML=`<option value="">(不选)</option>`+
  list.map(x=>`<option value="${x.id}">${esc(labelFirst?x.name:x.name+(x.host?" ("+x.host+")":""))}</option>`).join("")}
function editAction(id){const a=DATA.actions.find(x=>x.id==id)||{};
  fillSelect("a_site",DATA.sites);fillSelect("a_device",DATA.devices);
  $("a_id").value=a.id||"";$("a_name").value=a.name||"";$("a_site").value=a.site_id||"";
  $("a_device").value=a.device_id||"";$("a_mtype").value=a.match_type||"contains";
  $("a_kw").value=a.match_keywords||"";$("a_cmd").value=a.command_block||"";
  $("a_rb").value=a.rollback_block||"";$("a_verify").value=a.verify_block||"";
  $("a_expect").value=a.expect_keywords||"";$("a_target").value=a.target_line||"";
  $("a_cd").value=a.cooldown||0;$("a_en").checked=!!a.enabled||!a.id;
  $("mActTitle").textContent=a.id?"编辑动作 #"+a.id:"新建动作";$("mAct").classList.add("show")}
function saveAction(){const b={id:$("a_id").value||null,name:$("a_name").value.trim(),
  site_id:$("a_site").value?+$("a_site").value:null,device_id:+$("a_device").value||null,
  match_type:$("a_mtype").value,match_keywords:$("a_kw").value.trim(),
  command_block:$("a_cmd").value,rollback_block:$("a_rb").value,
  verify_block:$("a_verify").value,expect_keywords:$("a_expect").value.trim(),
  target_line:$("a_target").value.trim(),
  cooldown:+$("a_cd").value||0,enabled:$("a_en").checked?1:0};
  if(!b.name||!b.device_id||!b.match_keywords){showToast("动作名、设备、匹配关键词必填",1);return}
  api(b.id?"PUT":"POST",b.id?"/api/actions/"+b.id:"/api/actions",b).then(()=>{
    closeM("mAct");showToast("动作已保存");loadActions()})}
function delAction(id){if(confirm("确认删除动作 #"+id+"？"))api("DELETE","/api/actions/"+id).then(()=>{showToast("已删除");loadActions()})}
function execAction(id,dry,rb){if(dry===false&&id===0)return;
  const q=dry?"?dry_run=1":(rb?"?rollback=1":"");
  api("POST","/api/exec/"+id+q,{}).then(r=>{
    showToast(r.executed?("已提交执行（任务 #"+r.task_id+"）"):("未执行："+r.skip_reason),!r.executed);
    loadLogs()}).catch(e=>showToast("提交失败: "+e.message,1))}

// ---- 设备 ----
function loadDevices(){api("GET","/api/devices").then(d=>{DATA.devices=d;
  $("devtb").innerHTML=d.length?d.map(x=>`<tr>
    <td><div class="status-cell"><div class="${x.enabled?"dot-green":"dot-red"}"></div>${x.enabled?"启用":"停用"}</div></td>
    <td><div class="device-info"><span class="device-name">${esc(x.name)}</span>
      <span class="device-host mono">${esc(x.host)}:${x.port}</span></div></td>
    <td>${esc(x.site_name||"-")}</td><td><span class="tag ${x.protocol=="ssh"?"info":"gray"}">${x.protocol}</span></td>
    <td>${esc(x.username)}</td><td>${x.timeout}s</td>
    <td><div class="ops-cell">
      <button class="btn btn-sm btn-success" onclick="testDeviceById(${x.id})">测试</button>
      <button class="btn btn-sm btn-warning" onclick="testDeviceByIdStatus(${x.id})">查线路</button>
      <button class="btn btn-sm btn-secondary" onclick="editDevice(${x.id})">编辑</button>
      <button class="btn btn-sm btn-danger" onclick="delDevice(${x.id})">删除</button></div></td></tr>`).join(""):
    '<tr><td colspan=7><div class="empty"><svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/></svg>暂无设备</div></td></tr>'})}
function editDevice(id){const d=DATA.devices.find(x=>x.id==id)||{};
  api("GET","/api/sites").then(s=>{DATA.sites=s;fillSelect("d_site",s,true)});
  $("d_id").value=d.id||"";$("d_name").value=d.name||"";$("d_host").value=d.host||"";
  $("d_port").value=d.port||23;$("d_proto").value=d.protocol||"telnet";
  $("d_user").value=d.username||"";$("d_pwd").value="";$("d_epwd").value="";
  $("d_init").value=d.init_command!=null?d.init_command:"screen-length 0 temporary";
  $("d_prompt").value=d.prompt||"";$("d_to").value=d.timeout||10;
  $("d_scmd").value=d.status_command!=null?d.status_command:"display ip routing-table";
  $("d_cregex").value=d.current_regex||"";
  $("d_test").style.display="none";
  $("mDevTitle").textContent=d.id?"编辑设备 #"+d.id:"新建设备";$("mDev").classList.add("show")}
function devBody(){return{id:$("d_id").value||null,name:$("d_name").value.trim(),host:$("d_host").value.trim(),
  site_id:$("d_site").value?+$("d_site").value:null,port:+$("d_port").value||23,
  protocol:$("d_proto").value,username:$("d_user").value.trim(),
  password:$("d_pwd").value,enable_password:$("d_epwd").value,
  init_command:$("d_init").value.trim(),prompt:$("d_prompt").value.trim(),
  status_command:$("d_scmd").value.trim(),current_regex:$("d_cregex").value.trim(),
  timeout:+$("d_to").value||10,enabled:$("d_en").checked?1:0}}
function saveDevice(){const b=devBody();
  if(!b.name||!b.host){showToast("设备名与地址必填",1);return}
  api(b.id?"PUT":"POST",b.id?"/api/devices/"+b.id:"/api/devices",b).then(()=>{
    closeM("mDev");showToast("设备已保存");loadDevices()})}
function delDevice(id){if(confirm("确认删除设备 #"+id+"？"))api("DELETE","/api/devices/"+id).then(()=>{showToast("已删除");loadDevices()})}
function _showTest(r,el){const o=$(el);o.style.display="block";
  o.textContent=r.ok?("连接成功\n"+(r.note||[]).join("\n")+(r.banner?"\n"+r.banner:""))
    :("失败 ✗\n"+(r.error||"")+(r.session_tail?"\n\n--- ssh 会话尾部 ---\n"+r.session_tail:""))}
function testDevice(){const b=devBody();
  if(b.id){api("POST","/api/devices/"+b.id+"/test",{}).then(r=>_showTest(r,"d_test"))}
  else{api("POST","/api/devices",b).then(r=>{b.id=r.id;$("d_id").value=r.id;
    api("POST","/api/devices/"+r.id+"/test",{}).then(t=>_showTest(t,"d_test"))})}}
function testDeviceById(id){api("POST","/api/devices/"+id+"/test",{}).then(r=>{
  if(r.ok)showToast("连接成功");else showToast("连接失败: "+(r.error||""),1)})}
function queryDeviceLine(){const id=$("d_id").value;if(!id)return showToast("请先保存设备",1);
  api("POST","/api/devices/"+id+"/status",{}).then(r=>{
    const o=$("d_test");o.style.display="block";
    if(r.ok){o.textContent="当前生效线路: "+(r.current_line||"未识别")+"\n查询命令: "+r.command+((r.note&&r.note.length>1)?"\n\n"+r.note.slice(1).join("\n"):"")+"\n\n回显:\n"+(r.banner||"")}
    else{o.textContent="查询失败: "+(r.error||"")}})}
function testDeviceByIdStatus(id){api("POST","/api/devices/"+id+"/status",{}).then(r=>{
  if(r.ok){let t="当前生效线路: "+(r.current_line||"未识别");
    const hint=(r.note||[]).filter(x=>x.indexOf("提示:")===0);if(hint.length)t+="\n"+hint.join("\n");
    showToast(t)}else showToast("查询失败: "+(r.error||""),1)})}

// ---- 站点 ----
function loadSites(){Promise.all([api("GET","/api/sites"),api("GET","/api/lines")]).then(([s,lines])=>{
  DATA.sites=s;DATA.lines=lines;
  $("sitetb").innerHTML=s.length?s.map(x=>{
    const ls=lines.filter(l=>l.site_id==x.id);
    return `<tr>
    <td><span class="device-name">${esc(x.name)}</span><div class="device-host mono">#${x.id}</div></td>
    <td>${ls.length?ls.map(l=>`<span class="tag ok" style="margin:0 6px 4px 0">${esc(l.name)}</span>`).join(""):'<span style="color:var(--text-faint)">未配置</span>'}</td>
    <td style="color:var(--text-muted)">${esc(x.remark)}</td>
    <td><div class="ops-cell"><button class="btn btn-sm btn-secondary" onclick="editSite(${x.id})">编辑</button>
    <button class="btn btn-sm btn-warning" onclick="manageLines(${x.id},'${esc(x.name)}')">线路</button>
    <button class="btn btn-sm btn-danger" onclick="delSite(${x.id})">删除</button></div></td></tr>`}).join(""):
    '<tr><td colspan=4><div class="empty"><svg viewBox="0 0 24 24"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>暂无站点</div></td></tr>'})}
function editSite(id){const s=DATA.sites.find(x=>x.id==id)||{};
  $("si_id").value=s.id||"";$("si_name").value=s.name||"";$("si_rm").value=s.remark||"";
  $("mSiteTitle").textContent=s.id?"编辑站点":"新建站点";$("mSite").classList.add("show")}
function saveSite(){const b={id:$("si_id").value||null,name:$("si_name").value.trim(),remark:$("si_rm").value};
  if(!b.name){showToast("站点名必填",1);return}
  api(b.id?"PUT":"POST",b.id?"/api/sites/"+b.id:"/api/sites",b).then(()=>{closeM("mSite");showToast("站点已保存");loadSites()})}
function delSite(id){if(confirm("确认删除站点 #"+id+"？"))api("DELETE","/api/sites/"+id).then(()=>{showToast("已删除");loadSites()})}

// ---- 站点线路（互斥判定依据） ----
function manageLines(siteId,siteName){$("l_site").value=siteId;
  $("mLineTitle").textContent="站点线路 · "+siteName;
  $("l_name").value="";$("l_kw").value="";$("l_ip").value="";$("l_pri").value=1;
  loadLines(siteId);$("mLine").classList.add("show")}
function loadLines(siteId){api("GET","/api/lines?site_id="+siteId).then(ls=>{
  $("ltb").innerHTML=ls.length?ls.map(l=>`<tr>
    <td><b>${esc(l.name)}</b></td><td><span class="keyword-text mono" style="color:var(--text-muted)">${esc(l.alarm_keywords)||'(空)'}</span></td>
    <td class="mono" style="color:var(--text-muted)">${esc(l.nexthop_ip)||'-'}</td>
    <td>${l.priority}</td>
    <td><div class="status-cell"><div class="${l.enabled?"dot-green":"dot-red"}"></div>${l.enabled?"启用":"停用"}</div></td>
    <td><div class="ops-cell"><button class="btn btn-sm btn-danger" onclick="delLine(${l.id})">删除</button></div></td></tr>`).join(""):
    '<tr><td colspan=6><div class="empty">暂无线路</div></td></tr>'})}
function addLine(){const b={site_id:+$("l_site").value,name:$("l_name").value.trim(),
  alarm_keywords:$("l_kw").value.trim(),nexthop_ip:$("l_ip").value.trim(),priority:+$("l_pri").value||1};
  if(!b.name)return showToast("线路名必填",1);
  api("POST","/api/lines",b).then(()=>{$("l_name").value="";$("l_kw").value="";$("l_ip").value="";
    showToast("线路已添加");loadLines(b.site_id);loadSites()})}
function delLine(id){if(!confirm("删除该线路？"))return;
  api("DELETE","/api/lines/"+id).then(()=>{loadLines(+$("l_site").value);loadSites()})}

// ---- 设置 ----
function loadCfg(){api("GET","/api/config").then(c=>{
  $("s_pwd").value="";$("s_token").value=c.api_token||"";$("s_cd").value=c.global_cooldown||0;
  $("s_aiops_url").value=c.aiops_url||"";$("s_aiops_tok").value="";
  $("s_window").value=c.active_window_min||30})}
function saveCfg(){const b={api_token:$("s_token").value.trim(),global_cooldown:+$("s_cd").value||0,
  aiops_url:$("s_aiops_url").value.trim(),active_window_min:+$("s_window").value||30};
  if($("s_pwd").value)b.web_password=$("s_pwd").value;
  if($("s_aiops_tok").value)b.aiops_token=$("s_aiops_tok").value.trim();
  api("POST","/api/config",b).then(()=>showToast("设置已保存"))}

// ---- 匹配预检 / 回放 ----
function matchTest(){const t=$("mt_title").value.trim();if(!t)return;
  api("POST","/api/match/test",{title:t}).then(r=>{
    const o=$("mt_out");
    if(!r.matched){o.innerHTML=`<div class="hit-bad">未命中任何动作</div>`;return}
    o.innerHTML=r.hits.map(h=>`<div class="hit-ok">命中 <b>${esc(h.action_name)}</b>（站点 ${esc(h.site||"-")} / 设备 ${esc(h.device?h.device.name:"-")} / ${h.command_lines} 条命令）</div>`).join("")})}
function replayRun(){const d=+$("rp_days").value;
  $("rp_out").innerHTML='<div style="color:var(--text-muted);padding:6px 0">正在拉取 AIOps 告警并回放，请稍候…</div>';
  api("POST","/api/match/replay",{days:d}).then(r=>{
    if(r.error){$("rp_out").innerHTML=`<div class="hit-bad">${esc(r.error)}</div>`;return}
    let h=`<div class="stat-grid" style="margin:6px 0 16px">
      <div class="stat-card"><div class="stat-ic" style="background:#e0e7ff;color:#4f46e5"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg></div><div><b>${r.fetched}</b><span>回放标题数(去重前)</span></div></div>
      <div class="stat-card"><div class="stat-ic" style="background:#d1fae5;color:#10b981"><svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/></svg></div><div><b>${r.matched}</b><span>命中动作</span></div></div>
      <div class="stat-card"><div class="stat-ic" style="background:#fef3c7;color:#f59e0b"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg></div><div><b>${r.unmatched}</b><span>未命中</span></div></div>
      <div class="stat-card"><div class="stat-ic" style="background:#ede9fe;color:#8b5cf6"><svg viewBox="0 0 24 24"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg></div><div><b>${r.unmatched_kinds}</b><span>未命中标题种类</span></div></div></div>`;
    if(r.per_action.length)
      h+=`<div class="table-responsive" style="border:1px solid var(--border);border-radius:8px"><table class="data-table"><thead><tr><th>动作</th><th style="width:120px">命中条数</th></tr></thead><tbody>`+
         r.per_action.map(x=>`<tr><td>${esc(x[0])}</td><td><b>${x[1]}</b></td></tr>`).join("")+`</tbody></table></div>`;
    if(r.unmatched_titles.length)
      h+=`<h3 style="margin:20px 0 10px;font-size:14px;font-weight:600">未命中标题（按次数排序，判断是否属于「不需要切换」的告警）</h3>
          <div class="table-responsive" style="border:1px solid var(--border);border-radius:8px"><table class="data-table"><thead><tr><th style="width:80px">次数</th><th>告警标题</th></tr></thead><tbody>`+
          r.unmatched_titles.map(x=>`<tr><td><b>${x.count}</b></td><td><span class="keyword-text">${esc(x.title)}</span></td></tr>`).join("")+`</tbody></table></div>`;
    $("rp_out").innerHTML=h})}
function testAlert(){const t=$("t_title").value.trim();if(!t)return showToast("请输入标题",1);
  api("POST","/api/alert",{title:t}).then(r=>{const o=$("t_out");o.style.display="block";
    o.textContent=JSON.stringify(r,null,2);loadLogs()})}

// ---- 启动 ----
const PAGE_GROUP={dash:"monitor",match:"config",actions:"config",devices:"resource",sites:"resource",settings:"system",alerttest:"system"};
function boot(){buildSideNav("monitor");refresh("dash");setInterval(()=>{loadStats();loadLogs()},30000);
  const h=(location.hash||"").slice(1);
  if(PAGE_INFO[h])gotoGroup(PAGE_GROUP[h],h)}
api("GET","/api/session").then(()=>{boot()}).catch(()=>{$("loginBox").classList.add("show")});
document.querySelectorAll(".modal").forEach(m=>m.addEventListener("click",e=>{if(e.target===m)m.classList.remove("show")}));
// ---- 问号气泡：全局单例，自动避让视口边缘 ----
(function(){
  const tip=$("qtip"), arrow=$("qarrow"), txt=$("qtipText");
  function place(el){
    txt.textContent=el.dataset.tip||"";
    tip.classList.add("show");
    const r=el.getBoundingClientRect(), tw=tip.offsetWidth, th=tip.offsetHeight, M=8;
    let left=r.left+r.width/2-tw/2, top=r.bottom+7, side="bottom";
    if(left<M)left=M; if(left+tw>window.innerWidth-M)left=window.innerWidth-M-tw;
    if(top+th>window.innerHeight-M){top=r.top-th-7;side="top";}
    tip.style.left=left+"px"; tip.style.top=top+"px";
    const ax=r.left+r.width/2-left-5;
    arrow.style.left=Math.max(10,Math.min(ax,tw-20))+"px";
    if(side==="top"){arrow.style.top="auto";arrow.style.bottom="-5px"}else{arrow.style.top="-5px";arrow.style.bottom="auto"}
  }
  document.addEventListener("mouseover",e=>{const q=e.target.closest(".q");if(q&&q.dataset.tip)place(q)});
  document.addEventListener("mouseout",e=>{if(e.target.closest(".q"))tip.classList.remove("show")});
  window.addEventListener("scroll",()=>tip.classList.remove("show"),true);
})();
</script>
</body>
</html>

"""


def main():
    init_db()
    threading.Thread(target=_worker, daemon=True).start()
    server = ThreadingHTTPServer((LS_BIND, LS_PORT), Handler)
    print("[%s] Axd_Line_Switch 启动: http://%s:%d  db=%s  版本=%s"
          % (now(), LS_BIND, LS_PORT, LS_DB, VERSION))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
