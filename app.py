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
import pty
import queue
import re
import select
import socket
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
            chunk = self.sock.recv(4096)
            return chunk
        else:
            r, _, _ = select.select([self.master_fd], [], [], wait)
            if not r:
                return b""
            return os.read(self.master_fd, 4096)

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
    def connect(self):
        if self.kind == "telnet":
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock.setblocking(True)
        else:
            self.master_fd, slave = pty.openpty()
            cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
                   "-o", "UserKnownHostsFile=/dev/null",
                   "-o", "ConnectTimeout=%d" % max(5, self.timeout),
                   "-p", str(self.port), "-l", self.user or "admin", self.host]
            self.proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave,
                                         close_fds=True, preexec_fn=os.setsid)
            os.close(slave)

        login_re = re.compile(r"(ogin:|sername:|user name:)", re.IGNORECASE)
        passwd_re = re.compile(r"assword:", re.IGNORECASE)
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
                    raise RuntimeError("连接失败: " + tail.strip()[-200:])
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


def parse_current_line(output, line_map_text, custom_regex=""):
    """从状态命令回显中解析当前生效线路。
    优先用自定义正则(捕获组1)；否则默认解析 0.0.0.0/0 路由行的 NextHop(排除 Direct/127.x)。
    再经线路映射转换为线路名；无映射时返回原始标识。"""
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
    return lm.get(ident, ident)


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
        sess.connect()
        login_note = "\n".join(sess.log_lines)
        precheck_line = ""
        # 切换前：查询当前生效线路（演练也执行，用于"只看不切"）
        if (dev["status_command"] or "").strip():
            try:
                out = sess.send_cmd(dev["status_command"].strip())
                precheck_line = parse_current_line(out, dev["line_map"], dev["current_regex"])
                login_note += "\n[切换前] 当前生效线路: %s" % (precheck_line or "未识别(见上方回显)")
            except Exception as e:
                login_note += "\n[切换前] 状态查询失败: %s" % e
        conn.execute("UPDATE exec_logs SET precheck_line=? WHERE id=?", (precheck_line, log_id))
        conn.commit()
        if dry_run:
            return True, "", login_note + "\n[dry-run] 登录成功，未下发切换命令", precheck_line, True, ""
        # 条件判断：当前生效线路必须是故障线路，否则无需切换
        if require_line and precheck_line:
            req = [x.strip() for x in require_line.split(",") if x.strip()]
            if req and precheck_line not in req:
                return (True, "", login_note + "\n[跳过] 当前生效线路为 %s，非故障线路 %s，无需切换"
                        % (precheck_line, "/".join(req)), precheck_line, True,
                        "当前生效线路为 %s（非故障线路 %s），无需切换" % (precheck_line, "/".join(req)))
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
            conn.execute("INSERT INTO exec_steps(log_id,seq,command,output,raw_output,ok,ts) "
                         "VALUES(?,?,?,?,?,?,?)",
                         (log_id, i, cmd, (out or err)[:8000], (sess.last_raw or "")[:20000], ok, now()))
            conn.commit()
            if not ok:
                return (False, "第 %d 条命令失败: %s | %s" % (i, cmd, err),
                        login_note, precheck_line, False, "")
        # 切换后验证：用独立会话重新登录执行（切换命令块的 quit 可能已断开会话）
        verify_ok = True
        verr = ""
        if verify_cmds or expect_kws:
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
                                % (",".join(missing), precheck_line or "未知"))
            except Exception as e:
                verify_ok = False
                verr = "验证会话登录失败: %s" % e
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
            conn.execute("UPDATE exec_logs SET status='failed', error='设备或动作不存在', finished_at=? WHERE id=?",
                         (now(), log_id))
            conn.commit()
            return
        block = (act["rollback_block"] if log["rollback"] else act["command_block"]) or ""
        cmds = parse_block(block)
        if not cmds and not log["dry_run"]:
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
        if skip_reason:
            status = "skipped"
            err = skip_reason
        elif ok and verify_ok:
            status = "success"
        elif ok and not verify_ok:
            status = "verify_failed"
        else:
            status = "failed"
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


def submit_action(conn, action, trigger, title, dry_run=0, rollback=0,
                  source_line="", decision_note=""):
    """创建执行记录并入队。返回 (log_id, skip_reason)。冷却/串行判断在此。"""
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
    cur = conn.execute(
        "INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,alarm_title,"
        "dry_run,rollback,status,precheck_line,source_line,decision_note,started_at) "
        "VALUES(?,?,?,?,?,?,?,?, 'running', '', ?,?,? )",
        (action["id"], action["name"], dev["id"], dev["name"], trigger, title or "",
         dry_run, rollback, source_line, decision_note, now()))
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
                return self._send_json({"total": total, "success": ok, "failed": failed, "running": running})
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
                if not hits:
                    return self._send_json({"matched": False, "title": title})
                act = hits[0]
                dry_run = 1 if str(body.get("dry_run", "")).lower() in ("1", "true", "yes") else 0
                # 站点线路互斥判定：多条线路同时告警 / 无法确认故障线路 → 不切换
                allow, reason, decision = judge_site_alarms(conn, title, act)
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
                    cur = conn.execute(
                        "INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,"
                        "alarm_title,dry_run,rollback,status,source_line,decision_note,started_at,finished_at) "
                        "VALUES(?,?,?,?, 'api', ?,?,0, 'skipped', ?,? ,?,?)",
                        (act["id"], act["name"], act["device_id"], dev["name"] if dev else "",
                         title, dry_run, ",".join(decision.get("fault_lines") or []),
                         (reason + " | " + decision.get("note", "")), now(), now()))
                    conn.commit()
                    base.update({"task_id": None, "executed": False, "skip_reason": reason,
                                 "skip_reason_code": "site_alarm_condition"})
                    return self._send_json(base)
                log_id, skip = submit_action(conn, act, "api", title, dry_run=dry_run,
                                             source_line=",".join(decision.get("fault_lines") or []),
                                             decision_note=decision.get("note", ""))
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
                    "INSERT INTO lines(site_id,name,alarm_keywords,priority,enabled,remark,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (int(body["site_id"]), name, body.get("alarm_keywords") or "",
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
                                             dry_run=dry_run, rollback=rollback)
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
        try:
            def _do():
                sess = DeviceSession(dev, decrypt_pw(dev["password_enc"]))
                sess.connect()
                if want_status:
                    scmd = (dev["status_command"] or "").strip() or "display ip routing-table"
                    out = sess.send_cmd(scmd)
                    line = parse_current_line(out, dev["line_map"], dev["current_regex"])
                    sess.close()
                    return {"ok": True, "current_line": line or "未识别",
                            "command": scmd, "note": sess.log_lines, "banner": out[:800]}
                ver = ""
                try:
                    ver = sess.send_cmd("display version")[:500]
                except Exception:
                    pass
                sess.close()
                return {"ok": True, "note": sess.log_lines, "banner": ver}
            return self._send_json(_with_dev_lock(dev_id, 60, _do))
        except Exception as e:
            return self._send_json({"ok": False, "error": str(e)})

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
                for k in ("name", "alarm_keywords", "priority", "enabled", "remark", "site_id"):
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
PAGE_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Axd_Line_Switch · 线路自动切换</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--line:#e3e6ea;--txt:#1f2d3d;--sub:#7a8699;--pri:#2b6de8;--ok:#18a058;--bad:#d43a3a;--warn:#d98b00}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--txt);font-size:14px}
.topbar{background:#fff;border-bottom:1px solid var(--line);padding:0 20px;display:flex;align-items:center;height:52px;position:sticky;top:0;z-index:10}
.topbar h1{font-size:17px;margin-right:24px;font-weight:600}
.tabs{display:flex;gap:4px;flex:1}
.tabs button{border:none;background:none;padding:8px 14px;cursor:pointer;font-size:14px;color:var(--sub);border-radius:6px}
.tabs button.on{background:#eaf1fe;color:var(--pri);font-weight:600}
.wrap{max-width:1200px;margin:18px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.card h3{font-size:15px;margin-bottom:12px}
.btn{border:1px solid var(--line);background:#fff;color:var(--txt);padding:6px 14px;border-radius:6px;cursor:pointer;font-size:13px}
.btn.pri{background:var(--pri);color:#fff;border-color:var(--pri)}
.btn.ok{background:var(--ok);color:#fff;border-color:var(--ok)}
.btn.warn{background:var(--warn);color:#fff;border-color:var(--warn)}
.btn.bad{background:var(--bad);color:#fff;border-color:var(--bad)}
.btn.sm{padding:3px 10px;font-size:12px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}
th{color:var(--sub);font-weight:500;white-space:nowrap}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px}
.tag.success{background:#e6f7ef;color:var(--ok)} .tag.failed{background:#fdeaea;color:var(--bad)}
.tag.running{background:#eaf1fe;color:var(--pri)} .tag.cooldown{background:#fff7e6;color:var(--warn)}
.tag.verify_failed{background:#fff0e0;color:#c25a00}
.tag.skipped{background:#f1efec;color:#6b6b6b}
.muted{color:var(--sub);font-size:12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
label{display:block;font-size:12px;color:var(--sub);margin:8px 0 4px}
input,select,textarea{width:100%;border:1px solid var(--line);border-radius:6px;padding:7px 9px;font-size:13px;font-family:inherit}
textarea{font-family:Menlo,Consolas,monospace;font-size:12px;line-height:1.5}
.modal{position:fixed;inset:0;background:rgba(15,23,42,.45);display:none;align-items:flex-start;justify-content:center;z-index:100;overflow:auto;padding:40px 16px}
.modal.show{display:flex}
.modal .box{background:#fff;border-radius:12px;padding:20px;width:720px;max-width:100%}
.modal h3{margin-bottom:8px}
.mfoot{margin-top:14px;display:flex;gap:8px;justify-content:flex-end}
.login{position:fixed;inset:0;background:var(--bg);display:flex;align-items:center;justify-content:center;z-index:200}
.login .box{background:#fff;border:1px solid var(--line);border-radius:12px;padding:32px;width:320px}
pre.out{background:#1f2d3d;color:#d5e2f5;padding:10px;border-radius:8px;font-size:12px;overflow:auto;max-height:260px;white-space:pre-wrap}
pre.out .err{color:#ff9c9c}
.stat{display:flex;gap:12px;margin-bottom:14px}
.stat .it{flex:1;background:#fff;border:1px solid var(--line);border-radius:10px;padding:12px 16px}
.stat .it b{font-size:22px;display:block}
.stat .it span{color:var(--sub);font-size:12px}
.kv{display:flex;align-items:center;gap:10px;margin:10px 0}
.kv label{margin:0;width:130px}
.sw{display:flex;align-items:center;gap:6px;margin-top:6px}
.steps td{padding:4px 8px}
</style>
</head>
<body>
<div class="topbar">
  <h1>Axd_Line_Switch</h1>
  <div class="tabs" id="tabs">
    <button data-p="dash" class="on">执行记录</button>
    <button data-p="actions">切换动作</button>
    <button data-p="devices">设备管理</button>
    <button data-p="sites">站点管理</button>
    <button data-p="settings">全局设置</button>
  </div>
  <button class="btn sm" onclick="logout()">退出</button>
</div>
<div class="wrap">

<div id="p-dash">
  <div class="stat" id="stat"></div>
  <div class="card">
    <h3>执行记录 <span class="muted">（点击行查看每条命令回显与会话原文；30 秒自动刷新）</span>
      <button class="btn sm" onclick="loadLogs()" style="float:right">刷新</button></h3>
    <table><thead><tr><th>ID</th><th>时间</th><th>触发</th><th>告警标题</th><th>动作</th><th>设备</th><th>模式</th><th>状态</th><th>错误</th></tr></thead>
    <tbody id="logtb"></tbody></table>
  </div>
</div>

<div id="p-actions" style="display:none">
  <div class="card">
    <h3>匹配预检 <span class="muted">—— 确认"告警标题 ↔ 站点/线路"对应关系是否正确</span></h3>
    <div class="kv"><label>单条标题测试</label>
      <input id="mt_title" placeholder="粘贴一条真实告警标题，如：【ICMP中断】41.243.21.170-华刚卢本-Airtel" onkeydown="if(event.key=='Enter')matchTest()">
      <button class="btn pri" onclick="matchTest()" style="white-space:nowrap">检测</button></div>
    <div id="mt_out" class="muted" style="margin-left:140px"></div>
    <div style="border-top:1px dashed var(--line);margin:12px 0;padding-top:12px">
      <div class="kv"><label>真实告警回放</label>
        <select id="rp_days" style="width:120px"><option value="1">近 1 天</option><option value="7" selected>近 7 天</option><option value="14">近 14 天</option><option value="30">近 30 天</option></select>
        <button class="btn ok" onclick="replayRun()">拉取 AIOps 标题并回放</button>
        <span class="muted">校验现有动作规则能覆盖哪些真实告警；未命中清单用于补关键词</span></div>
    </div>
    <div id="rp_out"></div>
  </div>
  <div class="card">
    <h3>切换动作 <button class="btn pri sm" style="float:right" onclick="editAction(0)">+ 新建动作</button></h3>
    <div class="muted" style="margin-bottom:8px">告警标题 → 动作匹配：包含模式填逗号分隔关键词（全部包含才命中，如 <code>站点A,4G</code>）；正则模式填单个正则。命令块中 <code>#</code> 开头行为注释，执行时自动跳过。</div>
    <table><thead><tr><th>ID</th><th>动作名</th><th>站点</th><th>设备</th><th>匹配方式</th><th>关键词/正则</th><th>冷却(s)</th><th>状态</th><th>操作</th></tr></thead>
    <tbody id="acttb"></tbody></table>
  </div>
</div>

<div id="p-devices" style="display:none">
  <div class="card">
    <h3>设备管理 <button class="btn pri sm" style="float:right" onclick="editDevice(0)">+ 新建设备</button></h3>
    <table><thead><tr><th>ID</th><th>设备名</th><th>站点</th><th>地址</th><th>协议</th><th>账号</th><th>超时</th><th>状态</th><th>操作</th></tr></thead>
    <tbody id="devtb"></tbody></table>
  </div>
</div>

<div id="p-sites" style="display:none">
  <div class="card">
    <h3>站点管理 <span class="muted">（线路关键词用于判定"故障线路"与"多条线路同时告警"）</span>
      <button class="btn pri sm" style="float:right" onclick="editSite(0)">+ 新建站点</button></h3>
    <table><thead><tr><th>ID</th><th>站点名称</th><th>线路</th><th>备注</th><th>操作</th></tr></thead>
    <tbody id="sitetb"></tbody></table>
  </div>
</div>

<div id="p-settings" style="display:none">
  <div class="card">
    <h3>全局设置</h3>
    <div class="kv"><label>Web 登录密码</label><input type="password" id="s_pwd" placeholder="留空不修改"></div>
    <div class="kv"><label>API Token</label><input id="s_token"><span class="muted">AIOps 回调时带 X-API-Token 请求头</span></div>
    <div class="kv"><label>全局冷却(秒)</label><input id="s_cd" type="number"></div>
    <div class="kv"><label>AIOps 告警接口</label><input id="s_aiops_url"></div>
    <div class="kv"><label>AIOps Token</label><input id="s_aiops_tok" placeholder="留空不修改（用于匹配回放/互斥判定）"></div>
    <div class="kv"><label>活跃告警判定窗口(分钟)</label><input id="s_window" type="number" placeholder="30"><span class="muted">收到告警时，查近 N 分钟内未恢复的告警判断其它线路是否也异常</span></div>
    <div class="muted" style="margin:10px 0">告警回调接口：POST /api/alert，Body: {"title":"告警标题"}，响应含 matched / task_id / skip_reason。</div>
    <button class="btn pri" onclick="saveCfg()">保存设置</button>
  </div>
  <div class="card">
    <h3>告警回调测试</h3>
    <div class="kv"><label>告警标题</label><input id="t_title" placeholder="如：站点A-4G专线中断"></div>
    <button class="btn" onclick="testAlert()">发送测试</button>
    <pre class="out" id="t_out" style="display:none;margin-top:10px"></pre>
  </div>
</div>

</div>

<!-- 登录 -->
<div class="login" id="loginBox" style="display:none">
  <div class="box">
    <h3 style="margin-bottom:12px">Axd_Line_Switch 登录</h3>
    <input type="password" id="lg_pwd" placeholder="Web 登录密码" onkeydown="if(event.key=='Enter')doLogin()">
    <button class="btn pri" style="width:100%;margin-top:12px" onclick="doLogin()">登 录</button>
    <div class="muted" id="lg_err" style="color:var(--bad);margin-top:8px"></div>
  </div>
</div>

<!-- 动作编辑 -->
<div class="modal" id="mAct"><div class="box">
  <h3 id="mActTitle">切换动作</h3>
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
  <label>切换命令块（每行一条命令，# 开头为注释）</label>
  <div class="muted" style="margin:-2px 0 6px">建议一个方向一个动作：命令块内先 <code>undo</code> 掉其它所有方向的策略，再添加本方向，形成"完整状态"——这样从任意当前状态切过来结果都确定，无需系统排序。</div>
  <textarea id="a_cmd" rows="10"></textarea>
  <label>回切命令块（可选，手动触发用）</label>
  <textarea id="a_rb" rows="6"></textarea>
  <label>验证命令块（可选，切换完成后执行并检查期望内容，如 display ip routing-table）</label>
  <textarea id="a_verify" rows="3" placeholder="display ip routing-table"></textarea>
  <div class="grid2">
    <div><label>目标线路（切换到哪条，用于日志/判定展示）</label><input id="a_target" placeholder="如 Vodacom"></div>
    <div><label>期望关键词（逗号分隔，须全部出现在验证回显中）</label><input id="a_expect" placeholder="如：192.168.130.2（切到 Vodacom 后 0.0.0.0 的下一跳）"></div>
  </div>
  <div class="grid2">
    <div><label>冷却时间(秒，0=用全局)</label><input id="a_cd" type="number" value="0"></div>
    <div class="sw" style="margin-top:22px"><input type="checkbox" id="a_en" checked><span>启用</span></div>
  </div>
  <div class="mfoot">
    <button class="btn" onclick="closeM('mAct')">取消</button>
    <button class="btn warn" onclick="execAction(false)">保存前不执行</button>
    <button class="btn pri" onclick="saveAction()">保存</button>
  </div>
</div></div>

<!-- 设备编辑 -->
<div class="modal" id="mDev"><div class="box">
  <h3 id="mDevTitle">设备</h3>
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
    <div><label>状态查询命令(查当前生效线路)</label><input id="d_scmd" value="display ip routing-table" placeholder="留空则查线路时用 display ip routing-table"></div>
    <div><label>当前线路正则(空=默认解析 0.0.0.0/0 行下一跳)</label><input id="d_cregex" placeholder="如: 0\.0\.0\.0.*?(\d+\.\d+\.\d+\.\d+)"></div>
  </div>
  <label>线路映射（每行一条：下一跳IP=线路名，# 注释）</label>
  <textarea id="d_lmap" rows="4" placeholder="192.168.130.2=Vodacom&#10;192.168.130.10=Airtel&#10;192.168.130.22=4G"></textarea>
  <div class="sw"><input type="checkbox" id="d_en" checked><span>启用</span></div>
  <div class="mfoot">
    <button class="btn" onclick="closeM('mDev')">取消</button>
    <button class="btn ok" onclick="testDevice()">测试连接</button>
    <button class="btn warn" onclick="queryDeviceLine()">查当前线路</button>
    <button class="btn pri" onclick="saveDevice()">保存</button>
  </div>
  <pre class="out" id="d_test" style="display:none;margin-top:10px"></pre>
</div></div>

<!-- 站点编辑 -->
<div class="modal" id="mSite"><div class="box" style="width:420px">
  <h3 id="mSiteTitle">站点</h3>
  <input type="hidden" id="si_id">
  <label>站点名称 *</label><input id="si_name" placeholder="如：站点A">
  <label>备注</label><input id="si_rm">
  <div class="mfoot">
    <button class="btn" onclick="closeM('mSite')">取消</button>
    <button class="btn pri" onclick="saveSite()">保存</button>
  </div>
</div></div>

<!-- 站点线路 -->
<div class="modal" id="mLine"><div class="box" style="width:760px">
  <h3 id="mLineTitle">站点线路</h3>
  <input type="hidden" id="l_site">
  <div class="muted" style="margin-bottom:8px">线路关键词用于两个判定：①识别告警说的是哪条线路；②查 AIOps 活跃告警判断"是否多条线路同时告警"。关键词为逗号分隔，全部包含即命中。</div>
  <table><thead><tr><th>线路名</th><th>告警关键词</th><th>优先级</th><th>状态</th><th>操作</th></tr></thead>
  <tbody id="ltb"></tbody></table>
  <div class="grid3" style="margin-top:14px">
    <div><label>线路名</label><input id="l_name" placeholder="如 Airtel"></div>
    <div><label>告警关键词(逗号分隔)</label><input id="l_kw" placeholder="如 41.243.21.170,Airtel"></div>
    <div><label>优先级(1最高)</label><input id="l_pri" type="number" value="1"></div>
  </div>
  <div class="mfoot">
    <button class="btn" onclick="closeM('mLine')">关闭</button>
    <button class="btn pri" onclick="addLine()">添加线路</button>
  </div>
</div></div>

<!-- 日志详情 -->
<div class="modal" id="mLog"><div class="box">
  <h3 id="mLogTitle">执行详情</h3>
  <div id="mLogBody"></div>
  <div class="mfoot"><button class="btn" onclick="closeM('mLog')">关闭</button></div>
</div></div>

<script>
let DATA={sites:[],devices:[],actions:[],logs:[]};
const $=id=>document.getElementById(id);
const esc=s=>(s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function api(m,u,b){return fetch(u,{method:m,headers:{"Content-Type":"application/json"},body:b?JSON.stringify(b):undefined}).then(r=>{
  if(r.status==401){$("loginBox").style.display="flex";throw new Error("unauthorized")}
  return r.json()})}
function closeM(id){$(id).classList.remove("show")}

// ---- 登录 ----
function doLogin(){api("POST","/api/login",{password:$("lg_pwd").value}).then(()=>{
  $("loginBox").style.display="none";$("lg_err").textContent="";boot()}).catch(()=>{$("lg_err").textContent="密码错误"})}
function logout(){api("POST","/api/logout").then(()=>location.reload())}

// ---- 页签 ----
document.querySelectorAll("#tabs button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#tabs button").forEach(x=>x.classList.remove("on"));b.classList.add("on");
  ["dash","actions","devices","sites","settings"].forEach(p=>{$("p-"+p).style.display=(p==b.dataset.p)?"":"none"});
  refresh(b.dataset.p)});
function refresh(p){
  if(p=="dash"){loadStats();loadLogs()}
  if(p=="actions")loadActions();
  if(p=="devices")loadDevices();
  if(p=="sites")loadSites();
  if(p=="settings")loadCfg()}

// ---- 仪表盘 ----
function loadStats(){api("GET","/api/stats").then(s=>{
  $("stat").innerHTML=["total|总执行","success|成功","failed|失败","running|执行中"].map(x=>{
    const [k,l]=x.split("|");return `<div class="it"><b>${s[k]}</b><span>${l}</span></div>`}).join("")})}
function loadLogs(){api("GET","/api/logs?limit=100").then(ls=>{DATA.logs=ls;
  $("logtb").innerHTML=ls.length?ls.map(l=>`<tr onclick="showLog(${l.id})" style="cursor:pointer">
    <td>${l.id}</td><td>${esc(l.started_at)}</td><td>${l.trigger=="api"?"API":"手动"}</td>
    <td>${esc(l.alarm_title)||"-"}</td><td>${esc(l.action_name)}</td><td>${esc(l.device_name)}</td>
    <td>${l.dry_run?"演练":(l.rollback?"回切":"切换")}</td>
    <td><span class="tag ${l.status}">${l.status=="cooldown_skip"?"冷却跳过":(l.status=="verify_failed"?"验证未过":(l.status=="skipped"?"条件不满足":"")||esc(l.status))}</span></td>
    <td class="muted">${esc(l.error).slice(0,40)}</td></tr>`).join(""):"<tr><td colspan=9 class=muted>暂无记录</td></tr>"})}
function showLog(id){api("GET","/api/logs/"+id).then(l=>{
  $("mLogTitle").textContent=`执行详情 #${l.id} · ${l.action_name} · ${l.status=="verify_failed"?"验证未过":(l.status=="skipped"?"条件不满足未切换":l.status)}`;
  let h=`<div class="muted" style="margin-bottom:8px">告警标题: ${esc(l.alarm_title)||"-"} | 故障线路: <b>${esc(l.source_line)||"-"}</b> | 切换前当前线路: <b>${esc(l.precheck_line)||"未查询"}</b> | 开始: ${esc(l.started_at)} | 结束: ${esc(l.finished_at)||"-"}</div>`;
  if(l.decision_note)h+=`<div class="muted" style="margin-bottom:8px">判定依据: ${esc(l.decision_note)}</div>`;
  if(l.error)h+=`<div style="color:var(--bad);margin-bottom:8px">错误: ${esc(l.error)}</div>`;
  if(l.matched_note)h+=`<details style="margin-bottom:8px"><summary class="muted">登录过程摘要</summary><pre class="out">${esc(l.matched_note)}</pre></details>`;
  if(l.session_log)h+=`<details style="margin-bottom:8px"><summary class="muted">会话原文（登录 banner + 全部收发，排障用）</summary><pre class="out">${esc(l.session_log)}</pre></details>`;
  h+=(l.steps||[]).map(s=>`<div style="margin-top:10px"><b>${s.seq}. ${esc(s.command)}</b>
     <span class="tag ${s.ok?"success":"failed"}">${s.ok?"OK":"FAIL"}</span>
     <pre class="out ${s.ok?"":"err"}">${esc(s.output)||"(无回显)"}</pre>
     ${(s.raw_output&&s.raw_output!==s.output)?`<details><summary class="muted">原始回显（含命令回显与提示符）</summary><pre class="out">${esc(s.raw_output)}</pre></details>`:""}</div>`).join("");
  $("mLogBody").innerHTML=h;$("mLog").classList.add("show")})}

// ---- 动作 ----
function loadActions(){Promise.all([api("GET","/api/actions"),api("GET","/api/sites"),api("GET","/api/devices")]).then(([a,s,d])=>{
  DATA.actions=a;DATA.sites=s;DATA.devices=d;
  $("acttb").innerHTML=a.length?a.map(x=>`<tr>
    <td>${x.id}</td><td><b>${esc(x.name)}</b></td><td>${esc(x.site_name||"-")}</td>
    <td>${esc(x.device_name||"-")}<div class=muted>${esc(x.protocol||"")}://${esc(x.host||"")}</div></td>
    <td>${x.match_type=="regex"?"正则":"包含"}</td><td class=muted>${esc(x.match_keywords)}</td>
    <td>${x.cooldown||"全局"}</td>
    <td>${x.enabled?'<span class="tag success">启用</span>':'<span class="tag failed">停用</span>'}</td>
    <td style="white-space:nowrap">
      <button class="btn sm pri" onclick="execAction(${x.id})">执行</button>
      <button class="btn sm warn" onclick="execAction(${x.id},true)">演练</button>
      <button class="btn sm" onclick="execAction(${x.id},false,true)">回切</button>
      <button class="btn sm" onclick="editAction(${x.id})">编辑</button>
      <button class="btn sm bad" onclick="delAction(${x.id})">删除</button></td></tr>`).join(""):
    "<tr><td colspan=9 class=muted>暂无动作，点击右上角新建</td></tr>"})}
function fillSelect(sel,list,valKey,labelFirst){$(sel).innerHTML=`<option value="">(不选)</option>`+
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
  if(!b.name||!b.device_id||!b.match_keywords){alert("动作名、设备、匹配关键词必填");return}
  api(b.id?"PUT":"POST",b.id?"/api/actions/"+b.id:"/api/actions",b).then(()=>{
    closeM("mAct");loadActions()})}
function delAction(id){if(confirm("确认删除动作 #"+id+"？"))api("DELETE","/api/actions/"+id).then(loadActions)}
function execAction(id,dry,rb){if(dry===false&&id===0)return;
  const q=dry?"?dry_run=1":(rb?"?rollback=1":"");
  const body=dry||rb?{}:{};
  api("POST","/api/exec/"+id+q,body).then(r=>{
    alert(r.executed?"已提交执行，任务 #"+r.task_id+"，稍后在执行记录查看":"未执行: "+r.skip_reason);
    loadLogs()}).catch(e=>alert("提交失败: "+e.message))}

// ---- 设备 ----
function loadDevices(){api("GET","/api/devices").then(d=>{DATA.devices=d;
  $("devtb").innerHTML=d.length?d.map(x=>`<tr>
    <td>${x.id}</td><td><b>${esc(x.name)}</b></td><td>${esc(x.site_name||"-")}</td>
    <td>${esc(x.host)}:${x.port}</td><td>${x.protocol}</td><td>${esc(x.username)}</td>
    <td>${x.timeout}s</td>
    <td>${x.enabled?'<span class="tag success">启用</span>':'<span class="tag failed">停用</span>'}</td>
    <td style="white-space:nowrap">
      <button class="btn sm ok" onclick="testDeviceById(${x.id})">测试</button>
      <button class="btn sm warn" onclick="testDeviceByIdStatus(${x.id})">查线路</button>
      <button class="btn sm" onclick="editDevice(${x.id})">编辑</button>
      <button class="btn sm bad" onclick="delDevice(${x.id})">删除</button></td></tr>`).join(""):
    "<tr><td colspan=9 class=muted>暂无设备</td></tr>"})}
function editDevice(id){const d=DATA.devices.find(x=>x.id==id)||{};
  api("GET","/api/sites").then(s=>{DATA.sites=s;fillSelect("d_site",s)});
  $("d_id").value=d.id||"";$("d_name").value=d.name||"";$("d_host").value=d.host||"";
  $("d_port").value=d.port||23;$("d_proto").value=d.protocol||"telnet";
  $("d_user").value=d.username||"";$("d_pwd").value="";$("d_epwd").value="";
  $("d_init").value=d.init_command!=null?d.init_command:"screen-length 0 temporary";
  $("d_prompt").value=d.prompt||"";$("d_to").value=d.timeout||10;
  $("d_scmd").value=d.status_command!=null?d.status_command:"display ip routing-table";
  $("d_cregex").value=d.current_regex||"";$("d_lmap").value=d.line_map||"";
  $("d_test").style.display="none";
  $("mDevTitle").textContent=d.id?"编辑设备 #"+d.id:"新建设备";$("mDev").classList.add("show")}
function devBody(){return{id:$("d_id").value||null,name:$("d_name").value.trim(),host:$("d_host").value.trim(),
  site_id:$("d_site").value?+$("d_site").value:null,port:+$("d_port").value||23,
  protocol:$("d_proto").value,username:$("d_user").value.trim(),
  password:$("d_pwd").value,enable_password:$("d_epwd").value,
  init_command:$("d_init").value.trim(),prompt:$("d_prompt").value.trim(),
  status_command:$("d_scmd").value.trim(),current_regex:$("d_cregex").value.trim(),
  line_map:$("d_lmap").value,
  timeout:+$("d_to").value||10,enabled:$("d_en").checked?1:0}}
function saveDevice(){const b=devBody();
  if(!b.name||!b.host){alert("设备名与地址必填");return}
  api(b.id?"PUT":"POST",b.id?"/api/devices/"+b.id:"/api/devices",b).then(()=>{
    closeM("mDev");loadDevices()})}
function delDevice(id){if(confirm("确认删除设备 #"+id+"？"))api("DELETE","/api/devices/"+id).then(loadDevices)}
function _showTest(r,el){const o=$(el);o.style.display="block";
  o.textContent=r.ok?("连接成功 ✓\n"+(r.note||[]).join("\n")+(r.banner?"\n"+r.banner:"")):("失败 ✗\n"+(r.error||""))}
function testDevice(){const b=devBody();
  if(b.id){api("POST","/api/devices/"+b.id+"/test",{}).then(r=>_showTest(r,"d_test"))}
  else{api("POST","/api/devices",b).then(r=>{b.id=r.id;$("d_id").value=r.id;
    api("POST","/api/devices/"+r.id+"/test",{}).then(t=>_showTest(t,"d_test"))})}}
function testDeviceById(id){api("POST","/api/devices/"+id+"/test",{}).then(r=>{
  alert(r.ok?"连接成功 ✓":"连接失败: "+(r.error||""))})}
function queryDeviceLine(){const id=$("d_id").value;if(!id)return alert("请先保存设备");
  api("POST","/api/devices/"+id+"/status",{}).then(r=>{
    const o=$("d_test");o.style.display="block";
    if(r.ok){o.textContent="当前生效线路: "+(r.current_line||"未识别")+"\n查询命令: "+r.command+"\n\n回显:\n"+(r.banner||"")}
    else{o.textContent="查询失败: "+(r.error||"")}})}
function testDeviceByIdStatus(id){api("POST","/api/devices/"+id+"/status",{}).then(r=>{
  alert(r.ok?("当前生效线路: "+(r.current_line||"未识别")):"查询失败: "+(r.error||""))})}

// ---- 站点 ----
function loadSites(){Promise.all([api("GET","/api/sites"),api("GET","/api/lines")]).then(([s,lines])=>{
  DATA.sites=s;DATA.lines=lines;
  $("sitetb").innerHTML=s.length?s.map(x=>{
    const ls=lines.filter(l=>l.site_id==x.id);
    return `<tr>
    <td>${x.id}</td><td><b>${esc(x.name)}</b></td>
    <td>${ls.length?ls.map(l=>`<span class="tag success" style="margin-right:4px">${esc(l.name)}</span>`).join(""):'<span class="muted">未配置</span>'}</td>
    <td class=muted>${esc(x.remark)}</td>
    <td>      <button class="btn sm" onclick="editSite(${x.id})">编辑</button>
    <button class="btn sm warn" onclick="manageLines(${x.id},'${esc(x.name)}')">线路</button>
    <button class="btn sm bad" onclick="delSite(${x.id})">删除</button></td></tr>`}).join(""):
    "<tr><td colspan=5 class=muted>暂无站点</td></tr>"})}
function editSite(id){const s=DATA.sites.find(x=>x.id==id)||{};
  $("si_id").value=s.id||"";$("si_name").value=s.name||"";$("si_rm").value=s.remark||"";
  $("mSiteTitle").textContent=s.id?"编辑站点":"新建站点";$("mSite").classList.add("show")}
function saveSite(){const b={id:$("si_id").value||null,name:$("si_name").value.trim(),remark:$("si_rm").value};
  if(!b.name){alert("站点名必填");return}
  api(b.id?"PUT":"POST",b.id?"/api/sites/"+b.id:"/api/sites",b).then(()=>{closeM("mSite");loadSites()})}
function delSite(id){if(confirm("确认删除站点 #"+id+"？"))api("DELETE","/api/sites/"+id).then(loadSites)}

// ---- 站点线路（互斥判定依据） ----
function manageLines(siteId,siteName){$("l_site").value=siteId;
  $("mLineTitle").textContent="站点线路 · "+siteName;
  $("l_name").value="";$("l_kw").value="";$("l_pri").value=1;
  loadLines(siteId);$("mLine").classList.add("show")}
function loadLines(siteId){api("GET","/api/lines?site_id="+siteId).then(ls=>{
  $("ltb").innerHTML=ls.length?ls.map(l=>`<tr>
    <td><b>${esc(l.name)}</b></td><td class="muted">${esc(l.alarm_keywords)||'(空)'}</td>
    <td>${l.priority}</td>
    <td>${l.enabled?'<span class="tag success">启用</span>':'<span class="tag failed">停用</span>'}</td>
    <td><button class="btn sm bad" onclick="delLine(${l.id})">删除</button></td></tr>`).join(""):
    "<tr><td colspan=5 class=muted>暂无线路，请添加（如 Airtel / Vodacom / 4G）</td></tr>"})}
function addLine(){const b={site_id:+$("l_site").value,name:$("l_name").value.trim(),
  alarm_keywords:$("l_kw").value.trim(),priority:+$("l_pri").value||1};
  if(!b.name)return alert("线路名必填");
  api("POST","/api/lines",b).then(()=>{$("l_name").value="";$("l_kw").value="";
    loadLines(b.site_id);loadSites()})}
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
  api("POST","/api/config",b).then(()=>alert("已保存"))}

// ---- 匹配预检 / 回放 ----
function matchTest(){const t=$("mt_title").value.trim();if(!t)return;
  api("POST","/api/match/test",{title:t}).then(r=>{
    const o=$("mt_out");
    if(!r.matched){o.innerHTML=`<span style="color:var(--bad)">✗ 未命中任何动作</span>，需补充关键词或检查标题写法`;return}
    o.innerHTML=r.hits.map(h=>`<div>✓ 命中 <b>${esc(h.action_name)}</b>（站点 ${esc(h.site||"-")} / 设备 ${esc(h.device?h.device.name:"-")}）
      <span class="muted">${esc(h.reason)}；将执行 ${h.command_lines} 条命令</span></div>`).join("")})}
function replayRun(){const d=+$("rp_days").value;
  $("rp_out").innerHTML='<div class="muted">正在拉取 AIOps 告警并回放，请稍候…</div>';
  api("POST","/api/match/replay",{days:d}).then(r=>{
    if(r.error){$("rp_out").innerHTML=`<div style="color:var(--bad)">${esc(r.error)}</div>`;return}
    let h=`<div class="stat" style="margin:12px 0">
      <div class="it"><b>${r.fetched}</b><span>回放标题数(去重前)</span></div>
      <div class="it"><b style="color:var(--ok)">${r.matched}</b><span>命中动作</span></div>
      <div class="it"><b style="color:var(--warn)">${r.unmatched}</b><span>未命中</span></div>
      <div class="it"><b>${r.unmatched_kinds}</b><span>未命中标题种类</span></div></div>`;
    if(r.per_action.length)
      h+=`<table><thead><tr><th>动作</th><th>命中条数</th></tr></thead><tbody>`+
         r.per_action.map(x=>`<tr><td>${esc(x[0])}</td><td>${x[1]}</td></tr>`).join("")+`</tbody></table>`;
    if(r.unmatched_titles.length)
      h+=`<h3 style="margin-top:16px">未命中标题（按次数排序，判断是否属于"不需要切换"的告警）</h3>
          <table><thead><tr><th>次数</th><th>告警标题</th></tr></thead><tbody>`+
          r.unmatched_titles.map(x=>`<tr><td>${x.count}</td><td>${esc(x.title)}</td></tr>`).join("")+`</tbody></table>`;
    $("rp_out").innerHTML=h})}
function testAlert(){const t=$("t_title").value.trim();if(!t)return alert("请输入标题");
  api("POST","/api/alert",{title:t}).then(r=>{const o=$("t_out");o.style.display="block";
    o.textContent=JSON.stringify(r,null,2);loadLogs()})}

// ---- 启动 ----
function boot(){refresh("dash");setInterval(()=>{loadStats();loadLogs()},30000)}
api("GET","/api/session").then(()=>{boot()}).catch(()=>{$("loginBox").style.display="flex"});
</script>
</body>
</html>
"""


def main():
    init_db()
    threading.Thread(target=_worker, daemon=True).start()
    server = ThreadingHTTPServer((LS_BIND, LS_PORT), Handler)
    print("[%s] Axd_Line_Switch 启动: http://%s:%d  db=%s" % (now(), LS_BIND, LS_PORT, LS_DB))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
