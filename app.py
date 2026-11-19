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
        ("actions", "targets_json", "TEXT DEFAULT ''"),
        ("exec_logs", "target_line", "TEXT DEFAULT ''"),
        ("exec_logs", "target_override", "TEXT DEFAULT ''"),
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
                 ("aiops_token", AIOPS_TOKEN)]:
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
    """返回 (命中的动作列表)。contains: 逗号分隔关键词全部包含(不区分大小写)；regex: re.search。
    正则语法错误的规则不算命中（见 match_detail 的 error 标记）。"""
    return [m["action"] for m in match_detail(conn, title) if not m.get("error")]


def match_detail(conn, title):
    """返回命中明细 [{'action': Row, 'reason': '...', 'error': bool}]。
    error=True 表示规则本身配置有误（正则语法错误），不参与触发，仅供预检页展示。"""
    t = (title or "").strip()
    if not t:
        return []
    hits = []
    for a in conn.execute("SELECT * FROM actions WHERE enabled=1 ORDER BY id"):
        kw = (a["match_keywords"] or "").strip()
        if not kw:
            continue
        if a["match_type"] == "regex":
            try:
                if re.search(kw, t, re.IGNORECASE):
                    hits.append({"action": a, "reason": "正则匹配: %s" % kw})
            except re.error as e:
                hits.append({"action": a, "reason": "正则语法错误: %s（该规则不会触发任何切换，请修正）" % e,
                             "error": True})
        else:
            words = [w.strip() for w in kw.split(",") if w.strip()]
            if words and all(w.lower() in t.lower() for w in words):
                hits.append({"action": a, "reason": "关键词全部命中: %s" % ",".join(words)})
    return hits


def query_line_active(conn, gs_kw):
    """以线路告警关键字作为 gs 直接查询该线路是否存在 未处理(status=0)/处理中(status=1)
    且未忽略(is_ignore=0) 的告警；不附加时间过滤（状态即代表当前活跃）。
    返回 {"pending": n1, "handling": n2, "titles": [样例标题...], "requests": [url...],
          "raw": 首页原始响应}；查询失败抛异常。"""
    import urllib.parse
    import urllib.request
    token = (kv_get(conn, "aiops_token", "") or "").strip()
    api = (kv_get(conn, "aiops_url", "") or "").strip() or AIOPS_API
    if not token:
        raise RuntimeError("未配置 AIOps Token")
    result = {"pending": 0, "handling": 0, "titles": [], "requests": [], "raw": "",
              "display": [], "raws": [], "gs_label": gs_kw}
    for status_key, status in (("pending", 0), ("handling", 1)):
        sul = json.dumps([{"attr": "is_ignore", "search": [0], "operator": "="},
                          {"attr": "status", "search": [status], "operator": "="}],
                         ensure_ascii=False)
        params = {"gs": gs_kw, "offset": 0, "limit": 5, "search_unit_list": sul}
        full_url = api + "?" + urllib.parse.urlencode(params)
        result["requests"].append(full_url)
        # 展示用：gs/JSON 保持中文原文（不 URL 编码），参数顺序与紧凑格式便于人核对
        sul_c = json.dumps([{"attr": "is_ignore", "search": [0], "operator": "="},
                           {"attr": "status", "search": [status], "operator": "="}],
                          ensure_ascii=False, separators=(",", ":"))
        result["display"].append("%s?offset=0&limit=5&gs=%s&search_unit_list=%s"
                                 % (api.split("?")[0], gs_kw, sul_c))
        req = urllib.request.Request(full_url, headers={"token": token})
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode("utf-8")
        d = json.loads(raw)
        if d.get("code") != 0:
            raise RuntimeError("AIOps 接口返回错误: %s" % str(d)[:160])
        data = d.get("data") or {}
        result[status_key] = data.get("count") or 0
        result["raws"].append(raw[:600])
        if not result["raw"]:
            result["raw"] = raw[:3000]
        for it in (data.get("list") or [])[:3]:
            t = it.get("alarm_title") or ""
            if t and t not in result["titles"]:
                result["titles"].append(t)
    return result


def _kw_match(keywords, text):
    """线路告警关键词匹配：逗号分隔，全部包含(不区分大小写)视为命中。"""
    words = [w.strip() for w in (keywords or "").split(",") if w.strip()]
    if not words:
        return False
    t = (text or "").lower()
    return all(w.lower() in t for w in words)


def site_lines(conn, site_id):
    """站点启用中的线路（priority 字段已废弃，降级顺序以规则阶梯为准），按创建顺序返回。"""
    if not site_id:
        return []
    return conn.execute("SELECT * FROM lines WHERE site_id=? AND enabled=1 ORDER BY id",
                        (site_id,)).fetchall()


def parse_targets(act):
    """规则的降级阶梯：targets_json → [{line,command_block,verify_block,expect_keywords,nexthop}]。
    旧规则（无阶梯）→ 由 target_line/command_block 等合成单目标阶梯。"""
    raw = (act["targets_json"] or "").strip() if "targets_json" in act.keys() else ""
    ts = []
    if raw:
        try:
            arr = json.loads(raw)
            if isinstance(arr, list):
                for x in arr:
                    nm = (x.get("line") or "").strip()
                    if nm:
                        ts.append({"line": nm, "command_block": x.get("command_block") or "",
                                   "verify_block": x.get("verify_block") or "",
                                   "expect_keywords": x.get("expect_keywords") or "",
                                   "nexthop": x.get("nexthop") or ""})
        except Exception:
            ts = []
    if ts:
        return ts
    if (act["target_line"] or "").strip():
        return [{"line": act["target_line"].strip(), "command_block": act["command_block"] or "",
                 "verify_block": act["verify_block"] or "",
                 "expect_keywords": act["expect_keywords"] or "", "nexthop": ""}]
    return []


def resolve_fault_sites(conn, title):
    """按各站点线路的告警关键字匹配标题，返回 ({site_id: [故障线路名...]}, {site_id: 站点名})。"""
    rows = conn.execute("SELECT l.*, s.name AS site_name FROM lines l "
                        "LEFT JOIN sites s ON l.site_id=s.id WHERE l.enabled=1 "
                        "ORDER BY l.site_id, l.id").fetchall()
    faults, site_names = {}, {}
    for ln in rows:
        site_names[ln["site_id"]] = ln["site_name"]
        if _kw_match(ln["alarm_keywords"], title):
            faults.setdefault(ln["site_id"], []).append(ln["name"])
    return faults, site_names


def matched_actions(conn, title):
    """启用中、关键词命中标题的动作（含阶梯目标信息）。"""
    out = []
    for h in match_detail(conn, title):
        if h.get("error"):
            continue
        a = h["action"]
        out.append({"action": a, "targets": parse_targets(a), "reason": h["reason"]})
    return out


_STEP_STATUS_TXT = {
    "fault": "故障线路，排除", "active": "有活跃告警，不可选", "clear": "无活跃告警，可选",
    "no_cmd": "健康但未配置本方向的切换命令", "no_keyword": "未配置告警关键字，无法查询",
    "query_error": "查询失败，按不可用跳过", "legacy": "兼容路径：站点未配线路，走动作匹配"}


def plan_switch(conn, title, site_id=None):
    """多线路降级决策（规则内阶梯模型）。
    1) 故障线路 = 告警标题匹配站点线路关键字；
    2) 候选规则 = 该站点启用动作（按各自 match_keywords 命中标题的优先），
       每条规则的 targets 即降级阶梯：按顺序用各目标线路的告警关键字 gs 直查
       AIOps 未处理/处理中（不按时间过滤），第一条健康且配置了本方向命令的目标即选中；
    3) 全部规则的所有目标均不健康/缺命令 → 不切换；
    4) 站点未配线路 → 回退按动作关键词直接执行（兼容旧配置）。
    返回 dict：matched/allow/reason/note/site_id/site_name/fault_lines/target_line/
              action/target（选中目标配置）/steps/trace/legacy。"""
    out = {"matched": False, "allow": False, "reason": "", "note": "", "site_id": site_id,
           "site_name": "", "fault_lines": [], "target_line": "", "action": None,
           "target": None, "steps": [], "trace": {}, "legacy": False}
    t = (title or "").strip()
    if not t:
        out["reason"] = "缺少告警标题"
        return out
    if site_id:
        site_row = conn.execute("SELECT name FROM sites WHERE id=?", (site_id,)).fetchone()
        lines = site_lines(conn, site_id)
        fl = [ln["name"] for ln in lines if _kw_match(ln["alarm_keywords"], t)]
        faults = {site_id: fl} if fl else {}
        site_names = {site_id: site_row["name"] if site_row else ""}
    else:
        faults, site_names = resolve_fault_sites(conn, t)

    out["site_names"] = site_names
    if len(faults) > 1:
        out["matched"] = True
        out["reason"] = ("告警标题同时命中多个站点的线路（%s），无法确定切换站点"
                         % "、".join("%s:%s" % (site_names.get(k, k), "/".join(v))
                                     for k, v in faults.items()))
        return out

    if not faults:
        md = matched_actions(conn, t)
        if not md:
            return out
        m0 = md[0]
        act = m0["action"]
        srow = conn.execute("SELECT name FROM sites WHERE id=?", (act["site_id"] or 0,)).fetchone()
        out.update({"matched": True, "site_id": act["site_id"], "site_name": srow["name"] if srow else ""})
        if site_lines(conn, act["site_id"]):
            out["reason"] = ("站点「%s」已配置线路，但告警标题未匹配到任何线路的告警关键字，"
                             "请检查站点线路配置" % (srow["name"] if srow else act["site_id"]))
            out["note"] = "线路关键字未命中标题"
            return out
        tg = m0["targets"][0] if m0["targets"] else None
        out.update({"legacy": True, "allow": True, "action": act, "target": tg,
                    "target_line": (tg or {}).get("line", ""),
                    "note": "站点未配置线路，按动作匹配直接执行（不做多线路降级判定）"})
        out["steps"] = [{"line": out["target_line"] or "(动作默认)", "status": "legacy"}]
        return out

    sid = list(faults.keys())[0]
    fl = faults[sid]
    lines = {ln["name"]: ln for ln in site_lines(conn, sid)}
    srow = conn.execute("SELECT name FROM sites WHERE id=?", (sid,)).fetchone()
    out.update({"matched": True, "site_id": sid, "site_name": srow["name"] if srow else "",
                "fault_lines": fl})
    # 候选规则：优先取关键词命中标题的动作（语法错误规则除外），其次取站点内其它启用动作
    hits = {h["action"]["id"] for h in match_detail(conn, t) if not h.get("error")}
    acts = conn.execute("SELECT * FROM actions WHERE site_id=? AND enabled=1 ORDER BY id",
                        (sid,)).fetchall()
    cands = [a for a in acts if a["id"] in hits] + [a for a in acts if a["id"] not in hits]
    line_cache = {}

    def check_line(name):
        """线路健康状态查询（同一次判定内缓存）。返回 step dict。"""
        ln = lines.get(name)
        st = {"line": name, "nexthop": ln["nexthop_ip"] if ln else ""}
        if name in fl:
            st["status"] = "fault"
            return st
        kw = (ln["alarm_keywords"] or "").strip() if ln else ""
        if not kw:
            st["status"] = "no_keyword"
            return st
        if name in line_cache:
            return line_cache[name]
        try:
            q = query_line_active(conn, kw)
        except Exception as e:
            st.update({"status": "query_error", "gs": kw, "error": str(e)})
            return st
        n = q["pending"] + q["handling"]
        st.update({"status": "active" if n else "clear", "gs": kw,
                   "pending": q["pending"], "handling": q["handling"],
                   "raw": q.get("raw") or "",
                   "titles": q["titles"], "requests": q.get("requests") or [],
                   "display": q.get("display") or [], "raws": q.get("raws") or []})
        line_cache[name] = st
        return st

    # trace 从本次判定的 steps 局部聚合（无线程间共享状态）
    def _mk_trace():
        reqs, disp, raws, raw = [], [], [], ""
        for s in out["steps"]:
            reqs.extend(s.get("requests") or [])
            disp.extend(s.get("display") or [])
            raws.extend(s.get("raws") or [])
            if not raw and s.get("raw"):
                raw = s["raw"]
        return {"requests": reqs, "raw": raw, "display": disp, "raws": raws}

    for a in cands:
        tgs = parse_targets(a)
        if not tgs:
            continue
        for rank, tg in enumerate(tgs, 1):
            st = check_line(tg["line"])
            st["action"] = a["name"]
            st["rank"] = rank
            out["steps"].append(dict(st))
            if st["status"] != "clear":
                continue
            if not (tg["command_block"] or "").strip():
                out["steps"][-1]["status"] = "no_cmd"
                continue
            out["trace"] = _mk_trace()
            out.update({"allow": True, "action": a, "target": tg,
                        "target_line": tg["line"], "target_rank": rank,
                        "note": ("规则「%s」选中阶梯第 1 目标线路 %s（首选切换）"
                                 % (a["name"], tg["line"])) if rank == 1 else
                                ("规则「%s」阶梯降级选中第 %d 目标线路 %s"
                                 % (a["name"], rank, tg["line"]))})
            return out

    out["trace"] = _mk_trace()
    bad = [s for s in out["steps"] if s["status"] != "fault"]
    out["reason"] = ("站点「%s」无可切换的目标线路：%s"
                     % (out["site_name"] or sid,
                        "；".join("%s %s（规则:%s）" % (s["line"], _STEP_STATUS_TXT.get(s["status"], s["status"]), s.get("action", "-"))
                                  for s in bad) or "站点下没有配置目标线路的规则"))
    out["note"] = "降级遍历结束：所有候选目标均在告警或缺少本方向命令，本次不切换"
    return out


def _fmt_req_human(url):
    """把实际请求 URL 转成人能看懂的一行：接口 + gs关键字 + 过滤条件（解码）。"""
    import urllib.parse
    try:
        pr = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(pr.query)
        gs = (qs.get("gs") or [""])[0]
        sul = (qs.get("search_unit_list") or [""])[0]
        conds = []
        try:
            for u in json.loads(sul):
                attr, op, sv = u.get("attr"), u.get("operator"), u.get("search") or []
                if attr == "status":
                    lab = {0: "未处理", 1: "处理中"}.get(sv[0] if sv else None, sv)
                    conds.append("状态=%s" % lab)
                elif attr == "is_ignore":
                    conds.append("未忽略" if (sv and sv[0] == 0) else "已忽略")
                else:
                    conds.append("%s%s%s" % (attr, op, ",".join(map(str, sv))))
        except Exception:
            conds.append(sul or "")
        return "%s%s ｜ 关键字「%s」 ｜ 过滤：%s" % (pr.netloc, pr.path, gs, "、".join(conds))
    except Exception:
        return url


def _display_from_url(url):
    """把实际请求的编码 URL 还原为可读展示格式（gs/JSON 中文原文）。"""
    import urllib.parse
    try:
        pr = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(pr.query)
        gs = (qs.get("gs") or [""])[0]
        sul = (qs.get("search_unit_list") or [""])[0]
        try:
            sul_c = json.dumps(json.loads(sul), ensure_ascii=False, separators=(",", ":"))
        except Exception:
            sul_c = sul
        return "%s://%s%s?offset=%s&limit=%s&gs=%s&search_unit_list=%s" % (
            pr.scheme, pr.netloc, pr.path, (qs.get("offset") or ["0"])[0],
            (qs.get("limit") or ["5"])[0], gs, sul_c)
    except Exception:
        return url


_STATUS_REV = {v: k for k, v in _STEP_STATUS_TXT.items() if k != "legacy"}


def parse_ev_to_evd(ev_text):
    """旧记录：从 line_steps_evidence 纯文本反解析出 {steps, trace} 结构，
    供按最新证据样式重新渲染（历史记录不再锁死旧格式）。"""
    steps, raws, cur = [], [], None
    cur_raw = None
    for ln in (ev_text or "").splitlines():
        if cur_raw is not None:
            if re.match(r"^(?:目标|线路) ", ln):
                raws.append("\n".join(cur_raw).strip()[:600])
                cur_raw = None
            else:
                cur_raw.append(ln)
                continue
        if ln.startswith("AIOps 原始响应"):
            cur_raw = []
            continue
        mreq = re.match(r"^\s+实际请求: (\S+)", ln)
        if mreq and cur is not None:
            u = mreq.group(1)
            cur.setdefault("requests", []).append(u)
            cur.setdefault("display", []).append(_display_from_url(u))
            continue
        if " → " not in ln or not re.match(r"^(?:目标|线路) ", ln):
            continue
        head, concl = ln.rsplit(" → ", 1)
        m = re.match(r"^(?:目标|线路) (.+?)（", head)
        if not m:
            continue
        st = {"line": m.group(1), "status": _STATUS_REV.get(concl.strip(), "info")}
        am = re.search(r"规则:(.+?)）", head)
        if am:
            st["action"] = am.group(1)
        gm = re.search(r"gs=(.+?)，未处理", head)
        if gm:
            st["gs"] = gm.group(1)
        pm = re.search(r"未处理 (\d+|None)，处理中 (\d+|None)", head)
        if pm:
            def _n(x):
                return None if x in ("None", "-") else int(x)
            st["pending"], st["handling"] = _n(pm.group(1)), _n(pm.group(2))
        if "；样例: " in head:
            st["titles"] = head.split("；样例: ", 1)[1].split(" | ")
        cur = st
        steps.append(st)
    if cur_raw:
        raws.append("\n".join(cur_raw).strip()[:600])
    disp = [u for st in steps for u in st.get("display") or []]
    reqs = [u for st in steps for u in st.get("requests") or []]
    return {"steps": steps, "trace": {"display": disp, "raws": [r for r in raws if r],
                                       "requests": reqs}}


def line_steps_evidence_html(plan):
    """降级体检证据 → 结构化 HTML：表格（目标线路/所属规则/告警关键字/未处理/处理中/结论）
    + 每条查询的可读请求。值均 esc 转义，仅本函数生成的结构为标签。"""
    import html as _html
    e = _html.escape
    rows = []
    seen_req = set()
    for s in plan.get("steps") or []:
        st = s.get("status")
        concl = _STEP_STATUS_TXT.get(st, str(st))
        color = {"clear": "#047857", "fault": "#64748b", "active": "#b91c1c",
                 "no_cmd": "#b91c1c", "query_error": "#b45309",
                 "no_keyword": "#b45309"}.get(st, "#334155")
        pending = s.get("pending")
        handling = s.get("handling")
        cnt = "-" if pending is None else "%s / %s" % (pending, handling)
        titles = "、".join(s.get("titles") or [])
        kw = e(str(s.get("gs") or "-"))
        if titles:
            kw += '<div style="color:#94a3b8;font-size:11px;margin-top:2px">样例: %s</div>' % e(titles)
        err = ('<div style="color:#b45309;font-size:11px">%s</div>' % e(str(s.get("error")))) if s.get("error") else ""
        rows.append("<tr><td><b>%s</b></td><td><span class='rule-chip'>%s</span></td><td>%s%s</td><td style='text-align:center'>%s</td>"
                    "<td style='color:%s;font-weight:600'>%s</td></tr>"
                    % (e(str(s.get("line") or "-")), e(str(s.get("action") or "-")),
                       kw, err, cnt, color, e(concl)))
        for u in s.get("requests") or []:
            if u in seen_req:
                continue
            seen_req.add(u)
    head = ('<tr>'
            '<th style="width:12%%">目标线路</th>'
            '<th style="width:22%%">所属规则</th>'
            '<th style="width:36%%">告警关键字 / 样例</th>'
            '<th style="width:12%%;text-align:center">未处理 / 处理中</th>'
            '<th style="width:18%%">结论</th></tr>')
    out = []
    if rows:
        out.append('<table class="ev-table">%s%s</table>' % (head, "".join(rows)))
    disp = plan.get("trace", {}).get("display") or []
    if disp:
        req_blocks = "".join('<pre style="margin:6px 0 0;background:#0f172a;color:#e2e8f0;font-size:11px;padding:10px 12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-all;line-height:1.6"><span style="color:#38bdf8">GET</span> %s</pre>' % e(u) for u in disp)
        out.append('<div style="margin-top:14px;font-size:12px;font-weight:600;color:var(--text-muted)">实际发出的查询请求（%d 条）</div>%s'
                   % (len(disp), req_blocks))
    raws = plan.get("trace", {}).get("raws") or []
    if raws:
        blocks = "".join('<div style="margin-top:6px;font-size:11px;color:#94a3b8">响应 %d：</div>'
                         '<pre style="margin:2px 0 0;background:#0f172a;color:#e2e8f0;font-size:11px;padding:10px 12px;border-radius:6px;max-height:110px;overflow:auto;white-space:pre-wrap;word-break:break-all">%s</pre>'
                         % (i + 1, e(r)) for i, r in enumerate(raws))
        out.append('<div style="margin-top:14px;font-size:12px;font-weight:600;color:var(--text-muted)">AIOps 原始响应（每条截取前 600 字）</div>%s' % blocks)
    return "".join(out)


def line_steps_evidence(plan):
    """把降级体检过程拼成可核对的证据文本（含真实请求 URL 与原始响应）。"""
    ev = ["判定逻辑：故障线路 = 告警标题匹配站点线路的告警关键字；随后按各切换规则内配置的"
          "目标线路阶梯（顺序=优先级）逐条体检：用目标线路的告警关键字作为 gs 查询 AIOps"
          "（is_ignore=0，status 未处理0/处理中1，不按时间过滤），第一条无活跃告警且已配置"
          "本方向切换命令的目标线路即选中。"]
    for s in plan.get("steps") or []:
        st = s.get("status")
        head = "目标 %s" % s.get("line")
        if s.get("action"):
            head += "（规则:%s）" % s["action"]
        if st in ("active", "clear", "no_cmd"):
            head += "：gs=%s，未处理 %s，处理中 %s" % (s.get("gs"), s.get("pending"), s.get("handling"))
            if s.get("titles"):
                head += "；样例: " + " | ".join(s["titles"])
        if s.get("error"):
            head += "（%s）" % s["error"]
        ev.append(head + " → " + _STEP_STATUS_TXT.get(st, str(st)))
        for u in s.get("requests") or []:
            ev.append("  实际请求: " + u)
    tr = plan.get("trace") or {}
    if tr.get("raw"):
        ev.append("AIOps 原始响应(首次查询, 截3000字)：")
        ev.append(tr["raw"][:3000])
    return "\n".join(ev)


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
            self.transcript.append(("--", "### 登录阶段"))
            self.transcript.append(("RX", self.login_raw))

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
           + " ORDER BY site_id, id")
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
                 target_line=""):
    """登录设备：查当前线路 →（条件满足才）下发切换命令 → 执行验证命令。
    返回 (ok, error, 登录过程文本, 切换前当前线路, 验证是否通过, 跳过原因)。
    target_line 非空时：当前生效线路已是该目标线路则不下发命令（无需切换）。"""
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
            sess.transcript.append(("--", "### 查询当前线路"))
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
        # 条件判断：当前生效线路已是目标线路 → 无需切换
        if target_line and precheck_line:
            if precheck_line.strip() == target_line.strip():
                tl_append(conn, log_id, "当前线路 %s 已是目标线路，跳过"
                          % (precheck_disp or precheck_line), "warn")
                return (True, "", login_note + "\n[跳过] 当前生效线路已是目标线路 %s，无需切换"
                        % (precheck_disp or precheck_line), precheck_line, True,
                        "当前生效线路已是目标线路 %s，无需切换" % (precheck_disp or precheck_line))
            tl_append(conn, log_id, "满足切换条件（当前 %s → 目标 %s），下发切换命令（%d 条）"
                      % (precheck_disp or precheck_line, target_line, len(cmds)), "ok")
        else:
            tl_append(conn, log_id, "下发切换命令（%d 条）" % len(cmds), "ok")
        main_outs = []
        sess.transcript.append(("--", "### 下发切换命令"))
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
                        verr = ("验证未通过：路由表未包含期望下一跳 %s（切换前线路: %s）"
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
                    sess.transcript.append(("--", "### 验证会话（重新登录设备）"))
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
        # 命令块：非回切时优先取规则阶梯中"本次选中目标线路"的配置
        tgt_name = (log["target_line"] or "").strip() if not log["rollback"] else ""
        tg = None
        for x in parse_targets(act):
            if x["line"] == tgt_name:
                tg = x
                break
        if log["rollback"]:
            block = act["rollback_block"]
            verify_cmds = []
            expect_kws = []
        elif tg:
            block = tg["command_block"]
            verify_cmds = parse_block(tg["verify_block"])
            expect_kws = [k.strip() for k in (tg["expect_keywords"] or "").split(",") if k.strip()]
        else:
            block = act["command_block"]
            verify_cmds = parse_block(act["verify_block"])
            expect_kws = [k.strip() for k in (act["expect_keywords"] or "").split(",") if k.strip()]
        if tg and not expect_kws and (tg.get("nexthop") or "").strip():
            expect_kws = [tg["nexthop"].strip()]
        cmds = parse_block(block)
        if not cmds and not log["dry_run"]:
            tl_append(conn, log_id, "命令块为空，任务终止", "bad")
            conn.execute("UPDATE exec_logs SET status='failed', error='命令块为空', finished_at=? WHERE id=?",
                         (now(), log_id))
            conn.commit()
            return
        # 目标线路：回切（已隐藏）不做"是否已在目标线路"的跳过判断
        tgt = "" if log["rollback"] else ((log["target_line"] if "target_line" in log.keys() else "")
                                          or act["target_line"] or "")
        try:
            ok, err, note, precheck_line, verify_ok, skip_reason = _with_dev_lock(
                dev["id"], 180, lambda: _run_session(
                    dev, conn, log_id, cmds, log["dry_run"], verify_cmds, expect_kws,
                    target_line=tgt))
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


def exec_result_of(conn, log_id):
    """读取执行记录的结果摘要（供 /api/alert 同步返回）。"""
    row = conn.execute("SELECT status,precheck_line,target_line,error,started_at,finished_at "
                       "FROM exec_logs WHERE id=?", (log_id,)).fetchone()
    if not row:
        return None
    st = row["status"]
    tgt = row["target_line"] or ""
    before = row["precheck_line"] or ""
    after = tgt if st == "success" else (before if st == "skipped" else "")
    return {"status": st, "before_line": before, "after_line": after,
            "target_line": tgt, "reason": row["error"] or "",
            "started_at": row["started_at"], "finished_at": row["finished_at"],
            "timeout": st == "running"}


def wait_exec_result(conn, log_id, timeout):
    """轮询任务直至离开 running 状态或超时。返回结果 dict（timeout 标记是否超时）。"""
    deadline = time.time() + max(0, int(timeout))
    res = None
    while True:
        res = exec_result_of(conn, log_id)
        if res and res["status"] != "running" or time.time() >= deadline:
            return res
        time.sleep(0.5)


def submit_action(conn, action, trigger, title, dry_run=0, rollback=0,
                  source_line="", decision_note="", init_tl=None, target_line=""):
    """创建执行记录并入队。返回 (log_id, skip_reason)。冷却/串行判断在此。
    init_tl: 告警接入阶段已产生的时间线条目列表；target_line: 本次切换的目标线路
    （为空时取规则阶梯的第一目标——手动触发/旧配置语义）。"""
    target_line = (target_line or "").strip()
    if not target_line:
        tgs = parse_targets(action)
        if tgs:
            target_line = tgs[0]["line"]
    dev = conn.execute("SELECT * FROM devices WHERE id=?", (action["device_id"],)).fetchone()
    if not dev:
        return None, "设备不存在"
    if not dev["enabled"]:
        return None, "设备已停用"
    # 冷却判断（演练 dry_run 不受冷却限制）
    # 粒度 = 设备 + 目标线路方向：同方向冷却防抖，不同方向的阶梯降级互不封锁（B2）
    g_cooldown = int(kv_get(conn, "global_cooldown", "300") or 0)
    cooldown = action["cooldown"] or g_cooldown
    if cooldown > 0 and not dry_run:
        row = conn.execute(
            "SELECT started_at FROM exec_logs WHERE device_id=? AND target_line=? "
            "AND status IN ('running','success') ORDER BY id DESC LIMIT 1",
            (dev["id"], target_line or "")).fetchone()
        if row and row["started_at"]:
            try:
                t0 = datetime.strptime(row["started_at"], "%Y-%m-%d %H:%M:%S")
                if (datetime.now() - t0).total_seconds() < cooldown:
                    return None, "该方向冷却期内（%ds）：%s" % (cooldown, target_line or "(默认)")
            except Exception:
                pass
    tl = list(init_tl or [])
    mode = "演练" if dry_run else "切换"
    tl.append({"ts": now(), "kind": "info",
               "text": "任务入队（模式：%s，设备：%s）" % (mode, dev["name"])})
    cur = conn.execute(
        "INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,alarm_title,"
        "dry_run,rollback,status,precheck_line,source_line,decision_note,target_line,started_at,timeline) "
        "VALUES(?,?,?,?,?,?,?,?, 'running', '', ?,?,?,?,?)",
        (action["id"], action["name"], dev["id"], dev["name"], trigger, title or "",
         dry_run, rollback, source_line, decision_note, target_line or "", now(),
         json.dumps(tl, ensure_ascii=False)))
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
                        "aiops_url", "aiops_token"]
                cfg = {k: kv_get(conn, k) for k in keys}
                cfg["web_password"] = mask_pw(cfg["web_password"])
                cfg["aiops_token"] = mask_pw(cfg["aiops_token"])
                _t = cfg["api_token"] or ""
                cfg["api_token_masked"] = (_t[:7] + "****" + _t[-4:]) if len(_t) > 12 else ("******" if _t else "")
                cfg["api_token"] = ""
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
                    rows = conn.execute("SELECT * FROM lines WHERE site_id=? ORDER BY id",
                                        (int(sid),)).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT l.*, s.name AS site_name FROM lines l LEFT JOIN sites s ON l.site_id=s.id "
                        "ORDER BY l.site_id, l.id").fetchall()
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
                sql = ("SELECT e.*, COALESCE(si.name,'') AS site_name FROM exec_logs e "
                       "LEFT JOIN actions a ON e.action_id=a.id "
                       "LEFT JOIN sites si ON a.site_id=si.id ")
                aid = (qs.get("action_id") or [None])[0]
                if aid:
                    rows = conn.execute(sql + "WHERE e.action_id=? ORDER BY e.id DESC LIMIT ?",
                                        (int(aid), limit)).fetchall()
                else:
                    rows = conn.execute(sql + "ORDER BY e.id DESC LIMIT ?", (limit,)).fetchall()
                return self._send_json([dict(r) for r in rows])
            m = re.match(r"^/api/logs/(\d+)$", path)
            if m:
                log = conn.execute("SELECT e.*, COALESCE(si.name,'') AS site_name FROM exec_logs e "
                                   "LEFT JOIN actions a ON e.action_id=a.id "
                                   "LEFT JOIN sites si ON a.site_id=si.id WHERE e.id=?",
                                   (int(m.group(1)),)).fetchone()
                if not log:
                    return self._send_json({"error": "not found"}, 404)
                steps = conn.execute("SELECT * FROM exec_steps WHERE log_id=? ORDER BY seq", (log["id"],)).fetchall()
                d = dict(log)
                d["steps"] = [dict(s) for s in steps]
                # 旧记录证据重渲染：从 ev 纯文本反解析，按最新证据样式生成 evh
                try:
                    tl = json.loads(d.get("timeline") or "[]")
                    changed = False
                    for it in tl:
                        if it.get("ev") and not it.get("evh"):
                            evd = parse_ev_to_evd(it["ev"])
                            if evd["steps"]:
                                it["evh"] = line_steps_evidence_html(evd)
                                changed = True
                    if changed:
                        d["timeline"] = json.dumps(tl, ensure_ascii=False)
                except Exception:
                    pass
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
                dry_run = 1 if str(body.get("dry_run", "")).lower() in ("1", "true", "yes") else 0
                plan = plan_switch(conn, title)
                init_tl = [{"ts": now(), "kind": "info", "text": "收到告警：%s" % title}]
                if not plan["matched"]:
                    return self._send_json({"matched": False, "title": title,
                                            "note": plan.get("reason") or "未命中任何站点线路/动作"})
                act = plan["action"]
                base = {"matched": True, "title": title,
                        "action": ({"id": act["id"], "name": act["name"], "site_id": act["site_id"]}
                                   if act else None),
                        "device": None,
                        "decision": {"allow": plan["allow"], "reason": plan["reason"],
                                     "note": plan["note"], "site": plan.get("site_name"),
                                     "fault_lines": plan.get("fault_lines"),
                                     "target_line": plan.get("target_line"),
                                     "steps": [{k: s.get(k) for k in ("line", "status",
                                                                      "pending", "handling", "action", "rank")}
                                               for s in plan.get("steps") or []]}}
                # 逐条线路降级体检证据（真实 gs 请求 + 原始响应）
                if plan.get("fault_lines"):
                    init_tl.append({"ts": now(), "kind": "info",
                                    "text": "命中站点「%s」；故障线路：%s"
                                            % (plan.get("site_name") or "-",
                                               "、".join(plan["fault_lines"])),
                                    "ev": line_steps_evidence(plan),
                                    "evh": line_steps_evidence_html(plan)})
                if plan.get("target_line"):
                    _rk = plan.get("target_rank") or 1
                    init_tl.append({"ts": now(), "kind": "ok",
                                    "text": ("%s选中目标线路：%s（规则：%s，阶梯第 %d 位）"
                                             % ("降级" if _rk > 1 else "判定",
                                                plan["target_line"],
                                                act["name"] if act else "-", _rk))})
                if not plan["allow"]:
                    reason = plan["reason"] or "判定不切换"
                    init_tl.append({"ts": now(), "kind": "bad", "text": "判定不切换：%s" % reason})
                    _did = act["device_id"] if act else None
                    dev = conn.execute("SELECT name FROM devices WHERE id=?", (_did,)).fetchone() if _did else None
                    base["device"] = dict(dev) if dev else None
                    conn.execute(
                        "INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,"
                        "alarm_title,dry_run,rollback,status,source_line,decision_note,target_line,"
                        "started_at,finished_at,timeline) "
                        "VALUES(?,?,?,?, 'api', ?,?,0, 'skipped', ?,?,?,?,?,?)",
                        (act["id"] if act else None, act["name"] if act else "(无可用动作)",
                         _did, dev["name"] if dev else "",
                         title, dry_run, ",".join(plan.get("fault_lines") or []),
                         (reason + " | " + plan.get("note", "")), plan.get("target_line") or "",
                         now(), now(), json.dumps(init_tl, ensure_ascii=False)))
                    conn.commit()
                    base.update({"task_id": None, "executed": False, "skip_reason": reason,
                                 "skip_reason_code": "no_target_line",
                                 "result": {"status": "skipped", "before_line": "", "after_line": "",
                                            "target_line": "", "reason": reason}})
                    return self._send_json(base)
                dev = conn.execute("SELECT name,host FROM devices WHERE id=?", (act["device_id"],)).fetchone()
                base["device"] = dict(dev) if dev else None
                log_id, skip = submit_action(conn, act, "api", title, dry_run=dry_run,
                                             source_line=",".join(plan.get("fault_lines") or []),
                                             decision_note=plan.get("note", ""), init_tl=init_tl,
                                             target_line=plan.get("target_line") or "")
                base["task_id"] = log_id
                if skip:
                    base["executed"] = False
                    base["skip_reason"] = skip
                    base["result"] = {"status": "skipped", "before_line": "", "after_line": "",
                                      "target_line": plan.get("target_line") or "",
                                      "reason": skip}
                else:
                    base["executed"] = True
                    # 同步等待执行结果（wait=0 时立即返回，仅带 task_id）
                    try:
                        wait_s = max(0, min(int(body.get("wait", 120)), 600))
                    except Exception:
                        wait_s = 120
                    if log_id is not None and wait_s > 0:
                        base["result"] = wait_exec_result(conn, log_id, wait_s)
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
                m_tgt = (body.get("target_line") or "").strip()
                log_id, skip = submit_action(conn, act, "manual", body.get("title") or "",
                                             dry_run=dry_run, rollback=rollback,
                                             target_line=m_tgt,
                                             init_tl=[{"ts": now(), "kind": "info",
                                                       "text": "页面手动触发「%s」%s"
                                                       % (act["name"],
                                                          ("（目标：%s）" % m_tgt) if m_tgt else "")}])
                if log_id is None:
                    return self._send_json({"executed": False, "skip_reason": skip}, 409)
                return self._send_json({"executed": True, "task_id": log_id})
            m4 = re.match(r"^/api/config$", path)
            if m4:
                for k in ("global_cooldown", "continue_on_error", "api_token", "aiops_url",
                          "aiops_token"):
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
                                "error": bool(h.get("error")),
                                "device": dict(dev) if dev else None,
                                "command_lines": len(parse_block(a["command_block"]))})
                # 多线路降级预演：按站点线路识别故障线路并挑目标（只读查询 AIOps，不执行）
                with_dry = str(body.get("dry", "")).lower() not in ("0", "false", "no")
                plan = None
                if with_dry and title:
                    try:
                        p = plan_switch(conn, title)
                        plan = {"matched": p["matched"], "allow": p["allow"],
                                "site": p.get("site_name"), "fault_lines": p.get("fault_lines"),
                                "target_line": p.get("target_line"),
                                "reason": p.get("reason"), "note": p.get("note"),
                                "legacy": p.get("legacy"),
                                "action_name": p["action"]["name"] if p["action"] else None,
                                "steps": [{k: s.get(k) for k in ("line", "status",
                                                                 "pending", "handling", "action", "rank")}
                                          for s in p.get("steps") or []]}
                    except Exception as e:
                        plan = {"error": str(e)}
                return self._send_json({"title": title,
                                        "matched": bool(out) or bool(plan and plan.get("matched")),
                                        "would_execute": (plan or {}).get("target_line") or
                                                          (out[0]["action_name"] if out else None),
                                        "plan": plan, "hits": out})
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
                    hits = [h for h in match_detail(conn, t) if not h.get("error")]
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
                  "target_line", "targets_json", "cooldown", "enabled", "remark"):
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
/* ============ 视觉系统 v2（slate + indigo，8pt 栅格 / 三级阴影 / 胶囊徽章） ============ */
:root{
  --primary:#4f46e5; --primary-hover:#4338ca; --primary-bg:#eef2ff; --primary-ring:rgba(79,70,229,.14);
  --bg-body:#f6f7f9; --bg-card:#ffffff; --bg-subtle:#f8fafc; --bg-hover:#f1f5f9;
  --text-main:#0f172a; --text-secondary:#334155; --text-muted:#64748b; --text-faint:#94a3b8;
  --border:#e9edf2; --border2:#d3dbe5;
  --sidebar-bg:#0f172a; --sidebar-text:#94a3b8; --sidebar-active-bg:rgba(148,163,184,.12); --sidebar-active-text:#fff;
  --success:#10b981; --success-bg:#e7f8f1; --success-d:#047857; --success-bd:#b8ecd6;
  --danger:#ef4444; --danger-bg:#feecee; --danger-d:#b42318; --danger-bd:#fbc9c9;
  --warn:#f59e0b; --warn-bg:#fdf3e0; --warn-d:#93632a; --warn-bd:#f5dfae;
  --info:#3b82f6; --info-bg:#e9f2fe; --info-d:#1d4ed8; --info-bd:#bcd8f9;
  --purple:#8b5cf6; --purple-bg:#f1edfe;
  /* 阴影三级 */
  --sh-1:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.06);
  --sh-2:0 2px 4px -2px rgba(16,24,40,.06),0 4px 12px -2px rgba(16,24,40,.08);
  --sh-3:0 8px 12px -3px rgba(16,24,40,.07),0 16px 40px -4px rgba(16,24,40,.14);
  --r-ctl:8px; --r-card:12px; --r-pop:14px;
}
::selection{background:var(--primary-bg);color:var(--primary-hover)}
*{box-sizing:border-box;margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",Roboto,Helvetica,Arial,sans-serif}
body{display:flex;flex-direction:column;height:100vh;background:var(--bg-body);color:var(--text-main);font-size:14px;overflow:hidden}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#94a3b8}

/* ============ 顶部一级菜单 ============ */
.headerbar{height:60px;background:linear-gradient(180deg,#111c31,#0f172a);display:flex;align-items:center;padding:0 24px;gap:8px;flex-shrink:0;z-index:30;box-shadow:0 1px 0 rgba(255,255,255,.06) inset,0 1px 4px rgba(15,23,42,.28)}
.logo-icon{width:32px;height:32px;background:linear-gradient(135deg,#6366f1,#4f46e5 55%,#4338ca);border-radius:9px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:bold;font-size:16px;flex-shrink:0;box-shadow:0 2px 6px rgba(79,70,229,.45),inset 0 1px 0 rgba(255,255,255,.25)}
.brand{color:#fff;font-size:15px;font-weight:600;letter-spacing:.3px;margin-right:28px;white-space:nowrap}
.top-nav{display:flex;gap:4px}
.top-nav button{border:none;background:none;color:var(--sidebar-text);font-size:14px;padding:9px 20px;border-radius:6px;cursor:pointer;transition:all .2s;position:relative}
.top-nav button:hover{color:#fff;background:rgba(255,255,255,.06)}
.top-nav button.active{color:#fff;font-weight:600;background:var(--sidebar-active-bg)}
.top-nav button.active::after{content:"";position:absolute;left:20px;right:20px;bottom:-11px;height:2px;border-radius:2px;background:var(--primary)}
.header-actions{margin-left:auto;display:flex;align-items:center;gap:14px}
.ver-top{font-size:11px;color:#8b98ab;white-space:nowrap}
.btn-logout{display:flex;align-items:center;gap:6px;padding:7px 14px;background:transparent;color:var(--sidebar-text);border:1px solid rgba(255,255,255,.12);border-radius:6px;font-size:12px;cursor:pointer;transition:all .2s;white-space:nowrap}
.btn-logout:hover{background:rgba(239,68,68,.12);color:var(--danger);border-color:rgba(239,68,68,.25)}

/* ============ 左侧二级菜单 ============ */
.app-row{flex:1;display:flex;min-height:0;overflow:hidden}
.sidebar{width:196px;background:var(--bg-card);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;overflow-y:auto}
.side-nav{padding:14px 12px}
.side-title{color:var(--text-muted);font-size:11px;font-weight:600;margin-bottom:10px;padding-left:10px;letter-spacing:1px}
.nav-item{display:flex;align-items:center;padding:9px 12px;color:#475569;font-size:13px;border-radius:6px;margin-bottom:4px;transition:all .2s;cursor:pointer;border:none;background:none;width:100%;text-align:left}
.nav-item svg{margin-right:10px;width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.nav-item:hover{color:var(--text-main);background:#f1f5f9}
.nav-item{position:relative}
.nav-item.active{color:var(--primary);background:var(--primary-bg);font-weight:600}
.nav-item.active::before{content:"";position:absolute;left:-12px;top:8px;bottom:8px;width:3px;border-radius:0 3px 3px 0;background:var(--primary)}

/* ============ 主区 ============ */
.main-container{flex:1;display:flex;flex-direction:column;min-width:0}
.content-scroll{flex:1;overflow-y:auto;padding:26px 32px 40px}
.page-view{display:none;width:100%;max-width:1800px;margin:0 auto}
.page-view.active{display:block;animation:fadeIn .22s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

/* ============ 卡片 ============ */
.card{background:var(--bg-card);border-radius:var(--r-card);border:1px solid var(--border);box-shadow:var(--sh-1);margin-bottom:24px;overflow:hidden}
.card-header{padding:17px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px}
.card-header h3{font-size:14px;font-weight:650;letter-spacing:.01em}
.card-body{padding:22px}
.card-body.tight{padding:18px 24px}

/* ============ 按钮 ============ */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 15px;font-size:13px;font-weight:550;border-radius:var(--r-ctl);cursor:pointer;transition:background .15s,border-color .15s,box-shadow .15s,transform .05s;border:1px solid transparent;white-space:nowrap}
.btn-primary{background:var(--primary);color:#fff;box-shadow:0 1px 2px rgba(79,70,229,.28)}
.btn-primary:hover{background:var(--primary-hover)}
.btn-secondary{background:#fff;color:var(--text-secondary);border-color:var(--border2);box-shadow:0 1px 2px rgba(16,24,40,.04)}
.btn-secondary:hover{background:var(--bg-subtle);border-color:#9aa8ba}
.btn-success{background:var(--success);color:#fff}
.btn-success:hover{filter:brightness(.94)}
.btn-warning{background:var(--warn);color:#fff}
.btn-warning:hover{filter:brightness(.94)}
.btn-danger{background:#fff;color:var(--danger);border-color:#fecaca}
.btn-danger:hover{background:var(--danger-bg);border-color:var(--danger)}
.btn-sm{padding:5px 11px;font-size:12px;border-radius:7px}
.btn:active{transform:translateY(.5px)}

/* ============ 表格 ============ */
.table-responsive{width:100%;overflow-x:auto}
.data-table{width:100%;border-collapse:collapse;font-size:13px;text-align:left}
.data-table th{background:var(--bg-subtle);color:var(--text-muted);font-weight:600;font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;padding:11px 22px;border-bottom:1px solid var(--border);white-space:nowrap;position:sticky;top:0;z-index:2}
.data-table td{padding:13px 22px;border-bottom:1px solid var(--border);vertical-align:middle;color:var(--text-main);font-size:13px}
.data-table tbody tr{transition:background .12s}
.data-table tbody tr:hover{background-color:var(--bg-subtle)}
.data-table tbody tr.clickable:hover{background-color:#eef2f7}
.data-table tr:last-child td{border-bottom:none}
.data-table tr.clickable{cursor:pointer}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.flt-group{display:flex;align-items:center;gap:10px;flex-wrap:wrap;flex:1;min-width:0}
.flt-group select,.flt-group input{height:34px;font-size:13px;border:1px solid var(--border2);border-radius:var(--r-ctl);background-color:#fff;color:var(--text-main);outline:none;transition:border-color .15s,box-shadow .15s}
.flt-group select{padding:0 34px 0 12px;width:auto;cursor:pointer;appearance:none;-webkit-appearance:none;font-weight:500;color:var(--text-secondary);
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%2364748b' stroke-width='2' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:right 12px center}
.flt-group select:hover{border-color:#9aa8ba}
.flt-group input{padding:0 12px;width:210px}
.flt-group select:focus,.flt-group input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-ring)}
.pager{display:flex;align-items:center;justify-content:flex-end;gap:8px;padding:12px 22px;border-top:1px solid var(--border)}
.pager .pg-info{margin-right:auto;font-size:12px;color:var(--text-muted)}
.pg-btn{border:1px solid var(--border2);background:#fff;color:var(--text-secondary);font-size:12px;padding:5px 12px;border-radius:6px;cursor:pointer;transition:all .15s}
.pg-btn:hover:not(:disabled){border-color:var(--primary);color:var(--primary)}
.pg-btn:disabled{opacity:.45;cursor:not-allowed}
.empty{padding:44px 24px;text-align:center;color:var(--text-faint);font-size:13px;line-height:1.8}
.empty svg{width:34px;height:34px;display:block;margin:0 auto 12px;opacity:.45;fill:none;stroke:currentColor;stroke-width:1.5}

/* 表格内元素 */
.status-cell{display:flex;align-items:center;gap:8px;font-weight:500;white-space:nowrap}
.dot-green{width:8px;height:8px;background:var(--success);border-radius:50%;flex-shrink:0}
.dot-red{width:8px;height:8px;background:var(--danger);border-radius:50%;flex-shrink:0}
.device-info{display:flex;flex-direction:column;gap:3px}

.device-host{font-size:12px;color:var(--text-muted)}
.tag{padding:2px 10px;border-radius:999px;font-size:12px;font-weight:550;background:var(--primary-bg);color:var(--primary-hover);white-space:nowrap;display:inline-block;line-height:1.6}




.tag.ok{background:var(--success-bg);color:var(--success-d);box-shadow:inset 0 0 0 1px var(--success-bd)}
.tag.bad{background:var(--danger-bg);color:var(--danger-d);box-shadow:inset 0 0 0 1px var(--danger-bd)}
.tag.warn{background:var(--warn-bg);color:var(--warn-d);box-shadow:inset 0 0 0 1px var(--warn-bd)}
.tag.info{background:var(--info-bg);color:var(--info-d);box-shadow:inset 0 0 0 1px var(--info-bd)}
.tag.gray{background:var(--bg-hover);color:var(--text-muted);box-shadow:inset 0 0 0 1px #e2e8f0}
.cov-site{border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin-bottom:14px;background:var(--bg-subtle)}
.cov-site:last-child{margin-bottom:0}
.cov-site-hd{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.cov-site-hd b{font-size:13.5px;font-weight:650}
.cov-cnt{margin-left:auto;font-size:12px;font-weight:600;padding:2px 10px;border-radius:999px}
.cov-cnt.ok{color:var(--success-d);background:var(--success-bg)}
.cov-cnt.warn{color:var(--warn-d);background:var(--warn-bg)}
.cov-cnt.gray{color:var(--text-muted);background:var(--bg-hover)}
.cov-none{font-size:12px;color:var(--text-faint)}
.cov-lines{display:flex;flex-wrap:wrap;gap:8px}
.cov-ladders{margin-top:12px;padding-top:12px;border-top:1px dashed var(--border2);display:flex;flex-direction:column;gap:8px}
.ladder{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.ladder-name{font-size:12px;color:var(--text-muted);min-width:150px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ladder-step{display:inline-flex;align-items:center;gap:6px;background:#fff;border:1px solid var(--border2);border-radius:6px;padding:3px 10px;font-size:12px;font-weight:550;color:var(--text-main)}
.ladder-step i{font-style:normal;font-size:10px;font-weight:700;color:#fff;background:var(--text-faint);border-radius:50%;width:15px;height:15px;display:inline-flex;align-items:center;justify-content:center}
.ladder-step.miss{border-color:var(--danger-bd);color:var(--danger-d)}
.ladder-step.miss i{background:var(--danger)}
.ladder-arrow{color:var(--text-faint);font-size:12px}
.cov-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:999px;font-size:12.5px;font-weight:550;border:1px solid transparent;white-space:nowrap;transition:all .15s}
.cov-chip i{font-style:normal;font-size:11px;opacity:.7}
.cov-chip.ok{background:var(--success-bg);color:var(--success-d);border-color:var(--success-bd)}
.cov-chip.bad{background:var(--danger-bg);color:var(--danger-d);border-color:var(--danger-bd);cursor:pointer;box-shadow:0 0 0 0 rgba(239,68,68,.35)}
.cov-chip.bad:hover{background:#fdd8d8;border-color:var(--danger);box-shadow:0 2px 8px rgba(239,68,68,.18)}
.keyword-text{color:#334155;line-height:1.5;max-width:400px;display:inline-block;word-break:break-all}
.ops-cell{display:flex;gap:8px;justify-content:flex-end}
.err-text{color:#b91c1c;font-size:12px;line-height:1.5}
.data-table td.cell1{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.data-table.log-tb td{padding:11px 12px}
.data-table.log-tb th{padding:10px 12px}

/* ============ 统计卡 ============ */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-grid.stat-6{grid-template-columns:repeat(6,1fr)}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r-card);padding:18px 20px;display:flex;align-items:center;gap:15px;box-shadow:var(--sh-1);cursor:pointer;transition:border-color .15s,box-shadow .15s,transform .15s}
.stat-card:hover{border-color:var(--border2);box-shadow:var(--sh-2);transform:translateY(-1px)}
.stat-card.on{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-ring)}
tr.row-off td{opacity:.55}
tr.row-off td .tag{filter:saturate(.4)}
,input:focus-visible,select:focus-visible,tr.clickable:focus-visible{outline:2px solid var(--primary);outline-offset:2px}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
.stat-ic{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;flex-shrink:0;background:var(--bg-hover);color:var(--text-muted)}
.stat-ic svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.stat-card b{font-size:26px;font-weight:750;display:block;line-height:1.2;font-variant-numeric:tabular-nums}
.stat-card span{color:var(--text-muted);font-size:12.5px}

/* ============ 表单 ============ */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
label{display:block;font-size:12px;color:var(--text-secondary);margin:14px 0 6px;font-weight:600}
input,select,textarea{width:100%;border:1px solid var(--border2);border-radius:var(--r-ctl);padding:9px 12px;font-size:13px;font-family:inherit;color:var(--text-main);background:#fff;transition:border-color .15s,box-shadow .15s;outline:none}
input[readonly]{background:#f1f5f9;color:var(--text-muted);cursor:not-allowed}
input:focus,select:focus,textarea:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-ring)}
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
.q{position:relative;display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border-radius:50%;border:1px solid #94a3b8;color:#64748b;font-size:11px;font-weight:700;cursor:help;margin-left:7px;vertical-align:middle;flex-shrink:0;line-height:1}
.q:hover{border-color:var(--primary);color:var(--primary);background:var(--primary-bg)}
.qtip{position:fixed;background:#0f172a;color:#e2e8f0;font-size:12px;font-weight:400;line-height:1.65;padding:8px 12px;border-radius:6px;white-space:pre-line;width:max-content;max-width:320px;box-shadow:0 6px 20px rgba(15,23,42,.28);pointer-events:none;z-index:500;display:none}
.qtip.show{display:block}
.qtip .qarrow{position:absolute;width:10px;height:10px;background:#0f172a;transform:rotate(45deg)}

/* ============ 弹窗 ============ */
.modal{position:fixed;inset:0;background:rgba(15,23,42,.45);backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px);display:none;align-items:flex-start;justify-content:center;z-index:100;overflow:auto;padding:48px 16px}
.modal.show{display:flex;animation:fadeIn .18s ease}
.modal .box{background:#fff;border-radius:var(--r-pop);width:780px;max-width:100%;box-shadow:var(--sh-3),0 24px 60px rgba(15,23,42,.28);animation:rise .22s cubic-bezier(.2,.9,.3,1.12);border:1px solid rgba(255,255,255,.6)}
@keyframes rise{from{transform:translateY(14px);opacity:0}to{transform:none;opacity:1}}
.mhd{display:flex;align-items:center;padding:18px 24px;border-bottom:1px solid var(--border);gap:12px;background:linear-gradient(180deg,#fff,var(--bg-subtle))}
.mhd h3{font-size:15px;font-weight:650;flex:1}
.mx{border:none;background:#f1f5f9;color:#64748b;width:28px;height:28px;border-radius:6px;cursor:pointer;font-size:14px;line-height:1;display:flex;align-items:center;justify-content:center;transition:all .2s}
.mx:hover{background:var(--danger-bg);color:var(--danger)}
.mbd{padding:8px 24px 8px;max-height:calc(100vh - 230px);overflow-y:auto}
.mfoot{padding:16px 24px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end;align-items:center}
.mfoot .sp{flex:1}

/* ============ 终端输出 ============ */
pre.out{background:#0f172a;color:#cbd5e1;padding:14px 16px;border-radius:10px;font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;line-height:1.65;overflow:auto;max-height:280px;white-space:pre-wrap;border:1px solid #1e293b}
pre.out .err{color:#fca5a5}

/* ---- 执行详情：结构化元数据 / 折叠面板 / 终端窗口（参考稿样式） ---- */
.meta-grid{display:grid;grid-template-columns:2fr 1fr 1.3fr;gap:16px 24px;background:var(--bg-subtle);padding:18px 20px;border-radius:10px;border:1px solid var(--border);margin-bottom:20px}
.meta-item{display:flex;flex-direction:column;gap:4px}
.meta-label{font-size:12px;color:var(--text-muted)}
.meta-value{font-size:14px;font-weight:500;color:var(--text-main);word-break:break-all}
.meta-value.title{color:var(--text-main);font-weight:600}
.accordion{border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:16px;background:#fff}
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
.terminal-window{background:#0f172a;border-radius:10px;overflow:hidden;box-shadow:inset 0 0 0 1px rgba(255,255,255,.05)}
.terminal-header{background:#1e293b;padding:10px 16px;display:flex;align-items:center;border-bottom:1px solid #334155}
.mac-dots{display:flex;gap:6px}
.dot{width:10px;height:10px;border-radius:50%}
.dot.red{background:#ef4444}.dot.yellow{background:#f59e0b}.dot.green{background:#10b981}
.terminal-title{margin-left:16px;font-size:11px;color:#94a3b8}
.terminal-body{padding:16px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;line-height:1.6;color:#e2e8f0;overflow:auto;max-height:320px;white-space:pre-wrap;word-break:break-all}
.err-banner{margin-bottom:0}

/* ---- 执行过程时间线 ---- */
.timeline{position:relative;padding-left:22px;margin-bottom:20px}
.timeline::before{content:"";position:absolute;left:6px;top:8px;bottom:8px;width:1.5px;background:var(--border2)}
.tl-item{position:relative;padding:0 0 14px 6px}
.tl-item:last-child{padding-bottom:0}
.tl-dot{position:absolute;left:-22px;top:4px;width:11px;height:11px;border-radius:50%;background:#fff;border:2px solid var(--text-faint);box-shadow:0 0 0 3px var(--bg-body);z-index:1}
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
.verdict{display:flex;align-items:center;gap:14px;padding:14px 18px;border-radius:10px;margin-bottom:18px;border:1px solid var(--border);background:var(--bg-subtle)}
.verdict-tag{font-size:14px;font-weight:700;white-space:nowrap}
.verdict-route{font-size:14px;color:var(--text-secondary);white-space:nowrap}
.verdict-route b{font-size:15px;color:var(--text-main)}
.verdict-why{font-size:12.5px;color:var(--text-muted);line-height:1.5;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.verdict.ok{background:var(--success-bg);border-color:var(--success-bd)}.verdict.ok .verdict-tag{color:var(--success-d)}
.verdict.bad{background:var(--danger-bg);border-color:var(--danger-bd)}.verdict.bad .verdict-tag{color:var(--danger-d)}
.verdict.warn{background:var(--warn-bg);border-color:var(--warn-bd)}.verdict.warn .verdict-tag{color:var(--warn-d)}
.verdict.info .verdict-tag{color:var(--info-d)}
/* ---- 执行详情：图标时间线（参考稿结构） ---- */
.tlx-card{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:22px 24px}
.tlx-title{font-size:15px;font-weight:650;margin-bottom:20px;color:var(--text-main)}
.tlx{display:flex;flex-direction:column}
.tlx-item{display:flex;gap:16px}
.tlx-ic{display:flex;flex-direction:column;align-items:center;flex-shrink:0;width:24px}
.tlx-dot{width:24px;height:24px;border-radius:50%;background:#fff;border:2px solid var(--border2);color:var(--text-muted);display:flex;align-items:center;justify-content:center;z-index:2}
.tlx-dot svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round}
.tlx-item.ok .tlx-dot{border-color:var(--success);color:var(--success-d);background:var(--success-bg)}
.tlx-item.bad .tlx-dot{border-color:var(--danger);color:var(--danger-d);background:var(--danger-bg)}
.tlx-item.warn .tlx-dot{border-color:var(--warn);color:var(--warn-d);background:var(--warn-bg)}
.tlx-item.info .tlx-dot{border-color:var(--info);color:var(--info-d);background:var(--info-bg)}
.tlx-line{width:2px;background:var(--border);flex:1;min-height:16px;margin:4px 0}
.tlx-c{flex:1;min-width:0;padding-bottom:22px}
.tlx-item:last-child .tlx-c{padding-bottom:0}
.tlx-hd{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:6px;flex-wrap:wrap}
.tlx-hd h4{font-size:13.5px;font-weight:600;color:var(--text-main);word-break:break-word;flex:1;line-height:1.5}
.tlx-ts{font-size:12px;color:var(--text-muted);font-family:ui-monospace,Menlo,Consolas,monospace;white-space:nowrap}
.tlx-bd{margin-top:8px}
.tlx-panel{margin-top:12px;border:1px solid var(--border);border-radius:8px;overflow:hidden}
details.tlx-panel>summary.tlx-panel-hd{list-style:none;cursor:pointer}
details.tlx-panel>summary.tlx-panel-hd::-webkit-details-marker{display:none}
.sess-body{padding:16px;border-top:1px solid var(--border);background:#fff;display:flex;flex-direction:column;gap:14px}
.sess-phase{border:1px solid var(--border);border-radius:8px;overflow:hidden}
.sess-phase-hd{background:var(--bg-subtle);padding:9px 14px;font-size:12.5px;font-weight:600;color:var(--text-secondary);border-bottom:1px solid var(--border);display:flex;align-items:center}
.sess-pre{margin:0;background:#0f172a;color:#e2e8f0;font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;padding:12px 14px;max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all;line-height:1.6}
.tlx-panel-arrow{margin-left:auto;display:flex}
.tlx-panel-arrow svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;color:var(--text-muted);transition:transform .2s}
details.tlx-panel[open] .tlx-panel-arrow svg{transform:rotate(180deg)}
details.tlx-panel:not([open]) .tlx-panel-hd{border-bottom:none}
.tlx-panel-hd{background:var(--bg-subtle);padding:10px 16px;font-size:13px;font-weight:550;color:var(--text-secondary);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
.tlx-panel-hd svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;flex-shrink:0;color:var(--text-muted)}
.tlx-panel-bd{padding:16px;background:#fff;overflow-x:auto}
.tlx-ev{margin-top:10px}
.tlx-ev summary{cursor:pointer;font-size:12.5px;font-weight:600;color:var(--text-muted);padding:2px 0}
.tlx-ev summary:hover{color:var(--primary)}
.rule-chip{background:var(--bg-hover);color:var(--text-secondary);border:1px solid var(--border);padding:2px 6px;border-radius:4px;font-size:12px;font-family:ui-monospace,Menlo,monospace;word-break:break-all;display:inline-block}
/* 证据表格（弹窗内） */
.tlx-panel-bd table.ev-table{border-collapse:collapse;font-size:13px;width:100%;table-layout:fixed}
.tlx-panel-bd table.ev-table th{padding:8px 12px;text-align:left;color:var(--text-muted);font-weight:550;border-bottom:1px solid var(--border);background:#fff}
.tlx-panel-bd table.ev-table td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word}
.tlx-panel-bd table.ev-table tr:last-child td{border-bottom:none}
.tlx-ev summary{cursor:pointer;font-size:12px;font-weight:600;color:var(--text-muted);padding:2px 0}
.tl-ev summary:hover{color:var(--primary)}
.tl-ev[open]{margin-bottom:2px}
details{margin:8px 0}
details summary{cursor:pointer;color:var(--text-muted);font-size:12.5px;padding:4px 0;outline:none}
details summary:hover{color:var(--primary)}
.err-banner{color:var(--danger-d);background:var(--danger-bg);border:1px solid #fecaca;border-radius:6px;padding:10px 14px;margin-bottom:12px;font-size:13px}
.hit-ok{background:var(--bg-subtle);color:var(--text-main);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin-bottom:10px;font-size:13px;line-height:1.6}
.hit-bad{background:var(--danger-bg);color:var(--danger-d);border:1px solid var(--danger-bd);border-radius:8px;padding:10px 14px;margin-bottom:10px;font-size:13px}

/* ============ 登录 ============ */
.login{position:fixed;inset:0;background:radial-gradient(760px 460px at 24% 18%,rgba(79,70,229,.28),transparent 62%),var(--sidebar-bg);display:none;align-items:center;justify-content:center;z-index:200}
.login.show{display:flex}
.login .box{background:#fff;border-radius:16px;padding:36px 34px;width:360px;box-shadow:0 32px 80px rgba(0,0,0,.5),0 0 0 1px rgba(255,255,255,.08)}
.login .lg-logo{width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,#6366f1,#4338ca);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:bold;font-size:24px;margin-bottom:16px;box-shadow:0 4px 12px rgba(79,70,229,.4)}
.login h3{font-size:18px;margin-bottom:4px}
.login .ls{font-size:12.5px;color:var(--text-muted);margin-bottom:22px}
.login input{padding:11px 13px;font-size:14px}
.login .btn{width:100%;padding:11px;font-size:14px;margin-top:12px}
#lg_err{color:var(--danger);margin-top:10px;font-size:12.5px}

/* ============ Toast ============ */
#toast-container{position:fixed;top:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{display:flex;align-items:center;gap:10px;min-width:250px;max-width:420px;padding:12px 16px;background:#fff;border-radius:10px;box-shadow:var(--sh-3);font-size:13px;font-weight:500;border-left:4px solid var(--success);transform:translateX(120%);transition:transform .35s cubic-bezier(.22,1,.36,1);word-break:break-all;border:1px solid var(--border)}
.toast.show{transform:translateX(0)}
.toast.error{border-left-color:var(--danger)}
.toast .ti{font-weight:bold}

@media (max-width:1000px){
  .brand{margin-right:12px}
  .top-nav button{padding:8px 12px;font-size:13px}
  .sidebar{width:56px;flex-basis:56px}
  .nav-item span{display:none}
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
      <div class="card-header">
        <div class="flt-group">
        <select id="f_site" onchange="LOG_F.site=this.value;LOG_PAGE=1;loadLogs()"><option value="">全部站点</option></select>
        <select id="f_dev" onchange="LOG_F.dev=this.value;LOG_PAGE=1;loadLogs()"><option value="">全部设备</option></select>
        <select id="f_act" onchange="LOG_F.act=this.value;LOG_PAGE=1;loadLogs()"><option value="">全部动作</option></select>
        <input id="f_kw" placeholder="搜索标题/错误/动作关键字" oninput="LOG_F.kw=this.value.trim();clearTimeout(window.__kwT);window.__kwT=setTimeout(()=>{LOG_PAGE=1;loadLogs()},300)">
        </div>
        <button class="btn btn-secondary btn-sm" onclick="loadStats();loadLogs()" title="每 30 秒自动刷新；点击统计卡可按状态筛选">刷新</button></div>
      <div class="table-responsive"><table class="data-table log-tb" style="table-layout:fixed;min-width:1320px">
      <colgroup><col style="width:42px"><col style="width:182px"><col style="width:60px"><col style="width:88px"><col><col style="width:148px"><col style="width:110px"><col style="width:58px"><col style="width:94px"><col></colgroup>
      <thead><tr>
        <th>ID</th><th>时间</th><th>触发</th><th>站点</th><th>告警标题</th>
        <th>动作</th><th>设备</th><th>模式</th><th>状态</th><th>错误</th></tr></thead>
      <tbody id="logtb"></tbody></table></div>
      <div id="logpg"></div>
    </div>
  </div>

  <!-- 匹配预检 -->
  <div class="page-view" id="p-match">
    <div class="card">
      <div class="card-body" style="display:flex;flex-direction:column;gap:16px">
        <div class="toolbar-row">
          <div class="input-group">
            <input id="mt_title" placeholder="输入告警标题，如 【ICMP丢包】拉米卡专线-Airtel专线（刚果金地址）" onkeydown="if(event.key=='Enter')matchTest()">
            <button class="btn btn-primary" onclick="matchTest()">检测规则</button>
          </div>
        </div>
        <div id="mt_out"><div class="empty" style="padding:28px 24px"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>粘贴一条真实告警标题，校验它会命中哪条规则、降级预演会选中哪个目标线路<br><span style="font-size:12px">也可用下方「回放」以近几天真实告警批量检验规则覆盖</span></div></div>
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
    <div class="card" style="margin-bottom:16px">
      <div class="card-header"><h3>线路切换覆盖<span class="q" data-tip="降级阶梯总览：每条线路都应出现在某条规则的目标阶梯中。&#10;告警触发时按规则阶梯顺序（=优先级）逐条体检目标线路，选第一条无活跃告警且配了本方向命令的目标；全部告警/缺命令则不切换。&#10;点红色线路名可将其追加到规则阶梯。">?</span></h3>
        <button class="btn btn-secondary btn-sm" onclick="loadActions()">刷新</button></div>
      <div class="card-body" id="cov_out"></div>
    </div>
    <div class="card">
      <div class="card-header"><h3>动作规则<span class="q" data-tip="一条规则 = 一个降级阶梯：按顺序配置多个目标线路及各自的切换命令（命令块为全量状态：先 undo 其它方向再添加本方向，与从哪条切过来无关）。&#10;告警触发时按阶梯顺序（=优先级）逐条体检目标线路，选中第一条无活跃告警的目标并下发它的命令。&#10;降级顺序只在规则阶梯这一处维护；匹配关键词仅用于「匹配预检」与站点未配置线路时的兼容匹配；命令块中 # 开头行为注释，执行时跳过。">?</span></h3><button class="btn btn-primary" onclick="editAction(0)">＋ 新建切换规则</button></div>
      <div class="table-responsive"><table class="data-table"><thead><tr>
        <th style="width:90px">状态</th><th style="width:220px">规则名 / 设备</th><th style="width:230px">目标阶梯（降级顺序）</th>
        <th>匹配关键词 / 正则（预检用）</th><th style="width:80px">冷却</th><th style="width:300px;text-align:right">执行操作</th></tr></thead>
      <tbody id="acttb"></tbody></table></div>
    </div>
  </div>

  <!-- 设备管理 -->
  <div class="page-view" id="p-devices">
    <div class="card">
      <div class="card-header">
        <div class="flt-group"><input id="df_kw" placeholder="搜索设备名/IP/站点" oninput="DEV_KW=this.value.trim();loadDevices()"></div>
        <button class="btn btn-primary" onclick="editDevice(0)">＋ 新建设备</button></div>
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
      <div class="card-header">
        <div class="flt-group"><input id="sf_kw" placeholder="搜索站点名/线路" oninput="SITE_KW=this.value.trim();loadSites()"></div>
        <button class="btn btn-primary" onclick="editSite(0)">＋ 新建站点</button></div>
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
        <div class="kv"><label>API Token<span class="q" data-tip="AIOps 回调本系统时携带 X-API-Token 请求头。&#10;回调接口：POST /api/alert，Body: {&quot;title&quot;:&quot;告警标题&quot;}&#10;出于安全默认掩码显示；留空=不修改，粘贴新值可整体重置。">?</span></label><div class="ctl"><input id="s_token" placeholder="留空不修改"><span id="token_hint" style="font-size:12px;color:var(--text-muted);white-space:nowrap"></span></div></div>
        <div class="kv"><label>全局冷却(秒)</label><div class="ctl"><input id="s_cd" type="number" style="max-width:220px"></div></div>
        <div class="kv"><label>AIOps 告警接口</label><div class="ctl"><input id="s_aiops_url"></div></div>
        <div class="kv"><label>AIOps Token</label><div class="ctl"><input id="s_aiops_tok" placeholder="留空不修改"></div></div>
        <div style="display:flex;justify-content:flex-end"><button class="btn btn-primary" onclick="saveCfg()">保存设置</button></div>
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
<div class="modal" id="mAct"><div class="box" style="width:860px;max-width:94vw">
  <div class="mhd"><h3 id="mActTitle">切换动作</h3><button class="mx" onclick="closeM('mAct')">✕</button></div>
  <div class="mbd">
  <input type="hidden" id="a_id">
  <div class="grid2">
    <div><label>规则名称 *</label><input id="a_name" placeholder="如：拉米卡-故障降级切换"></div>
    <div><label>所属站点</label><select id="a_site" onchange="onActionSiteChange()"></select></div>
  </div>
  <div class="grid2">
    <div><label>目标设备 *</label><select id="a_device"></select></div>
    <div><label>匹配方式</label><select id="a_mtype"><option value="contains">包含关键词</option><option value="regex">正则表达式</option></select></div>
  </div>
  <div class="grid2">
    <div><label>故障线路（告警说的是哪条）<span class="q" data-tip="读取站点维护的线路。选中后自动填充匹配关键词=该线路告警关键字，用于「匹配预检」；站点未配线路时它就是触发关键词。">?</span></label><select id="a_line" onchange="onActionLineChange()"></select></div>
    <div><label>匹配关键词 / 正则（站点已配线路时仅预检用）</label><input id="a_kw" placeholder="选择故障线路后自动填充"></div>
  </div>
  <textarea id="a_rb" style="display:none"></textarea>
  <label>目标线路阶梯（降级顺序=列表顺序，第一条最优先）<span class="q" data-tip="收到该线路告警后：按阶梯顺序逐条查询目标线路是否有未处理/处理中告警，选中第一条健康且配了切换命令的目标并下发它的命令块。&#10;每个目标的命令块建议为「全量状态」：undo 其它方向策略 + 添加本方向。&#10;期望关键词默认取该线路下一跳IP，用于切换后验证路由指向。">?</span></label>
  <div id="tgt_box" style="display:flex;flex-direction:column;gap:10px"></div>
  <button class="btn btn-secondary btn-sm" style="margin-top:10px" onclick="addTarget()">＋ 添加目标线路</button>
  <div class="grid2" style="margin-top:14px">
    <div><label>冷却时间(秒，0=用全局)</label><input id="a_cd" type="number" value="0"></div>
    <label class="sw"><input type="checkbox" id="a_en" checked><span>启用该规则</span></label>
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
    <button class="btn btn-secondary" onclick="testDevice()">测试连接</button>
    <button class="btn btn-secondary" onclick="queryDeviceLine()">查当前线路</button>
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
  <div class="mhd"><h3 id="mLineTitle">站点线路</h3><span class="q" data-tip="线路是全站统一配置：告警关键词用于①识别告警说的是哪条线路②查 AIOps 判断该线路是否仍有活跃告警；下一跳IP用于识别设备当前运行在哪条线路上（线路映射只在此维护），并作为切换规则中该目标线路的期望验证关键词默认值。&#10;降级切换的先后顺序在「切换配置 → 切换动作」的规则阶梯里维护，此处不再设置优先级。">?</span><button class="mx" onclick="closeM('mLine')">✕</button></div>
  <div class="mbd">
  <input type="hidden" id="l_site">
  <div class="table-responsive"><table class="data-table"><thead><tr><th>线路名</th><th>告警关键词</th><th>下一跳IP<span class="q" data-tip="该线路生效时路由表 0.0.0.0/0 的下一跳地址，用于识别「当前运行在哪条线路上」">?</span></th><th style="width:90px">状态</th><th style="width:100px;text-align:right">操作</th></tr></thead>
  <tbody id="ltb"></tbody></table></div>
  <div class="grid2" style="margin-top:14px">
    <div><label>线路名</label><input id="l_name" placeholder="如 Airtel"></div>
    <div><label>下一跳IP（该线路生效时 0.0.0.0/0 的 NextHop）</label><input id="l_ip" placeholder="如 192.168.130.10"></div>
  </div>
  <div><label>告警关键词(逗号分隔)</label><input id="l_kw" placeholder="如 41.243.21.170,Airtel"></div>
  </div>
  <div class="mfoot">
    <button class="btn btn-secondary" onclick="closeM('mLine')">关闭</button>
    <span class="sp"></span>
    <button class="btn btn-primary" onclick="addLine()">添加线路</button>
  </div>
</div></div>

<!-- 日志详情 -->
<div class="modal" id="mLog"><div class="box" style="width:1080px;max-width:96vw">
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
const PAGE_INFO={dash:["执行记录","告警触发的切换任务历史、状态与结果证据"],
  match:["匹配预检","以告警标题校验规则命中与降级链路，不产生任何执行"],
  actions:["切换动作","维护站点降级阶梯：目标线路顺序与各方向切换命令"],
  devices:["设备管理","站点设备的连接凭据、线路识别命令与连通性"],
  sites:["站点管理","站点与其线路的告警关键字、下一跳映射"],
  settings:["全局设置","访问凭据、AIOps 接口与判定参数"],
  alerttest:["回调测试","模拟 AIOps 告警回调，验证端到端触发链路"]};
const NAV_GROUPS={
  monitor:{title:"监控中心",items:[["dash","执行记录",'<path d="M3 12h4l3-8 5 16 3-8h4"/>']]},
  config:{title:"切换配置",items:[["actions","切换动作",'<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>'],["match","匹配预检",'<circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>']]},
  resource:{title:"资源管理",items:[["devices","设备管理",'<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>'],["sites","站点管理",'<path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>']]},
  system:{title:"系统设置",items:[["settings","全局设置",'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>'],["alerttest","回调测试",'<path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/>']]}};
let CUR_PAGE="dash";
function buildSideNav(g){
  const grp=NAV_GROUPS[g];
  $("sideNav").innerHTML=grp.items.map(it=>`<button class="nav-item${it[0]==CUR_PAGE?" active":""}" data-p="${it[0]}"><svg viewBox="0 0 24 24">${it[2]}</svg><span>${it[1]}</span></button>`).join("");
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
 ["total","总执行","","",'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8M16 17H8"/>'],
 ["success","成功","","",'<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/>'],
 ["failed","失败","var(--danger-d)","",'<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>'],
 ["running","执行中","","",'<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>'],
 ["skipped","条件不满足","","",'<path d="M5 12h14"/><path d="M13 5l7 7-7 7"/>'],
 ["verify_failed","验证未过","var(--warn-d)","",'<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>']];
let LOG_FILTER="", LOG_F={site:"",dev:"",act:"",kw:""};
let LOG_ALL=[];
function fillFilterOpts(){
  const sites={},devs={},acts={};
  LOG_ALL.forEach(l=>{if(l.site_name)sites[l.site_name]=1;if(l.device_name)devs[l.device_name]=1;if(l.action_name)acts[l.action_name]=1});
  const set=(id,keys)=>{const sel=$(id);const v=sel.value;
    sel.innerHTML=sel.options[0].outerHTML+Object.keys(keys).sort().map(k=>`<option value="${esc(k)}"${k===v?" selected":""}>${esc(k)}</option>`).join("")};
  set("f_site",sites);set("f_dev",devs);set("f_act",acts)}
function loadStats(){api("GET","/api/stats").then(s=>{
  $("ver").textContent=s.version;
  $("stat").innerHTML=STAT.map(x=>`<div class="stat-card${LOG_FILTER===(x[0]=='total'?'':x[0])?" on":""}" title="点击筛选该状态" onclick="setLogFilter('${x[0]=='total'?'':x[0]}')">
    <div class="stat-ic"><svg viewBox="0 0 24 24">${x[4]}</svg></div>
    <div><b${x[2]?` style="color:${x[2]}"`:""}>${s[x[0]]}</b><span>${x[1]}</span></div></div>`).join("")})}
function setLogFilter(st){LOG_FILTER=(LOG_FILTER===st?"":st);LOG_PAGE=1;loadStats();loadLogs()}
const ST_TAG={success:["成功","ok"],failed:["失败","bad"],running:["执行中","info"],cooldown_skip:["冷却跳过","gray"],
  verify_failed:["验证未过","warn"],skipped:["条件不满足","gray"],cooldown:["冷却中","warn"]};
const LOG_PER=15;let LOG_PAGE=1;
function logsFiltered(){let ls=LOG_ALL.slice();
  if(LOG_FILTER)ls=ls.filter(l=>l.status===LOG_FILTER);
  if(LOG_F.site)ls=ls.filter(l=>l.site_name===LOG_F.site);
  if(LOG_F.dev)ls=ls.filter(l=>l.device_name===LOG_F.dev);
  if(LOG_F.act)ls=ls.filter(l=>l.action_name===LOG_F.act);
  if(LOG_F.kw){const k=LOG_F.kw.toLowerCase();ls=ls.filter(l=>((l.alarm_title||"")+(l.error||"")+(l.action_name||"")).toLowerCase().includes(k))}
  return ls}
function setLogPage(n){LOG_PAGE=n;loadLogs()}
function loadLogs(){api("GET","/api/logs?limit=300").then(all=>{DATA.logs=all;LOG_ALL=all;fillFilterOpts();
  const fl=logsFiltered();
  const pages=Math.max(1,Math.ceil(fl.length/LOG_PER));
  if(LOG_PAGE>pages)LOG_PAGE=pages;
  const ls=fl.slice((LOG_PAGE-1)*LOG_PER,(LOG_PAGE-1)*LOG_PER+LOG_PER);
  const pg=$("logpg");
  if(pg)pg.innerHTML=fl.length>LOG_PER?`<div class="pager"><span class="pg-info">共 ${fl.length} 条 · 第 ${LOG_PAGE}/${pages} 页</span>
    <button class="pg-btn" ${LOG_PAGE<=1?"disabled":""} onclick="setLogPage(1)">首页</button>
    <button class="pg-btn" ${LOG_PAGE<=1?"disabled":""} onclick="setLogPage(${LOG_PAGE-1})">上一页</button>
    <button class="pg-btn" ${LOG_PAGE>=pages?"disabled":""} onclick="setLogPage(${LOG_PAGE+1})">下一页</button>
    <button class="pg-btn" ${LOG_PAGE>=pages?"disabled":""} onclick="setLogPage(${pages})">末页</button></div>`:"";
  $("logtb").innerHTML=ls.length?ls.map(l=>{const st=ST_TAG[l.status]||[esc(l.status),"gray"];
    return `<tr class="clickable" tabindex="0" onkeydown="if(event.key==='Enter')showLog(${l.id})" onclick="showLog(${l.id})">
    <td class="mono" style="color:var(--text-muted)">#${l.id}</td>
    <td class="mono cell1" style="color:var(--text-muted)">${esc(l.started_at)}</td>
    <td><span class="tag gray">${l.trigger=="api"?"API":"手动"}</span></td>
    <td class="cell1"><span title="${esc(l.site_name)}">${esc(l.site_name)||"-"}</span></td>
    <td class="cell1"><span class="keyword-text" style="max-width:260px" title="${esc(l.alarm_title)}">${esc(l.alarm_title)||"-"}</span></td>
    <td class="cell1"><b title="${esc(l.action_name)}">${esc(l.action_name)}</b></td><td class="cell1">${esc(l.device_name)}</td>
    <td class="cell1">${l.dry_run?"演练":"切换"}</td>
    <td><span class="tag ${st[1]}">${st[0]}</span></td>
    <td class="cell1"><span class="err-text" style="max-width:none" title="${esc(l.error)}">${esc(l.error)||"-"}</span></td></tr>`}).join(""):'<tr><td colspan=10><div class="empty"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 5 16 3-8h4"/></svg>暂无执行记录</div></td></tr>'})}
const TL_IC={ok:'<svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>',
  bad:'<svg viewBox="0 0 24 24"><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
  warn:'<svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  info:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>'};
function durTxt(l){if(!l.finished_at||!l.started_at)return "";
  const t=(new Date(l.finished_at.replace(" ","T"))-new Date(l.started_at.replace(" ","T")))/1000;
  if(!(t>=0))return "";
  const d=t>=86400?Math.floor(t/86400)+"天":t>=3600?Math.floor(t/3600)+"时"+Math.floor(t%3600/60)+"分":t>=60?Math.floor(t/60)+"分"+Math.round(t%60)+"秒":Math.round(t)+"秒";
  return ` <span style="color:var(--primary);font-weight:600">（共 ${d}）</span>`}
function showLog(id){api("GET","/api/logs/"+id).then(l=>{
  $("mLogTitle").innerHTML=`执行详情 <span>#${l.id} · ${esc(l.action_name)} · ${(ST_TAG[l.status]||[l.status])[0]}</span>`;
  const ARROW='<svg viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>';
  const term=(title,text,open)=>`<div class="accordion${open?" open":""}"><div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">${title}${ARROW}</div><div class="accordion-content"><div class="terminal-wrapper" style="padding-top:0;border-top:none"><div class="terminal-window"><div class="terminal-header"><div class="mac-dots"><div class="dot red"></div><div class="dot yellow"></div><div class="dot green"></div></div><span class="terminal-title">Session Transcript</span></div><div class="terminal-body">${esc(text)}</div></div></div></div></div>`;
  // 结论横幅：状态 + 线路变化 + 一句话原因（打开弹窗 1 秒内抓住重点）
  const CON={success:["ok","✓ 切换成功"],verify_failed:["warn","! 命令已下发，验证未通过"],
    failed:["bad","✕ 切换失败"],skipped:["gray","— 未切换（条件不满足）"],
    cooldown_skip:["gray","— 未切换（冷却期内）"],running:["info","执行中…"]};
  const c=CON[l.status]||[l.status,l.status];
  const fromLine=(l.precheck_line||l.source_line||"").split(" ")[0]||"-";
  const toLine=l.status==="success"?(l.target_line||"-"):(l.status==="skipped"||l.status==="cooldown_skip"?fromLine:"-");
  let why=l.error||l.decision_note||"";
  why=why.replace(/^切换命令已下发，但/,"").replace(/，请检查命令块输出或改在验证命令块配置查询命令/,"").replace(/，可能路由未收敛或切换失败/,"");
  let h=`<div class="verdict ${c[0]}">
    <span class="verdict-tag">${c[1]}</span>
    <span class="verdict-route">${esc(fromLine)} → <b>${esc(toLine)}</b></span>
    <span class="verdict-why" title="${esc(l.error||l.decision_note||"")}">${esc(why)}</span></div>
  <div class="meta-grid">
    <div class="meta-item"><span class="meta-label">告警标题</span><span class="meta-value title">${esc(l.alarm_title)||"-"}</span></div>
    <div class="meta-item"><span class="meta-label">设备</span><span class="meta-value">${esc(l.device_name)||"-"}</span></div>
    <div class="meta-item"><span class="meta-label">耗时</span><span class="meta-value mono" style="font-size:13px;white-space:nowrap">${esc(l.started_at)} <span style="color:var(--text-muted)">→</span> ${esc((l.finished_at||"").slice(11))||"-"}${durTxt(l)}</span></div>
  </div>`;
  const SESS_IC='<svg viewBox="0 0 24 24" style="width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;vertical-align:-2px;margin-right:6px"><path d="M4 17l6-6-6-6"/><line x1="12" y1="19" x2="20" y2="19"/></svg>';
  const sessTerm=(title,text)=>{
    const lines=(text||"").split("\n"); const blocks=[]; let cur={name:"（起始）",buf:[]};
    lines.forEach(ln=>{
      const m=ln.match(/^###\s+(.+)$/);
      if(m){ if(cur.buf.join("\n").trim()||cur.name!=="（起始）")blocks.push(cur); cur={name:m[1].trim(),buf:[]}; }
      else cur.buf.push(ln);
    });
    blocks.push(cur);
    const hasMark=lines.some(ln=>/^###\s+/.test(ln));
    const real=blocks.filter(b=>b.buf.join("\n").trim()||(b.name!=="（起始）"));
    const body=real.map(b=>{
      const nm=b.name==="（起始）"?(hasMark?"登录握手":"完整会话"):b.name;
      return `<div class="sess-phase"><div class="sess-phase-hd">${SESS_IC}${esc(nm)}</div><pre class="sess-pre">${esc(b.buf.join("\n").replace(/^\n+/,"").replace(/\n+$/,""))}</pre></div>`;
    }).join("");
    return `<div class="accordion"><div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">${title}<span style="font-size:12px;color:var(--text-faint);font-weight:400;margin-left:8px">${real.length} 个阶段</span>${ARROW}</div><div class="accordion-content"><div class="sess-body">${body}</div></div></div>`;
  };
  let tl=[];try{tl=JSON.parse(l.timeline||"[]")}catch(e){}
  if(tl.length){
    const items=tl.filter(t=>!(t.kind=="info"&&!t.evh&&!t.ev&&/^(收到告警|命中站点)/.test(t.text)));
    h+=`<div class="tlx-card"><div class="tlx-title">执行过程</div><div class="tlx">`+
      items.map((t,idx)=>{
        const ic=TL_IC[t.kind]||TL_IC.info;
        const panel=(title,body,open,tip)=>`<details class="tlx-panel"${open?" open":""}><summary class="tlx-panel-hd"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>${title}${tip?`<span class="q" data-tip="${tip}">?</span>`:""}<span class="tlx-panel-arrow"><svg viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg></span></summary><div class="tlx-panel-bd">${body}</div></details>`;
        const termPre=x=>`<pre style="margin:0;background:#0f172a;color:#e2e8f0;font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;padding:12px 14px;border-radius:6px;max-height:280px;overflow:auto;white-space:pre-wrap;word-break:break-all;line-height:1.6">${esc(x)}</pre>`;
        const nested=(t.evh?panel("证据 · 线路体检",t.evh,t.kind=="bad","判定逻辑：故障线路=告警标题匹配站点线路关键字；再按规则阶梯顺序用目标线路关键字查询 AIOps（未忽略+未处理/处理中），第一条无活跃告警且配了本方向命令的目标即选中。")
          :(t.ev?panel(t.step?"命令回显":"证据",termPre(t.ev),t.kind=="bad"):""));
        return `<div class="tlx-item ${t.kind||""}">
          <div class="tlx-ic"><div class="tlx-dot">${ic}</div>${idx<items.length-1?'<div class="tlx-line"></div>':''}</div>
          <div class="tlx-c"><div class="tlx-hd"><h4>${esc(t.text)}</h4><span class="tlx-ts">${esc((t.ts||"").slice(11))}</span></div>
          ${nested?'<div class="tlx-bd">'+nested+'</div>':''}</div></div>`}).join("")+`</div></div>`;}
  if(l.session_log)h+=sessTerm("会话原文",l.session_log);
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
function renderCoverage(){const o=$("cov_out");if(!o)return;
  if(!DATA.sites.length){o.innerHTML='<div class="empty">暂无站点</div>';return}
  o.innerHTML=DATA.sites.map(s=>{
    const ls=DATA.lines.filter(l=>l.site_id==s.id);
    if(!ls.length)return `<div class="cov-site"><div class="cov-site-hd"><b>${esc(s.name)}</b><span class="cov-cnt gray">未维护线路</span></div>
      <div class="cov-none">该站点未配置线路，走动作关键词兼容匹配（无降级能力）</div></div>`;
    const acts=DATA.actions.filter(a=>a.site_id==s.id&&a.enabled);
    let tgMap={};acts.forEach(a=>{let arr=[];try{arr=a.targets_json?JSON.parse(a.targets_json):[]}catch(e){}
      if(!arr.length&&a.target_line)arr=[{line:a.target_line,command_block:a.command_block}];
      arr.forEach(t=>{if(!tgMap[t.line])tgMap[t.line]=a.name})});
    const done=ls.filter(l=>tgMap[l.name]).length;
    const chips=ls.map(l=>tgMap[l.name]
      ?`<span class="cov-chip ok" title="规则「${esc(tgMap[l.name])}」已含该目标">${esc(l.name)}</span>`
      :`<span class="cov-chip bad" title="没有规则包含「切到${esc(l.name)}」，点此追加到规则阶梯" onclick="newActionFor(${s.id},${l.id})">${esc(l.name)} 缺规则</span>`).join("");
    const ladders=acts.map(a=>{let arr=[];try{arr=a.targets_json?JSON.parse(a.targets_json):[]}catch(e){}
      if(!arr.length&&a.target_line)arr=[{line:a.target_line,command_block:a.command_block}];
      if(!arr.length)return '';
      const steps=arr.map((t,i)=>`${i>0?'<span class="ladder-arrow">→</span>':''}<span class="ladder-step${t.command_block?'':' miss'}" title="${t.command_block?'已配切换命令':'缺少本方向切换命令'}"><i>${i+1}</i>${esc(t.line)}</span>`).join("");
      return `<div class="ladder"><span class="ladder-name" title="${esc(a.name)}">${esc(a.name)}</span>${steps}</div>`}).join("");
    return `<div class="cov-site">
      <div class="cov-site-hd"><b>${esc(s.name)}</b>
        <span class="cov-cnt ${done===ls.length?"ok":"warn"}">覆盖 ${done}/${ls.length}</span></div>
      <div class="cov-lines">${chips}</div>
      ${ladders?'<div class="cov-ladders">'+ladders+'</div>':''}</div>`}).join("")}
function newActionFor(siteId,lineId){
  // 联动：站点已有规则 → 打开该规则编辑并把缺失线路追加到阶梯；否则新建规则预置该目标
  const ref=DATA.actions.find(a=>a.site_id==siteId&&a.enabled);
  if(ref){editAction(ref.id);
    const l=DATA.lines.find(x=>String(x.id)===String(lineId));
    if(l&&!TGT.some(t=>t.line===l.name)){readTargetInputs();
      TGT.push({line:l.name,command_block:"",verify_block:"display ip routing-table",
                expect_keywords:l.nexthop_ip||"",nexthop:l.nexthop_ip||"",_lineId:l.id});
      renderTargets();
      showToast("已把「"+l.name+"」追加为优先级 "+TGT.length+" 的目标，请补填该方向切换命令后保存")}
    return}
  editAction(0);
  $("a_site").value=siteId;refreshActionLines();
  const l=DATA.lines.find(x=>String(x.id)===String(lineId));if(!l)return;
  $("a_name").value="切到"+l.name;
  TGT=[{line:l.name,command_block:"",verify_block:"display ip routing-table",
        expect_keywords:l.nexthop_ip||"",nexthop:l.nexthop_ip||"",_lineId:l.id}];
  renderTargets();
  $("mActTitle").textContent="新建切换规则（目标："+l.name+"）"}
function loadActions(){Promise.all([api("GET","/api/actions"),api("GET","/api/sites"),api("GET","/api/devices"),api("GET","/api/lines")]).then(([a,s,d,lines])=>{
  DATA.actions=a;DATA.sites=s;DATA.devices=d;DATA.lines=lines;
  $("acttb").innerHTML=a.length?a.map(x=>`<tr${x.enabled?"":" class='row-off'"}>
    <td><div class="status-cell"><div class="${x.enabled?"dot-green":"dot-red"}"></div>${x.enabled?"启用":"停用"}</div></td>
    <td><div class="device-info"><span class="device-name">${esc(x.name)}</span>
      <span class="device-host">${esc(x.site_name?x.site_name+" · ":"")}${esc(x.protocol||"")}://${esc(x.host||"")}</span></div></td>
    <td>${(()=>{let arr=[];try{arr=x.targets_json?JSON.parse(x.targets_json):[]}catch(e){}
      if(!arr.length&&x.target_line)arr=[{line:x.target_line,command_block:x.command_block}];
      return arr.length?arr.map((t,i)=>`<span class="tag ${t.command_block?'ok':'bad'}" style="margin:0 6px 2px 0"><b style="margin-right:3px">${i+1}.</b>${esc(t.line)}${t.command_block?'':'（缺命令）'}</span>`).join(''):'<span class="tag gray">未指定</span>'})()}</td>
    <td><span class="tag gray" style="margin-right:6px">${x.match_type=="regex"?"正则":"包含"}</span><span class="keyword-text">${esc(x.match_keywords)||'-'}</span></td>
    <td>${x.cooldown||"全局"}</td>
    <td><div class="ops-cell">
      <button class="btn btn-sm btn-secondary" onclick="execAction(${x.id})">执行</button>
      <button class="btn btn-sm btn-secondary" onclick="execAction(${x.id},true)">演练</button>
      <button class="btn btn-sm btn-secondary" onclick="editAction(${x.id})">编辑</button>
      <button class="btn btn-sm btn-secondary" onclick="copyAction(${x.id})">复制</button>
      <button class="btn btn-sm btn-danger" onclick="delAction(${x.id})">删除</button></div></td></tr>`).join(""):
    '<tr><td colspan=6><div class="empty"><svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>暂无切换规则</div></td></tr>';
  renderCoverage()})}
function fillSelect(sel,list,labelFirst){$(sel).innerHTML=`<option value="">(不选)</option>`+
  list.map(x=>`<option value="${x.id}">${esc(labelFirst?x.name:x.name+(x.host?" ("+x.host+")":""))}</option>`).join("")}
let TGT=[];
function siteLineList(){const sid=+$("a_site").value||0;return sid?DATA.lines.filter(l=>l.site_id==sid):[]}
function addTarget(lineId){const l=DATA.lines.find(x=>String(x.id)===String(lineId))||{};
  TGT.push({line:l.name||"",command_block:"",verify_block:"display ip routing-table",
            expect_keywords:l.nexthop_ip||"",nexthop:l.nexthop_ip||"",_lineId:l.id||""});
  renderTargets()}
function removeTarget(i){TGT.splice(i,1);renderTargets()}
function moveTarget(i,d){const j=i+d;if(j<0||j>=TGT.length)return;
  const t=TGT[i];TGT[i]=TGT[j];TGT[j]=t;renderTargets()}
function readTargetInputs(){TGT.forEach((t,i)=>{const g=document.querySelector('#tgt_box [data-i="'+i+'"]');if(!g)return;
  t.command_block=g.querySelector(".t_cmd").value;
  t.verify_block=g.querySelector(".t_verify").value;
  t.expect_keywords=g.querySelector(".t_expect").value})}
function usedLineIds(except){return TGT.filter((t,i)=>i!==except&&t._lineId).map(t=>t._lineId)}
function renderTargets(skipRead){if(!skipRead)readTargetInputs();
  const box=$("tgt_box");const ls=siteLineList();
  if(!ls.length){box.innerHTML='<div style="font-size:12px;color:var(--text-faint)">该站点未维护线路：请到「资源管理 → 站点管理 → 线路」添加后，即可为每条目标线路配置切换命令</div>';return}
  box.innerHTML=TGT.map((t,i)=>{
    const used=usedLineIds(i);
    const opts=ls.filter(l=>!used.includes(l.id)||String(l.id)===String(t._lineId))
      .map(l=>`<option value="${l.id}" ${String(l.id)===String(t._lineId)?"selected":""}>${esc(l.name)}${l.enabled?"":"（停用）"}</option>`).join("");
    return `<div data-i="${i}" style="border:1px solid var(--border);border-radius:8px;padding:10px 12px;background:#f8fafc">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <span style="font-size:12px;font-weight:600;color:var(--primary);background:var(--primary-bg);border-radius:12px;padding:2px 10px">优先级 ${i+1}</span>
        <select style="width:200px" onchange="targetLineChange(${i},this.value)">${opts}</select>
        <span style="font-size:12px;color:var(--text-muted)">${t.nexthop?("下一跳 "+esc(t.nexthop)):"（未配下一跳IP）"}</span>
        <span style="flex:1"></span>
        <button class="btn btn-sm btn-secondary" style="padding:2px 8px" ${i===0?"disabled":""} onclick="moveTarget(${i},-1)" title="上移（更优先）">↑</button>
        <button class="btn btn-sm btn-secondary" style="padding:2px 8px" ${i===TGT.length-1?"disabled":""} onclick="moveTarget(${i},1)" title="下移（更靠后）">↓</button>
        <button class="btn btn-sm btn-danger" style="padding:2px 8px" onclick="removeTarget(${i})">✕</button>
      </div>
      <label style="font-size:12px">切换命令块（每行一条，# 注释）</label>
      <textarea class="t_cmd" rows="5" placeholder="bgp 65000&#10; undo peer x.x.x.x&#10; peer y.y.y.y enable">${esc(t.command_block)}</textarea>
      <div class="grid2" style="margin-top:6px">
        <div><label style="font-size:12px">验证命令（可选）</label><input class="t_verify" value="${esc(t.verify_block)}"></div>
        <div><label style="font-size:12px">期望关键词（默认取下一跳IP）</label><input class="t_expect" value="${esc(t.expect_keywords)}"></div>
      </div></div>`}).join("")}
function targetLineChange(i,val){readTargetInputs();
  const l=DATA.lines.find(x=>String(x.id)===String(val));if(!l)return;
  TGT[i]._lineId=l.id;TGT[i].line=l.name;TGT[i].nexthop=l.nexthop_ip||"";
  if(!(TGT[i].expect_keywords||"").trim())TGT[i].expect_keywords=l.nexthop_ip||"";
  renderTargets()}
function refreshActionLines(){const sid=+$("a_site").value||0;
  const ls=sid?DATA.lines.filter(l=>l.site_id==sid):[];
  $("a_line").innerHTML=!sid?`<option value="">(请先选择所属站点)</option>`:
    `<option value="">${ls.length?"(选择故障线路自动填关键词)":"(该站点未维护线路，手动输入关键词)"}</option>`+
    ls.map(l=>`<option value="${l.id}">${esc(l.name)}${l.enabled?"":"（停用）"}</option>`).join("")+
    (ls.length?`<option value="__custom">自定义（手动输入关键词）</option>`:"")}
function onActionSiteChange(){refreshActionLines();$("a_line").value="";
  $("a_kw").readOnly=false;$("a_kw").value="";
  readTargetInputs();TGT=[];renderTargets()}
function onActionLineChange(){const v=$("a_line").value;
  if(!v||v=="__custom"){$("a_kw").readOnly=false;return}
  const l=DATA.lines.find(x=>String(x.id)===String(v));if(!l)return;
  $("a_kw").value=l.alarm_keywords||"";$("a_kw").readOnly=!!(l.alarm_keywords||"").trim()}
function targetsFromAction(a){
  const arr=(a.targets_json||"").trim()?JSON.parse(a.targets_json):null;
  if(arr&&arr.length)return arr.map(x=>({...x,_lineId:(DATA.lines.find(l=>l.site_id==a.site_id&&l.name===x.line)||{}).id||""}));
  if((a.target_line||"").trim()){
    const l=DATA.lines.find(x=>x.site_id==a.site_id&&x.name===a.target_line.trim())||{};
    return [{line:a.target_line.trim(),command_block:a.command_block||"",verify_block:a.verify_block||"",
             expect_keywords:a.expect_keywords||"",nexthop:l.nexthop_ip||"",_lineId:l.id||""}]}
  return []}
function editAction(id){const a=DATA.actions.find(x=>x.id==id)||{};
  fillSelect("a_site",DATA.sites);fillSelect("a_device",DATA.devices);
  $("a_id").value=a.id||"";$("a_name").value=a.name||"";$("a_site").value=a.site_id||"";
  $("a_device").value=a.device_id||"";$("a_mtype").value=a.match_type||"contains";
  refreshActionLines();
  let pre="";
  if(a.site_id){const kw=(a.match_keywords||"").trim();
    if(kw){const cands=DATA.lines.filter(l=>l.site_id==a.site_id&&(l.alarm_keywords||"").trim()==kw);
      if(cands.length==1)pre=String(cands[0].id)}}
  $("a_line").value=pre;
  const ml=pre?DATA.lines.find(x=>String(x.id)===pre):null;
  if(ml&&ml.alarm_keywords){$("a_kw").value=ml.alarm_keywords;$("a_kw").readOnly=true}
  else{$("a_kw").value=a.match_keywords||"";$("a_kw").readOnly=false}
  try{TGT=a.id?targetsFromAction(a):[]}catch(e){TGT=[]}
  $("a_rb").value=a.rollback_block||"";
  $("a_cd").value=a.cooldown||0;$("a_en").checked=!!a.enabled||!a.id;
  renderTargets(true);
  $("mActTitle").textContent=a.id?"编辑规则 #"+a.id:"新建切换规则";$("mAct").classList.add("show")}
function saveAction(){readTargetInputs();
  const b={id:$("a_id").value||null,name:$("a_name").value.trim(),
  site_id:$("a_site").value?+$("a_site").value:null,device_id:+$("a_device").value||null,
  match_type:$("a_mtype").value,match_keywords:$("a_kw").value.trim(),
  rollback_block:$("a_rb").value,cooldown:+$("a_cd").value||0,enabled:$("a_en").checked?1:0};
  const ts=TGT.filter(t=>t.line);
  if(!b.name||!b.device_id){showToast("规则名、目标设备必填",1);return}
  if(!ts.length){showToast("请至少添加一个目标线路（降级阶梯）",1);return}
  if(ts.some(t=>!(t.command_block||"").trim())){showToast("每个目标线路都必须填写切换命令块",1);return}
  b.targets_json=JSON.stringify(ts.map(t=>({line:t.line,command_block:t.command_block,
    verify_block:t.verify_block,expect_keywords:t.expect_keywords,nexthop:t.nexthop})));
  b.target_line=ts[0].line;b.command_block=ts[0].command_block;
  b.verify_block=ts[0].verify_block;b.expect_keywords=ts[0].expect_keywords;
  const siteHasLines=b.site_id&&DATA.lines.some(l=>l.site_id==b.site_id);
  if(!siteHasLines&&!b.match_keywords){showToast("站点未维护线路时，匹配关键词必填",1);return}
  api(b.id?"PUT":"POST",b.id?"/api/actions/"+b.id:"/api/actions",b).then(()=>{
    closeM("mAct");showToast("切换规则已保存");loadActions()})}
function copyAction(id){const a=DATA.actions.find(x=>x.id==id);if(!a)return;
  editAction(id);$("a_id").value="";$("a_name").value=(a.name||"规则")+"-副本";
  $("mActTitle").textContent="复制规则 #"+id}
function delAction(id){if(confirm("确认删除动作 #"+id+"？"))api("DELETE","/api/actions/"+id).then(()=>{showToast("已删除");loadActions()})}
function actionTargets(x){let arr=[];try{arr=x.targets_json?JSON.parse(x.targets_json):[]}catch(e){}
  if(!arr.length&&x.target_line)arr=[{line:x.target_line,command_block:x.command_block}];return arr}
function execAction(id,dry){if(dry===false&&id===0)return;
  const x=DATA.actions.find(a=>a.id==id);const q=dry?"?dry_run=1":"";
  const go=tgt=>{api("POST","/api/exec/"+id+q,tgt?{target_line:tgt}:{}).then(r=>{
    showToast(r.executed?("已提交执行（任务 #"+r.task_id+"）"):("未执行："+r.skip_reason),!r.executed);
    loadLogs()}).catch(e=>showToast("提交失败: "+e.message,1))};
  const tgs=x?actionTargets(x):[];
  const dev=x?(x.protocol||"")+"://"+(x.host||""):"";
  if(tgs.length>1){
    const names=tgs.map((t,i)=>(i+1)+". "+t.line+(t.command_block?"":"（缺命令，不可选）")).join("\n");
    const pick=prompt("规则「"+x.name+"」设备 "+dev+"\n选择本次执行的目标线路（输入序号）：\n"+names,"1");
    if(pick===null)return;
    const n=parseInt(pick||"1",10);const t=tgs[n-1];
    if(!t)return showToast("无效序号",1);
    if(!t.command_block)return showToast("该目标未配置切换命令",1);
    if(!confirm("确认对 "+dev+" 真实下发目标「"+t.line+"」的切换命令？"))return;
    go(t.line);return}
  const only=tgs[0]||{};
  if(!dry&&!confirm("确认对 "+dev+" 真实下发目标「"+(only.line||"默认")+"」的切换命令？"))return;
  go("")}

// ---- 设备 ----
let DEV_KW="";
function loadDevices(){api("GET","/api/devices").then(d=>{DATA.devices=d;
  if(DEV_KW){const k=DEV_KW.toLowerCase();d=d.filter(x=>((x.name||"")+(x.host||"")+(x.site_name||"")).toLowerCase().includes(k))}
  $("devtb").innerHTML=d.length?d.map(x=>`<tr${x.enabled?"":" class='row-off'"}>
    <td><div class="status-cell"><div class="${x.enabled?"dot-green":"dot-red"}"></div>${x.enabled?"启用":"停用"}</div></td>
    <td><div class="device-info"><span class="device-name">${esc(x.name)}</span>
      <span class="device-host mono">${esc(x.host)}:${x.port}</span></div></td>
    <td>${esc(x.site_name||"-")}</td><td><span class="tag gray">${x.protocol}</span></td>
    <td>${esc(x.username)}</td><td>${x.timeout}s</td>
    <td><div class="ops-cell">
      <button class="btn btn-sm btn-secondary" onclick="testDeviceById(${x.id})">测试</button>
      <button class="btn btn-sm btn-secondary" onclick="testDeviceByIdStatus(${x.id})">查线路</button>
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
let SITE_KW="";
function loadSites(){Promise.all([api("GET","/api/sites"),api("GET","/api/lines")]).then(([s,lines])=>{
  DATA.sites=s;DATA.lines=lines;
  if(SITE_KW){const k=SITE_KW.toLowerCase();
    s=s.filter(x=>((x.name||"")+(x.remark||"")).toLowerCase().includes(k)||lines.some(l=>l.site_id==x.id&&(l.name||"").toLowerCase().includes(k)))}
  $("sitetb").innerHTML=s.length?s.map(x=>{
    const ls=lines.filter(l=>l.site_id==x.id);
    return `<tr>
    <td><span class="device-name">${esc(x.name)}</span><div class="device-host mono">#${x.id}</div></td>
    <td>${ls.length?ls.map(l=>`<span class="tag ok" style="margin:0 6px 4px 0">${esc(l.name)}</span>`).join(""):'<span style="color:var(--text-faint)">未配置</span>'}</td>
    <td style="color:var(--text-muted);max-width:200px" class="cell1"><span title="${esc(x.remark)}">${esc(x.remark)||"-"}</span></td>
    <td><div class="ops-cell"><button class="btn btn-sm btn-secondary" onclick="editSite(${x.id})">编辑</button>
    <button class="btn btn-sm btn-secondary" onclick="manageLines(${x.id})">线路</button>
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
function manageLines(siteId){const s=(DATA.sites||[]).find(x=>x.id==siteId)||{};
  $("l_site").value=siteId;
  $("mLineTitle").textContent="站点线路 · "+(s.name||"");
  $("l_name").value="";$("l_kw").value="";$("l_ip").value="";
  loadLines(siteId);$("mLine").classList.add("show")}
function loadLines(siteId){api("GET","/api/lines?site_id="+siteId).then(ls=>{
  DATA.lines=DATA.lines.filter(l=>l.site_id!=siteId).concat(ls);
  $("ltb").innerHTML=ls.length?ls.map(l=>`<tr>
    <td><b>${esc(l.name)}</b></td><td><span class="keyword-text mono" style="color:var(--text-muted)">${esc(l.alarm_keywords)||'(空)'}</span></td>
    <td class="mono" style="color:var(--text-muted)">${esc(l.nexthop_ip)||'-'}</td>
    <td><div class="status-cell"><div class="${l.enabled?"dot-green":"dot-red"}"></div>${l.enabled?"启用":"停用"}</div></td>
    <td><div class="ops-cell"><button class="btn btn-sm btn-danger" onclick="delLine(${l.id})">删除</button></div></td></tr>`).join(""):
    '<tr><td colspan=5><div class="empty">暂无线路</div></td></tr>'})}
function addLine(){const b={site_id:+$("l_site").value,name:$("l_name").value.trim(),
  alarm_keywords:$("l_kw").value.trim(),nexthop_ip:$("l_ip").value.trim()};
  if(!b.name)return showToast("线路名必填",1);
  api("POST","/api/lines",b).then(()=>{$("l_name").value="";$("l_kw").value="";$("l_ip").value="";
    showToast("线路已添加");loadLines(b.site_id);loadSites()})}
function delLine(id){if(!confirm("删除该线路？"))return;
  api("DELETE","/api/lines/"+id).then(()=>{loadLines(+$("l_site").value);loadSites()})}

// ---- 设置 ----
function loadCfg(){api("GET","/api/config").then(c=>{
  $("s_pwd").value="";$("s_token").value="";$("s_cd").value=c.global_cooldown||0;
  $("s_aiops_url").value=c.aiops_url||"";$("s_aiops_tok").value="";
  $("token_hint").textContent=c.api_token_masked?("当前："+c.api_token_masked):"未设置";
})}
function saveCfg(){const b={global_cooldown:+$("s_cd").value||0,
  aiops_url:$("s_aiops_url").value.trim()};
  if($("s_token").value.trim())b.api_token=$("s_token").value.trim();
  if($("s_pwd").value)b.web_password=$("s_pwd").value;
  if($("s_aiops_tok").value)b.aiops_token=$("s_aiops_tok").value.trim();
  api("POST","/api/config",b).then(()=>showToast("设置已保存"))}

// ---- 匹配预检 / 回放 ----
const _STEP_TXT={fault:"故障线路，排除",active:"有活跃告警，不可选",clear:"无活跃告警，可选",
  no_cmd:"健康但未配本方向切换命令",no_action:"无活跃告警，但缺切换动作",no_keyword:"未配告警关键字",query_error:"查询失败",
  legacy:"站点未配线路，走动作匹配"};
function matchTest(){const t=$("mt_title").value.trim();if(!t)return;
  api("POST","/api/match/test",{title:t}).then(r=>{
    const o=$("mt_out");const p=r.plan;
    let h="";
    if(p&&p.error){h+=`<div class="hit-bad">降级预演失败：${esc(p.error)}</div>`}
    else if(p&&p.matched){
      const st=s=>`<span class="tag ${s.status=="clear"?"ok":(s.status=="fault"?"gray":(s.status=="active"||s.status=="no_cmd"?"bad":"warn"))}">${esc(_STEP_TXT[s.status]||s.status)}</span>`;
      h+=`<div style="border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin-bottom:12px">
        <div style="font-weight:600;margin-bottom:8px">降级预演：站点 ${esc(p.site||"-")} · 故障线路 ${esc((p.fault_lines||[]).join("、")||"-")}</div>
        ${(p.steps||[]).map(s=>`<div style="display:flex;gap:10px;align-items:center;padding:3px 0;font-size:13px">
          <span style="width:200px">${esc(s.line)}${s.action?`<span style="color:var(--text-faint);font-size:12px">（规则:${esc(s.action)}）</span>`:""}</span>
          <span style="color:var(--text-muted);flex:1">${s.status=="active"||s.status=="clear"||s.status=="no_cmd"?`未处理 ${s.pending} / 处理中 ${s.handling}`:""}</span>
          ${st(s)}</div>`).join("")}
        <div style="margin-top:8px;font-size:13px">${p.allow
          ? `<span class="tag ok">将执行切换</span> 规则「${esc(p.action_name||"")}」→ 目标线路 <b>${esc(p.target_line||"")}</b>`
          : `<span class="tag bad">不会切换</span> ${esc(p.reason||"")}`}</div>
      </div>`}
    if(r.hits&&r.hits.length){h+=r.hits.map(x=>x.error
      ?`<div class="hit-bad">规则 <b>${esc(x.action_name)}</b> 配置错误：${esc(x.reason)}</div>`
      :`<div class="hit-ok">命中动作 <b>${esc(x.action_name)}</b>（站点 ${esc(x.site||"-")} / 设备 ${esc(x.device?x.device.name:"-")} / ${x.command_lines} 条命令）</div>`).join("")}
    o.innerHTML=h||`<div class="hit-bad">未命中任何站点线路或动作</div>`})}
function replayRun(){const d=+$("rp_days").value;
  $("rp_out").innerHTML='<div style="color:var(--text-muted);padding:6px 0">正在拉取 AIOps 告警并回放，请稍候…</div>';
  api("POST","/api/match/replay",{days:d}).then(r=>{
    if(r.error){$("rp_out").innerHTML=`<div class="hit-bad">${esc(r.error)}</div>`;return}
    let h=`<div class="stat-grid" style="margin:6px 0 16px">
      <div class="stat-card"><div class="stat-ic"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg></div><div><b>${r.fetched}</b><span>回放标题数(去重前)</span></div></div>
      <div class="stat-card"><div class="stat-ic"><svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/></svg></div><div><b>${r.matched}</b><span>命中动作</span></div></div>
      <div class="stat-card"><div class="stat-ic"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg></div><div><b>${r.unmatched}</b><span>未命中</span></div></div>
      <div class="stat-card"><div class="stat-ic"><svg viewBox="0 0 24 24"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg></div><div><b>${r.unmatched_kinds}</b><span>未命中标题种类</span></div></div></div>`;
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
function boot(){buildSideNav("monitor");openPage("dash");setInterval(()=>{loadStats();loadLogs()},30000);
  const h=(location.hash||"").slice(1);
  if(PAGE_INFO[h])gotoGroup(PAGE_GROUP[h],h)}
api("GET","/api/session").then(()=>{boot()}).catch(()=>{$("loginBox").classList.add("show")});
document.addEventListener("keydown",e=>{if(e.key==="Escape"){
  const open=[...document.querySelectorAll(".modal.show")];
  if(open.length)open[open.length-1].classList.remove("show")}});
document.querySelectorAll(".modal").forEach(m=>{
  let downOnMask=false;
  m.addEventListener("mousedown",e=>{downOnMask=(e.target===m)});
  m.addEventListener("click",e=>{if(downOnMask&&e.target===m)m.classList.remove("show");downOnMask=false});
});
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
  function placeText(el,text){
    txt.textContent=text;tip.classList.add("show");
    const r=el.getBoundingClientRect(),tw=tip.offsetWidth,th=tip.offsetHeight,M=8;
    let left=r.left+r.width/2-tw/2,top=r.bottom+7,side="bottom";
    if(left<M)left=M;if(left+tw>window.innerWidth-M)left=window.innerWidth-M-tw;
    if(top+th>window.innerHeight-M){top=r.top-th-7;side="top";}
    tip.style.left=left+"px";tip.style.top=top+"px";
    const ax=r.left+r.width/2-left-5;
    arrow.style.left=Math.max(10,Math.min(ax,tw-20))+"px";
    if(side==="top"){arrow.style.top="auto";arrow.style.bottom="-5px"}else{arrow.style.top="-5px";arrow.style.bottom="auto"}
  }
  document.addEventListener("mouseover",e=>{
    const q=e.target.closest(".q");if(q&&q.dataset.tip){place(q);return}
    const c=e.target.closest("td.cell1");
    if(c&&c.scrollWidth>c.clientWidth+1)placeText(c,c.textContent.trim());
  });
  document.addEventListener("mouseout",e=>{if(e.target.closest(".q")||e.target.closest("td.cell1"))tip.classList.remove("show")});
  window.addEventListener("scroll",()=>tip.classList.remove("show"),true);
})();
</script>
</body>
</html>

"""


def recover_running():
    """进程重启后把残留的 running 执行记录标记为失败（B3）：
    否则冷却查询命中 running 会令该方向永久封锁，wait 也永远超时。"""
    conn = get_db()
    try:
        cur = conn.execute(
            "UPDATE exec_logs SET status='failed', error='服务重启，任务中断', finished_at=? "
            "WHERE status='running'", (now(),))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def main():
    init_db()
    n = recover_running()
    if n:
        print("[%s] 启动恢复：%d 条中断的 running 记录已标记为 failed" % (now(), n))
    if LS_SECRET == "axd-line-switch-default-secret":
        print("[%s] ⚠ 警告：LS_SECRET 仍为默认值，请在 .env 中设置独立密钥后重启" % now())
    _conn = get_db()
    try:
        if (kv_get(_conn, "web_password", "admin123") or "admin123") == "admin123":
            print("[%s] ⚠ 提醒：Web 登录密码仍为默认 admin123，请尽快在「全局设置」中修改" % now())
    finally:
        _conn.close()
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
