#!/usr/bin/env python3
"""回调接收记录：未命中也可追踪，预检不落库，响应字段一致。"""
import json
import os
import sqlite3
import sys
import tempfile
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
with tempfile.TemporaryDirectory() as tmp:
    os.environ["LS_DB"] = os.path.join(tmp, "alert_receipts.db")
    import app  # noqa: E402

    app.init_db()
    conn = app.get_db()
    token = app.kv_get(conn, "api_token")
    conn.execute("INSERT INTO sites(name) VALUES('测试站点')")
    conn.execute("INSERT INTO lines(site_id,name,alarm_keywords,enabled) "
                 "VALUES(1,'4G','测试站点-4G',1)")
    conn.commit()
    conn.close()

    server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    root = "http://127.0.0.1:%d" % server.server_port

    def call(method, path, body=None, extra_headers=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"X-API-Token": token, "Content-Type": "application/json"}
        headers.update(extra_headers or {})
        req = Request(root + path, data=data, method=method,
                      headers=headers)
        with urlopen(req, timeout=5) as response:
            return response.status, json.load(response)

    try:
        code, unmatched = call("POST", "/api/alert", {"title": "测试用告警，无需处理"},
                               {"User-Agent": "AIOps/1.0"})
        assert code == 200
        assert unmatched["matched"] is False and unmatched["rule_matched"] is False
        assert unmatched["executed"] is False
        assert unmatched["task_id"] is None and unmatched["result"]["status"] == "skipped"
        assert unmatched["skip_reason_code"] == "unmatched"

        code, only_line = call("POST", "/api/alert", {"title": "测试站点-4G 中断"})
        assert code == 200 and only_line["matched"] is True
        assert only_line["rule_matched"] is False
        assert only_line["executed"] is False and only_line["result"]["status"] == "skipped"
        _, logs = call("GET", "/api/logs")
        assert len(logs) == 1 and logs[0]["site_name"] == "测试站点"
        _, detail = call("GET", "/api/logs/%d" % logs[0]["id"])
        assert detail["site_name"] == "测试站点"

        _, listing = call("GET", "/api/alert-receipts?limit=1&page=1")
        assert listing["total"] == 2 and len(listing["items"]) == 1
        assert listing["items"][0]["title"] == "测试站点-4G 中断"
        _, api_receipts = call("GET", "/api/alert-receipts?source=api")
        assert api_receipts["total"] == 2
        assert next(r for r in api_receipts["items"] if r["title"] == unmatched["title"])["user_agent"] == "AIOps/1.0"
        _, filtered = call("GET", "/api/alert-receipts?rule_matched=0&q=%E6%97%A0%E9%9C%80")
        assert filtered["total"] == 1
        assert filtered["items"][0]["title"] == unmatched["title"]
        assert json.loads(filtered["items"][0]["response_json"])["result"]["status"] == "skipped"

        call("POST", "/api/match/test", {"title": "测试用告警，无需处理"})
        _, listing = call("GET", "/api/alert-receipts")
        assert listing["total"] == 2
        conn = app.get_db()
        assert conn.execute("SELECT COUNT(*) FROM exec_logs").fetchone()[0] == 1
        conn.close()

        try:
            call("POST", "/api/alert", {"title": ""})
            raise AssertionError("空标题应返回 400")
        except HTTPError as error:
            assert error.code == 400
        _, listing = call("GET", "/api/alert-receipts")
        assert listing["total"] == 2

        # 有效规则命中时，接收记录立即可见；执行结果由关联任务实时更新。
        conn = app.get_db()
        conn.execute("INSERT INTO sites(name) VALUES('旧站')")
        conn.execute("INSERT INTO devices(site_id,name,host,enabled) VALUES(2,'模拟设备','127.0.0.1',1)")
        conn.execute("INSERT INTO actions(site_id,name,device_id,match_type,match_keywords,"
                     "command_block,enabled) VALUES(2,'旧规则',1,'contains','旧站线路告警','display version',1)")
        conn.commit()
        conn.close()
        _, queued = call("POST", "/api/alert", {"title": "旧站线路告警", "wait": 0})
        assert queued["matched"] and queued["rule_matched"] and queued["executed"]
        assert queued["task_id"] and queued["result"]["status"] == "running"
        _, matched = call("GET", "/api/alert-receipts?rule_matched=1")
        assert matched["total"] == 1 and matched["items"][0]["task_status"] == "running"
        conn = app.get_db()
        conn.execute("UPDATE exec_logs SET status='success' WHERE id=?", (queued["task_id"],))
        conn.commit()
        conn.close()
        _, matched = call("GET", "/api/alert-receipts?rule_matched=1")
        assert matched["items"][0]["task_status"] == "success"

        # API Token 不能伪装成页面调试；只有 Web 会话提交的调试标记才被采信。
        call("POST", "/api/alert", {"title": "外部标记调试", "source": "debug"})
        _, api_receipts = call("GET", "/api/alert-receipts?source=api")
        assert api_receipts["total"] == 4
        login = Request(root + "/api/login", method="POST",
                        data=json.dumps({"password": "admin123"}).encode(),
                        headers={"Content-Type": "application/json"})
        with urlopen(login, timeout=5) as response:
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        call("POST", "/api/alert", {"title": "测试站点-4G 中断", "source": "debug"},
             {"Cookie": cookie, "User-Agent": "Browser-Debug/1.0"})
        _, debug_receipts = call("GET", "/api/alert-receipts?source=debug")
        assert debug_receipts["total"] == 1
        assert debug_receipts["items"][0]["user_agent"] == "Browser-Debug/1.0"
        _, logs = call("GET", "/api/logs")
        assert logs[0]["trigger"] == "debug" and logs[0]["site_name"] == "测试站点"
        print("PASS 告警接收：未命中入库、响应统一、筛选分页、预检不入库")
    finally:
        server.shutdown()
        server.server_close()

    # 升级旧库时，从当时保存的判定时间线恢复无关联动作的站点。
    app.LS_DB = os.path.join(tmp, "legacy.db")
    old = sqlite3.connect(app.LS_DB)
    old.execute("CREATE TABLE exec_logs(id INTEGER PRIMARY KEY, action_id INTEGER, device_id INTEGER, "
                "timeline TEXT, decision_note TEXT, error TEXT)")
    old.execute("INSERT INTO exec_logs(action_id,timeline) VALUES(NULL,?)",
                (json.dumps([{"text": "命中站点「拉米卡」；故障线路：4G线路"}], ensure_ascii=False),))
    old.execute("CREATE TABLE alert_receipts(id INTEGER PRIMARY KEY, received_at TEXT, "
                "title TEXT, matched INTEGER, executed INTEGER, task_id INTEGER, "
                "action_name TEXT, reason TEXT, response_json TEXT)")
    old.execute("INSERT INTO alert_receipts(received_at,title,response_json) "
                "VALUES('2026-11-19 20:00:00','旧回调','{}')")
    old.commit()
    old.close()
    app.init_db()
    check = app.get_db()
    assert check.execute("SELECT site_name FROM exec_logs WHERE id=1").fetchone()[0] == "拉米卡"
    assert check.execute("SELECT source,user_agent FROM alert_receipts WHERE id=1").fetchone()[:] == ("unknown", "")
    check.close()
    print("PASS 执行记录站点：无动作跳过记录与旧库迁移均显示命中站点")
