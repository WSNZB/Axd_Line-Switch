#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""判定逻辑自测：站点线路互斥 + 当前线路条件 + 回显解析。
运行: python3 tests/test_decision.py
AIOps 接口用假数据注入，不依赖外网。"""
import os
import sys
import tempfile
import threading

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.environ["LS_DB"] = tempfile.mktemp(suffix="_test.db")
import app  # noqa: E402

app.init_db()
conn = app.get_db()
conn.execute("INSERT INTO sites(name) VALUES('华刚卢本')")
conn.execute("INSERT INTO sites(name) VALUES('未配线路站点')")
for name, kw, pri in [("Airtel", "41.243.21.170,Airtel", 1),
                      ("Vodacom", "41.243.21.170,Vodacom", 2),
                      ("4G", "41.243.21.170,4G", 3)]:
    conn.execute("INSERT INTO lines(site_id,name,alarm_keywords,priority,enabled) VALUES(1,?,?,?,1)",
                 (name, kw, pri))
conn.commit()

SITE1 = {"site_id": 1}
SITE2 = {"site_id": 2}
T_AIRTEL = "【ICMP中断】41.243.21.170-华刚卢本-Airtel"
T_VODA = "【ICMP中断】41.243.21.170-华刚卢本-Vodacom"


def fake_alarms(titles):
    """titles: 当前 AIOps 中"在告警"的告警标题集合；
    线路关键字(gs)命中任一标题 → 该线路有未处理告警。"""
    def q(conn, gs_kw):
        hit = [t for t in titles if all(w.lower() in t.lower() for w in gs_kw.split(",") if w.strip())]
        return {"pending": len(hit), "handling": 0, "titles": hit[:3],
                "requests": ["mock://?gs=" + gs_kw], "raw": "", "gs_label": gs_kw}
    app.query_line_active = q


def test_only_fault_line_active():
    fake_alarms([T_AIRTEL])
    allow, reason, d = app.judge_site_alarms(conn, T_AIRTEL, SITE1)
    assert allow, "仅故障线路告警时应放行，实际: %s" % reason
    assert d["fault_lines"] == ["Airtel"], d
    assert set(d["active_lines"]) == {"Airtel"}, d
    print("PASS 场景1 仅故障线路告警 → 放行（故障线路=Airtel）")


def test_multi_lines_active():
    fake_alarms([T_AIRTEL, T_VODA])
    allow, reason, d = app.judge_site_alarms(conn, T_AIRTEL, SITE1)
    assert not allow, "两条线路同时告警应拦截"
    assert "其它线路同时告警" in reason, reason
    print("PASS 场景2 Airtel+Vodacom 同时告警 → 拦截: %s" % reason)


def test_other_line_active():
    # 只有目标线路 Vodacom 在告警（标题本身不匹配任何线路的场景由场景3覆盖）
    fake_alarms([T_VODA])
    allow, reason, d = app.judge_site_alarms(conn, T_AIRTEL, SITE1)
    assert not allow, "其它线路也在告警时应拦截"
    assert "其它线路同时告警" in reason, reason
    print("PASS 场景3 除故障线路外还有线路告警 → 拦截: %s" % reason)


def test_title_no_line():
    fake_alarms([])
    allow, reason, _ = app.judge_site_alarms(conn, "【ESXi内存延迟过高】hk-esxi28", SITE1)
    assert not allow and "无法确认故障线路" in reason, reason
    print("PASS 场景4 标题匹配不到线路 → 拦截: %s" % reason)


def test_site_without_lines():
    allow, reason, d = app.judge_site_alarms(conn, "任意告警", SITE2)
    assert allow and "未配置线路" in d["note"], d
    print("PASS 场景5 站点未配置线路 → 放行（不做互斥判定）")


def test_aiops_error():
    def boom(*a, **k):
        raise RuntimeError("未配置 AIOps Token")
    app.query_line_active = boom
    allow, reason, d = app.judge_site_alarms(conn, T_AIRTEL, SITE1)
    assert allow and "查询失败" in d["note"], d
    print("PASS 场景6 AIOps 查询失败 → 放行并记录原因（避免完全不动作）")


def test_parse_current_line():
    out = """
Destination/Mask    Proto   Pre  Cost   Flags NextHop         Interface
   0.0.0.0/0        BGP     255  3      D    192.168.130.10          GigabitEthernet0/1
  127.0.0.0/8       Direct  0    0      D    127.0.0.1       InLoop0
192.168.130.0/24    Direct  0    0      D    192.168.130.5   GigabitEthernet0/1
"""
    lm = "192.168.130.2=Vodacom\n192.168.130.10=Airtel\n192.168.130.22=4G"
    assert app.parse_current_line(out, lm) == "Airtel"
    out4g = out.replace("192.168.130.10", "192.168.130.22")
    assert app.parse_current_line(out4g, lm) == "4G"
    assert app.parse_current_line(out, lm, r"0\.0\.0\.0.*?(\d+\.\d+\.\d+\.\d+)") == "Airtel"
    # 展示模式：命中映射 → "线路名 (IP)"；未命中 → 原始 IP
    assert app.parse_current_line(out, lm, with_ip=True) == "Airtel (192.168.130.10)"
    assert app.parse_current_line(out, "", with_ip=True) == "192.168.130.10"
    print("PASS 场景7 路由表解析当前线路（默认/自定义正则/展示带IP）")


def test_require_line_skip():
    """当前线路 ≠ 故障线路时不下发切换命令（mock 设备验证）"""
    import importlib.util
    spec = importlib.util.spec_from_file_location("mockdev", os.path.join(BASE, "tests/mock_telnet.py"))
    mock = importlib.util.module_from_spec(spec)
    old_argv = sys.argv
    sys.argv = ["mock", "12399"]
    try:
        spec.loader.exec_module(mock)
    finally:
        sys.argv = old_argv
    srv = mock.Server(("127.0.0.1", 12399), mock.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    conn.execute(
        "INSERT INTO devices(site_id,name,host,port,protocol,username,password_enc,timeout,"
        "status_command,enabled,created_at) VALUES(1,'m','127.0.0.1',12399,'telnet','admin',?,8,"
        "'display ip routing-table',1,'now')",
        (app.encrypt_pw("Mock@123"),))
    # 线路映射唯一维护处 = 站点线路（下一跳IP 字段）
    conn.execute("INSERT INTO lines(site_id,name,alarm_keywords,nexthop_ip,priority,enabled) "
                 "VALUES(1,'Airtel','Airtel','192.168.130.10',1,1)")
    conn.execute("INSERT INTO lines(site_id,name,alarm_keywords,nexthop_ip,priority,enabled) "
                 "VALUES(1,'4G','4G','192.168.130.22',2,1)")
    conn.commit()
    dev = conn.execute("SELECT * FROM devices WHERE id=1").fetchone()
    cur = conn.execute("INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,"
                       "status,source_line,started_at) VALUES(1,'x',1,'m','manual','running','Vodacom','now')")
    conn.commit()
    log_id = cur.lastrowid
    # 设备当前是 Airtel，故障线路是 Vodacom → 应跳过
    ok, err, note, precheck, verify_ok, skip = app._run_session(
        dev, conn, log_id, ["sys", "quit"], 0, None, None, require_line="Vodacom")
    assert skip and "无需切换" in skip, (skip, note)
    assert precheck == "Airtel", precheck
    rows = conn.execute("SELECT command FROM exec_steps WHERE log_id=?", (log_id,)).fetchall()
    assert all(r["command"].startswith("[线路查询]") for r in rows), \
        "跳过时只应有线路查询步骤，实际: %s" % [r["command"] for r in rows]
    print("PASS 场景8 当前线路(Airtel)≠故障线路(Vodacom) → 不下发命令，直接跳过")

    # 故障线路 = Airtel（当前就是 Airtel）→ 应执行
    cur2 = conn.execute("INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,"
                        "status,source_line,started_at) VALUES(1,'x',1,'m','manual','running','Airtel','now')")
    conn.commit()
    log2 = cur2.lastrowid
    ok, err, note, precheck, verify_ok, skip = app._run_session(
        dev, conn, log2, ["sys", "quit"], 0, None, None, require_line="Airtel")
    assert not skip and ok, (skip, err, note)
    cmds2 = [r["command"] for r in conn.execute("SELECT command FROM exec_steps WHERE log_id=? ORDER BY id", (log2,)).fetchall()]
    assert cmds2 == ["[线路查询] display ip routing-table", "sys", "quit"], cmds2
    print("PASS 场景9 当前线路(Airtel)=故障线路 → 正常下发 2 条命令")
    srv.shutdown()


def test_huawei_stelnet_prompt():
    """华为 stelnet 的密码提示是 'User Authentication'（非 Password:），登录逻辑须兼容。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location("mockdev2", os.path.join(BASE, "tests/mock_telnet.py"))
    mock = importlib.util.module_from_spec(spec)
    old_argv = sys.argv
    sys.argv = ["mock", "12398", "User Authentication"]
    try:
        spec.loader.exec_module(mock)
    finally:
        sys.argv = old_argv
    srv = mock.Server(("127.0.0.1", 12398), mock.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    conn.execute(
        "INSERT INTO devices(site_id,name,host,port,protocol,username,password_enc,timeout,enabled,created_at) "
        "VALUES(2,'huawei-ssh','127.0.0.1',12398,'telnet','admin',?,8,1,'now')",
        (app.encrypt_pw("Mock@123"),))
    conn.commit()
    dev = conn.execute("SELECT * FROM devices WHERE name='huawei-ssh'").fetchone()
    cur = conn.execute("INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,"
                       "status,started_at) VALUES(1,'x',?, 'huawei-ssh','manual','running','now')",
                       (dev["id"],))
    conn.commit()
    ok, err, note, precheck, verify_ok, skip = app._run_session(
        dev, conn, cur.lastrowid, ["display version"], 0, None, None)
    assert ok and not skip, (ok, skip, err, note)
    print("PASS 场景10 华为 stelnet 密码提示(User Authentication) 登录并执行命令")
    srv.shutdown()


if __name__ == "__main__":
    test_only_fault_line_active()
    test_multi_lines_active()
    test_other_line_active()
    test_title_no_line()
    test_site_without_lines()
    test_aiops_error()
    test_parse_current_line()
    test_require_line_skip()
    test_huawei_stelnet_prompt()
    print("\n全部判定逻辑测试通过")
