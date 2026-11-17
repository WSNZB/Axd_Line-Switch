#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""判定逻辑自测：多线路按优先级降级选目标 + 当前线路跳过 + 回显解析。
运行: python3 tests/test_decision.py
AIOps 接口用假数据注入，不依赖外网。

核心场景（对应现场三线路站点）：
  1) 仅故障线路告警 → 选下一条健康线路
  2) 前两条都告警 → 降级到第 3 条
  3) 三条全告警 → 不切换，任务结束
  4) 候选线路未配动作 → 跳过继续找下一条
  5) 当前生效线路就是目标线路 → 不下发命令
"""
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
conn.execute("INSERT INTO sites(name) VALUES('华刚卢本')")      # 1
conn.execute("INSERT INTO sites(name) VALUES('未配线路站点')")  # 2
for name, kw, pri, nh in [("Airtel", "41.243.21.170,Airtel", 1, "192.168.130.10"),
                          ("Vodacom", "41.243.21.170,Vodacom", 2, "1.1.1.1"),
                          ("4G", "41.243.21.170,4G", 3, "192.168.130.22")]:
    conn.execute("INSERT INTO lines(site_id,name,alarm_keywords,nexthop_ip,priority,enabled) "
                 "VALUES(1,?,?,?,?,1)", (name, kw, nh, pri))
# 每个"可切换到"的线路一个动作（命令块=全量状态，只依赖目标线路）
ACT = {}
for tgt in ("Airtel", "Vodacom", "4G"):
    cur = conn.execute(
        "INSERT INTO actions(site_id,name,device_id,match_type,match_keywords,command_block,"
        "verify_block,expect_keywords,target_line,cooldown,enabled) "
        "VALUES(1,?,1,'contains','41.243.21.170',?,?,?,?,0,1)",
        ("切到" + tgt, "display ip int brief", "display ip routing-table", "1.1.1.1", tgt))
    ACT[tgt] = cur.lastrowid
# 站点 2（未配线路）保留一个"故障→目标"的传统动作
conn.execute("INSERT INTO actions(site_id,name,device_id,match_type,match_keywords,command_block,"
             "target_line,cooldown,enabled) VALUES(2,'老动作',1,'contains','HK-ESXi','display ver','',0,1)")
conn.commit()

T_AIRTEL = "【ICMP中断】41.243.21.170-华刚卢本-Airtel"
T_VODA = "【ICMP中断】41.243.21.170-华刚卢本-Vodacom"
T_4G = "【ICMP中断】41.243.21.170-华刚卢本-4G"


def fake_alarms(titles):
    """titles: 当前 AIOps 中"在告警"的告警标题集合；
    线路关键字(gs)命中任一标题 → 该线路有活跃告警。"""
    def q(conn, gs_kw):
        hit = [t for t in titles if all(w.lower() in t.lower() for w in gs_kw.split(",") if w.strip())]
        return {"pending": len(hit), "handling": 0, "titles": hit[:3],
                "requests": ["mock://?gs=" + gs_kw], "raw": "", "gs_label": gs_kw}
    app.query_line_active = q


def steps_of(plan):
    return {s["line"]: s["status"] for s in plan["steps"]}


def test_only_fault_line_active():
    fake_alarms([T_AIRTEL])
    p = app.plan_switch(conn, T_AIRTEL)
    assert p["allow"] and p["target_line"] == "Vodacom", p
    assert p["fault_lines"] == ["Airtel"], p
    assert steps_of(p) == {"Airtel": "fault", "Vodacom": "clear"}, steps_of(p)
    assert p["action"]["id"] == ACT["Vodacom"], p["action"]
    print("PASS 场景1 仅故障线路(Airtel)告警 → 目标 Vodacom（priority 2）")


def test_degrade_to_third_line():
    fake_alarms([T_AIRTEL, T_VODA])
    p = app.plan_switch(conn, T_AIRTEL)
    assert p["allow"] and p["target_line"] == "4G", p
    assert steps_of(p) == {"Airtel": "fault", "Vodacom": "active", "4G": "clear"}, steps_of(p)
    assert p["action"]["id"] == ACT["4G"], p["action"]
    print("PASS 场景2 前两条(Airtel/Vodacom)均告警 → 降级切到 4G（priority 3）")


def test_all_lines_active():
    fake_alarms([T_AIRTEL, T_VODA, T_4G])
    p = app.plan_switch(conn, T_AIRTEL)
    assert not p["allow"], p
    assert "无可切换的健康线路" in p["reason"], p["reason"]
    print("PASS 场景3 三条线路全部告警 → 不切换：%s" % p["reason"])


def test_skip_candidate_without_action():
    """候选线路无对应动作 → 跳过并继续找下一条（用户确认的策略）"""
    fake_alarms([T_AIRTEL])
    conn.execute("UPDATE actions SET enabled=0 WHERE id=?", (ACT["Vodacom"],))
    conn.commit()
    p = app.plan_switch(conn, T_AIRTEL)
    assert p["allow"] and p["target_line"] == "4G", p
    assert steps_of(p)["Vodacom"] == "no_action", steps_of(p)
    print("PASS 场景4 Vodacom 无切换动作 → 跳过并继续，目标 4G")
    conn.execute("UPDATE actions SET enabled=1 WHERE id=?", (ACT["Vodacom"],))
    conn.commit()


def test_title_not_match_line():
    """标题命中动作关键词、但匹配不到站点任何线路关键字 → 提示检查线路配置，不切换"""
    fake_alarms([])
    p = app.plan_switch(conn, "【BGP邻居中断】41.243.21.170")
    assert p["matched"] and not p["allow"], p
    assert "未匹配到任何线路的告警关键字" in p["reason"], p["reason"]
    print("PASS 场景5 站点已配线路但标题不匹配线路 → 不切换：%s" % p["reason"])


def test_site_without_lines_legacy():
    fake_alarms([])
    p = app.plan_switch(conn, "【告警】HK-ESXi 宕机")
    assert p["matched"] and p["allow"] and p["legacy"], p
    assert p["action"]["name"] == "老动作", p["action"]
    print("PASS 场景6 站点未配线路 → 回退按动作关键词直接执行（兼容旧配置）")


def test_query_error_skipped():
    def boom(*a, **k):
        raise RuntimeError("未配置 AIOps Token")
    app.query_line_active = boom
    p = app.plan_switch(conn, T_AIRTEL)
    assert not p["allow"], p
    assert steps_of(p).get("Vodacom") == "query_error", steps_of(p)
    assert "无可切换的健康线路" in p["reason"], p["reason"]
    print("PASS 场景7 AIOps 查询失败 → 该线路按不可用跳过，无可切换时不下发")


def test_multi_site_conflict():
    """同一标题同时命中两个站点的线路 → 不切换（无法判定站点）"""
    fake_alarms([])
    conn.execute("INSERT INTO sites(name) VALUES('第二站点')")
    conn.execute("INSERT INTO lines(site_id,name,alarm_keywords,priority,enabled) "
                 "VALUES(3,'专线A','41.243.21.170,Airtel',1,1)")
    conn.commit()
    p = app.plan_switch(conn, T_AIRTEL)
    assert p["matched"] and not p["allow"] and "多个站点" in p["reason"], p
    print("PASS 场景8 标题同时命中两个站点线路 → 不切换：%s" % p["reason"])
    conn.execute("DELETE FROM lines WHERE site_id=3")
    conn.execute("DELETE FROM sites WHERE id=3")
    conn.commit()


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
    assert app.parse_current_line(out, lm, with_ip=True) == "Airtel (192.168.130.10)"
    assert app.parse_current_line(out, "", with_ip=True) == "192.168.130.10"
    print("PASS 场景9 路由表解析当前线路（默认/自定义正则/展示带IP）")


def test_target_line_skip():
    """当前线路 == 目标线路 → 不下发切换命令；不同 → 正常下发（mock 设备）"""
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
    conn.commit()
    dev = conn.execute("SELECT * FROM devices WHERE id=1").fetchone()

    # 设备当前是 Airtel，目标也是 Airtel → 跳过
    cur = conn.execute("INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,"
                       "status,source_line,target_line,started_at) "
                       "VALUES(1,'x',1,'m','api','running','Vodacom','Airtel','now')")
    conn.commit()
    log_id = cur.lastrowid
    ok, err, note, precheck, verify_ok, skip = app._run_session(
        dev, conn, log_id, ["sys", "quit"], 0, None, None, target_line="Airtel")
    assert skip and "已是目标线路" in skip, (skip, note)
    assert precheck == "Airtel", precheck
    rows = conn.execute("SELECT command FROM exec_steps WHERE log_id=?", (log_id,)).fetchall()
    assert all(r["command"].startswith("[线路查询]") for r in rows), \
        "跳过时只应有线路查询步骤，实际: %s" % [r["command"] for r in rows]
    print("PASS 场景10 当前线路(Airtel)=目标线路 → 不下发命令，直接跳过")

    # 设备当前是 Airtel，目标是 4G → 正常下发
    cur2 = conn.execute("INSERT INTO exec_logs(action_id,action_name,device_id,device_name,trigger,"
                        "status,source_line,target_line,started_at) "
                        "VALUES(1,'x',1,'m','api','running','Vodacom','4G','now')")
    conn.commit()
    log2 = cur2.lastrowid
    ok, err, note, precheck, verify_ok, skip = app._run_session(
        dev, conn, log2, ["sys", "quit"], 0, None, None, target_line="4G")
    assert not skip and ok, (skip, err, note)
    cmds2 = [r["command"] for r in conn.execute(
        "SELECT command FROM exec_steps WHERE log_id=? ORDER BY id", (log2,)).fetchall()]
    assert cmds2 == ["[线路查询] display ip routing-table", "sys", "quit"], cmds2
    print("PASS 场景11 当前线路(Airtel)≠目标线路(4G) → 正常下发 2 条命令")
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
    print("PASS 场景12 华为 stelnet 密码提示(User Authentication) 登录并执行命令")
    srv.shutdown()


if __name__ == "__main__":
    test_only_fault_line_active()
    test_degrade_to_third_line()
    test_all_lines_active()
    test_skip_candidate_without_action()
    test_title_not_match_line()
    test_site_without_lines_legacy()
    test_query_error_skipped()
    test_multi_site_conflict()
    test_parse_current_line()
    test_target_line_skip()
    test_huawei_stelnet_prompt()
    print("\n全部判定逻辑测试通过")
