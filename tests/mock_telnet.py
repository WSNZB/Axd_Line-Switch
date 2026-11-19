#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""模拟华为 VRP 设备的 telnet 服务端，用于本地端到端验证执行链路。
行为：telnet 协商 → Login:/Password: → <MockSW> 提示符；
带状态模拟：display ip routing-table 的 0.0.0.0/0 下一跳随切换命令变化，
display current-configuration 显示当前挂 route-policy import 的 peer。
可选第 2 参数：密码提示文本（模拟华为 stelnet 的 "User Authentication"）。"""
import socket
import socketserver
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 12345
PWD_PROMPT = sys.argv[2] if len(sys.argv) > 2 else "Password:"
RESPONSE_DELAY = float(sys.argv[3]) if len(sys.argv) > 3 else 0
USER = "admin"
PASS = "Mock@123"
PROMPT = "<MockSW>"

PEERS = ["192.168.130.2", "192.168.130.10", "192.168.130.22"]
POLICY = {"192.168.130.2": "vd", "192.168.130.10": "im", "192.168.130.22": "im4"}
CURRENT_NH = {"nh": "192.168.130.10"}   # 全局状态，跨连接保持（模拟真实设备）


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        current_nh = CURRENT_NH["nh"]
        s.sendall(bytes([255, 251, 1, 255, 251, 3, 255, 253, 24]) + "\r\nWelcome to Mock VRP\r\n".encode())

        def send(t):
            s.sendall(t.encode())

        def recv_line():
            buf = b""
            while True:
                d = s.recv(1024)
                if not d:
                    raise ConnectionError
                buf += d
                if b"\r" in buf or b"\n" in buf:
                    line = buf.decode("utf-8", "replace").strip()
                    print("[mock] 收到:", line)
                    return line

        send("Login:")
        if recv_line() != USER:
            send("Error: invalid user\r\n")
            return
        send(PWD_PROMPT)
        if recv_line() != PASS:
            send("Error: wrong password\r\n")
            return
        send("\r\n" + PROMPT + "\r\n")
        while True:
            line = recv_line()
            if line in ("quit", "exit"):
                send("Bye\r\n")
                return
            if "display ip routing-table" in line:
                if RESPONSE_DELAY:
                    time.sleep(RESPONSE_DELAY)
                out = ("Route Flags: R - relay, D - download to fib\r\n"
                       "------------------------------------------------------------------------------\r\n"
                       "Routing Tables: Public\r\n"
                       "Destinations : 9        Routes : 9\r\n\r\n"
                       "Destination/Mask    Proto   Pre  Cost   Flags NextHop         Interface\r\n\r\n"
                       "   0.0.0.0/0        BGP     255  3      D    %s          GigabitEthernet0/1\r\n"
                       "  127.0.0.0/8       Direct  0    0      D    127.0.0.1       InLoop0\r\n"
                       "192.168.130.0/24    Direct  0    0      D    192.168.130.5   GigabitEthernet0/1\r\n") % current_nh
                if line == "display ip routing-table":
                    # 整表查询模拟设备分页，客户端必须发送单个空格继续。
                    first, rest = out.split("  127.0.0.0/8", 1)
                    send(PROMPT + line + "\r\n" + first + "---- More ----")
                    if s.recv(1) != b" ":
                        return
                    send("\r\n  127.0.0.0/8" + rest + PROMPT + "\r\n")
                else:
                    send(PROMPT + line + "\r\n" + out + PROMPT + "\r\n")
            elif "display current-configuration" in line:
                peers = "".join(
                    "  peer %s route-policy %s import\r\n" % (p, POLICY[p])
                    for p in PEERS if p == current_nh)
                out = ("bgp 65320\r\n address-family ipv4 unicast\r\n"
                       + (peers or "  (no import policy peer)\r\n"))
                send(PROMPT + line + "\r\n" + out + PROMPT + "\r\n")
            else:
                # 切换命令: 模拟 peer X route-policy ... import 生效
                for p in PEERS:
                    if p in line and "peer" in line and "route-policy" in line and "undo" not in line:
                        current_nh = p
                        CURRENT_NH["nh"] = p
                out = "  Info: command '%s' executed ok on MockSW" % line
                send(PROMPT + line + "\r\n" + out + PROMPT + "\r\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    srv = Server(("127.0.0.1", PORT), Handler)
    print("[mock] telnet mock device on 127.0.0.1:%d (admin/Mock@123, 初始生效线路=Airtel)" % PORT)
    srv.serve_forever()
