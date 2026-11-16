#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""模拟华为 VRP 设备的 telnet 服务端，用于本地端到端验证执行链路。
行为：发送 telnet 协商垃圾字节 → Login: → Password: → <MockSW> 提示符，
收到命令回显 + 新提示符；screen-length 0 temporary 也能正常应答。"""
import socket
import socketserver
import threading
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 12345
USER = "admin"
PASS = "Mock@123"
PROMPT = "<MockSW>"

NEG = bytes([255, 251, 1, 255, 251, 3, 255, 253, 24])  # IAC WILL ECHO / WILL SGA / DO NAWS


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.sendall(NEG + "\r\nWelcome to Mock VRP\r\n".encode())

        def send(t):
            s.sendall(t.encode())

        def recv_line(expect_user):
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
        user = recv_line(True)
        if user != USER:
            send("Error: invalid user\r\nLogin:")
            return
        send("Password:")
        pw = recv_line(False)
        if pw != PASS:
            send("Error: wrong password\r\n")
            return
        send("\r\n" + PROMPT + "\r\n")
        while True:
            line = recv_line(False)
            if line in ("quit", "exit"):
                send("Bye\r\n")
                return
            # 模拟真实回显: 命令本身 + 输出 + 提示符
            out = "  Info: command '%s' executed ok on MockSW" % line
            send(PROMPT + line + "\r\n" + out + "\r\n" + PROMPT + "\r\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    srv = Server(("127.0.0.1", PORT), Handler)
    print("[mock] telnet mock device listening on 127.0.0.1:%d (user=%s pass=%s)" % (PORT, USER, PASS))
    srv.serve_forever()
