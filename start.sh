#!/bin/bash
# 兼容旧启动方式；安装 systemd 后，管理命令交给 systemctl。
DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$DIR/app.py"
PID_FILE="$DIR/lineswitch.pid"
LOG_FILE="$DIR/lineswitch.log"

if [ -f /etc/systemd/system/axd-line-switch.service ] && command -v systemctl >/dev/null 2>&1; then
    case "$1" in
        start|stop|restart|status) exec systemctl --no-pager "$1" axd-line-switch.service ;;
        "") echo "[lineswitch] 已由 systemd 管理，请使用 systemctl start|stop|restart|status axd-line-switch" >&2; exit 1 ;;
    esac
fi

# 可选: 载入同级 .env (KEY=VALUE)
if [ -f "$DIR/.env" ]; then
    set -a; source "$DIR/.env"; set +a
fi

is_running() {
    [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

start_daemon() {
    if is_running; then
        echo "[lineswitch] 已在运行 (PID $(cat "$PID_FILE"))"
        return 0
    fi
    echo "[lineswitch] 启动中..."
    nohup python3 "$APP" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 1
    if is_running; then
        echo "[lineswitch] 启动成功 (PID $(cat "$PID_FILE")), 日志: $LOG_FILE"
    else
        echo "[lineswitch] 启动失败, 查看日志: tail -50 $LOG_FILE"
        return 1
    fi
}

stop_daemon() {
    if is_running; then
        kill "$(cat "$PID_FILE")"
        rm -f "$PID_FILE"
        echo "[lineswitch] 已停止"
    else
        echo "[lineswitch] 未在运行"
        rm -f "$PID_FILE"
    fi
}

case "$1" in
    start)   start_daemon ;;
    stop)    stop_daemon ;;
    restart) stop_daemon; sleep 1; start_daemon ;;
    status)  if is_running; then echo "[lineswitch] 运行中 (PID $(cat "$PID_FILE"))"; else echo "[lineswitch] 未运行"; fi ;;
    "")      exec python3 "$APP" ;;
    *)       echo "用法: $0 {start|stop|restart|status}"; exit 1 ;;
esac
