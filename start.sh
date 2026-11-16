#!/bin/bash
# Axd_Line_Switch 启动脚本: start.sh start|stop|restart|status (不带参数=前台运行)
DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$DIR/app.py"
PID_FILE="$DIR/lineswitch.pid"
LOG_FILE="$DIR/lineswitch.log"

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
