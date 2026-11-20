#!/usr/bin/env bash
# 在 Linux 服务器的项目目录执行：sudo ./install-systemd.sh
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SERVICE_NAME="axd-line-switch.service"
UNIT_FILE="/etc/systemd/system/$SERVICE_NAME"
PYTHON_BIN="$(command -v python3 || true)"
RUN_USER="${LS_SERVICE_USER:-${SUDO_USER:-$(id -un)}}"

fail() { printf '错误：%s\n' "$*" >&2; exit 1; }

[[ -n "$PYTHON_BIN" ]] || fail "找不到 python3"
id "$RUN_USER" >/dev/null 2>&1 || fail "运行用户 $RUN_USER 不存在"
[[ "$RUN_USER" != root ]] || fail "请通过 sudo 运行，或设置 LS_SERVICE_USER 为非 root 用户"
[[ "$APP_DIR" != *[[:space:]%]* && "$PYTHON_BIN" != *[[:space:]%]* ]] ||
  fail "项目或 Python 路径不能包含空格、百分号"

render_unit() {
    python3 - "$APP_DIR" "$PYTHON_BIN" "$RUN_USER" <<'PY'
import pathlib
import sys

app_dir, python_bin, run_user = sys.argv[1:]
template = pathlib.Path(app_dir, "deploy", "axd-line-switch.service.in").read_text()
print(template.replace("@APP_DIR@", app_dir)
              .replace("@PYTHON_BIN@", python_bin)
              .replace("@RUN_USER@", run_user), end="")
PY
}

if [[ "${1:-}" == "--dry-run" ]]; then
    render_unit
    exit 0
fi
[[ $# -eq 0 ]] || fail "用法：sudo ./install-systemd.sh [--dry-run]"
[[ "$(uname -s)" == Linux ]] || fail "请在运行本服务的 Linux 服务器上执行"
[[ "$(id -u)" -eq 0 ]] || fail "安装 systemd unit 需要 sudo"
command -v systemctl >/dev/null || fail "系统未安装 systemd/systemctl"
[[ -f "$APP_DIR/.env" ]] || fail "缺少 $APP_DIR/.env，请先从 .env.example 创建并配置"

if command -v runuser >/dev/null; then
    runuser -u "$RUN_USER" -- test -r "$APP_DIR/app.py" || fail "$RUN_USER 无法读取 app.py"
    runuser -u "$RUN_USER" -- test -r "$APP_DIR/.env" || fail "$RUN_USER 无法读取 .env"
    if ! grep -qE '^[[:space:]]*LS_DB=' "$APP_DIR/.env"; then
        runuser -u "$RUN_USER" -- test -w "$APP_DIR" ||
          fail "$RUN_USER 无法写入项目目录中的 SQLite 数据库"
    fi
fi

render_unit > "$UNIT_FILE"
chmod 644 "$UNIT_FILE"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# 首次迁移时停止 start.sh 创建的旧进程，避免两个实例争用监听端口。
PID_FILE="$APP_DIR/lineswitch.pid"
if ! systemctl is-active --quiet "$SERVICE_NAME" && [[ -f "$PID_FILE" ]]; then
    old_pid="$(cat "$PID_FILE")"
    if [[ "$old_pid" =~ ^[0-9]+$ ]] && kill -0 "$old_pid" 2>/dev/null; then
        old_args="$(ps -p "$old_pid" -o args= || true)"
        [[ "$old_args" == *"$APP_DIR/app.py"* ]] ||
          fail "PID 文件指向非本项目进程（PID $old_pid），请手动检查"
        kill -TERM "$old_pid"
        for _ in {1..30}; do
            kill -0 "$old_pid" 2>/dev/null || break
            sleep 1
        done
        kill -0 "$old_pid" 2>/dev/null && fail "旧进程未退出（PID $old_pid）"
    fi
    rm -f "$PID_FILE"
fi

if ! systemctl restart "$SERVICE_NAME"; then
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager >&2 || true
    fail "$SERVICE_NAME 启动失败"
fi
sleep 1
systemctl is-active --quiet "$SERVICE_NAME" || fail "$SERVICE_NAME 未保持运行"
printf '已启用并启动 %s（用户：%s）\n' "$SERVICE_NAME" "$RUN_USER"
printf '状态：systemctl status %s\n日志：journalctl -u %s -f\n' "$SERVICE_NAME" "$SERVICE_NAME"
