# Axd_Line_Switch (告警触发线路自动切换系统)

当 AIOps 平台产生告警时，根据告警标题自动匹配站点与线路方向，登录对应网络设备并按序下发预维护的切换命令，实现线路自动切换。**Python 标准库单文件实现，零第三方依赖**，适合内网生产环境直接部署。

---

## 工作流程

```
AIOps 告警 ──POST /api/alert {"title":"站点A-4G专线中断"}──▶ 本系统
                                                            │
                                            1. 按标题匹配"切换动作"
                                               (包含关键词 / 正则)
                                                            │
                                            2. 找到动作绑定的设备
                                               (站点 + telnet/ssh)
                                                            │
                                            3. 后台队列登录设备，逐条下发
                                               命令块(每条等提示符回归)
                                                            │
                                            4. 执行记录落库，Web 查看回显
```

- 命令块完全由 Web 端维护（如华为/H3C BGP AS-PATH 调整三方向命令），`#` 开头行为注释自动跳过；
- `quit/exit/logout` 类断开命令发送后不等待提示符；
- 同一动作有**冷却时间**（默认全局 300 秒）防止重复告警反复切换；**演练（dry-run）不受冷却限制**，只登录验证不下发命令；
- 所有执行任务**单线程串行**（切换操作不应并发）；同一告警标题命中多个动作时只执行第一个（按动作 ID 序）。

---

## 快速开始

```bash
cp .env.example .env && vi .env   # 修改 LS_SECRET 为随机串（用于设备密码加密）
chmod 600 .env
./start.sh start                  # 后台守护: 日志 lineswitch.log, pid lineswitch.pid
./start.sh status|stop|restart    # 其它命令；不带参数=前台运行
```

访问 `http://<服务器IP>:8090`，默认登录密码 `admin123`（登录后请在"全局设置"修改）。

## 配置告警回调

AIOps 告警动作中配置 HTTP 回调：

```
POST http://<本机IP>:8090/api/alert
Header:  X-API-Token: <在"全局设置"中查看>
Body:    {"title": "告警标题"}       # 兼容 alarm_title / name 字段；支持 dry_run:true 演练
```

响应示例：

```json
{"matched": true, "task_id": 5, "executed": true, "action": {"id": 1, "name": "切到4G"}}
{"matched": true, "task_id": null, "executed": false, "skip_reason": "冷却期内（300s）"}
{"matched": false, "title": "..."}
```

---

## Web 页面（五个页签）

| 页签 | 功能 |
|------|------|
| 执行记录 | 每次触发的告警标题/动作/设备/状态，点行查看每条命令回显 |
| 切换动作 | 匹配方式+关键词/正则、目标设备、切换命令块、回切命令块；一键"执行 / 演练 / 回切" |
| 设备管理 | telnet/ssh、账号密码（加密存储）、登录后初始命令、提示符正则、超时；"测试连接" |
| 站点管理 | 站点 CRUD |
| 全局设置 | Web 密码、API Token、全局冷却时间；告警回调在线测试 |

## API 一览

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/alert` | 告警入口（X-API-Token 鉴权） |
| GET | `/api/task/{id}` | 查任务状态（供回调方轮询） |
| POST/PUT/DELETE | `/api/actions[/{id}]` | 切换动作 CRUD |
| POST/PUT/DELETE | `/api/devices[/{id}]` | 设备 CRUD（密码留空=不修改） |
| POST/PUT/DELETE | `/api/sites[/{id}]` | 站点 CRUD |
| POST | `/api/exec/{action_id}` | 手动执行，`?dry_run=1` 演练、`?rollback=1` 回切 |
| POST | `/api/devices/{id}/test` | 设备连通测试 |
| GET | `/api/logs?limit=N`、`/api/logs/{id}` | 执行记录与详情 |

鉴权：Web 登录 Cookie 或 `X-API-Token` 请求头任一。

## 数据模型

```
sites(站点) ── devices(设备: host/protocol/账号/加密密码/init_command/提示符/超时)
            └─ actions(动作: 匹配方式+关键词、设备、command_block、rollback_block、冷却)
exec_logs / exec_steps  每次执行的日志与逐条命令回显
kv 全局设置(web_password / api_token / global_cooldown)
```

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `LS_PORT` | 8090 | 监听端口 |
| `LS_BIND` | 0.0.0.0 | 监听地址 |
| `LS_DB` | 程序目录/line_switch.db | SQLite 路径 |
| `LS_SECRET` | 内置默认值 | 设备密码加密主密钥（生产必改） |

## 本地自测

```bash
python3 tests/mock_telnet.py 12345   # 模拟华为设备 (admin / Mock@123)
LS_PORT=8090 python3 app.py          # Web 端建站点/设备(127.0.0.1:12345 telnet)/动作后触发
```

## 安全说明

- 设备密码以 `LS_SECRET` 派生密钥 HMAC 流加密落库，不出现在日志与接口返回中；SSH 登录密码经 pty 写入，不进进程列表与命令行。
- 切换命令不做白名单限制（按设计命令完全自定义），建议：上线前先用"演练"验证登录连通，再用"执行"生效；生产 `LS_SECRET` 务必修改。
