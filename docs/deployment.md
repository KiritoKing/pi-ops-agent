# 部署、BotMux 与飞书冒烟

## 前置条件

- systemd Linux；启用非特权 user namespace。
- Node.js 22.19+、Go 1.23+、bubblewrap、Git 和 npm。
- 一个专用的 BotMux 本机账户。该账户代表真实审批者，不能和 `ops-agent` 共用 UID，也不应使用 root。
- DeepSeek V4 Flash 可用的 OpenAI Chat Completions 兼容 endpoint 和 key。

先验证 bubblewrap 基础能力：

```bash
bwrap --unshare-all --die-with-parent --ro-bind /usr /usr --ro-bind /bin /bin --proc /proc --dev /dev /bin/true
```

若内核或企业安全策略禁止 user namespace，应修复宿主策略或改用 VM/container 作为更外层隔离；不要删掉 bwrap 或放宽 systemd unit 来“让测试通过”。

## 构建与安装

构建必须使用普通账户，避免以 root 执行 npm lifecycle。两只 Go helper 必须在目标 Linux 构建，或显式交叉编译成与目标匹配的 Linux ELF；安装器会在任何系统写入前验证格式和架构，拒绝把 macOS Mach-O/其他架构产物覆盖到服务：

```bash
npm ci
npm run check
npm run build
mkdir -p bin
go build -trimpath -o bin/ops-root-helper ./cmd/ops-root-helper
go build -trimpath -o bin/ops-systemd-helper ./cmd/ops-systemd-helper
```

安装器只复制已构建产物，不访问网络。以实际 BotMux 运行账户为审批账户：

```bash
sudo ./scripts/install.sh --approver-user botmux
sudo /opt/pi-ops-agent/scripts/encrypt-credential.sh
sudo systemctl start ops-agent.target ops-agent-healthcheck.timer
sudo /opt/pi-ops-agent/scripts/healthcheck.sh
```

安装后检查：

```bash
systemctl status ops-root-helper ops-systemd-helper ops-agentd --no-pager
systemd-analyze security ops-agentd.service ops-systemd-helper.service ops-root-helper.service
journalctl -u ops-agentd -u ops-systemd-helper -u ops-root-helper -n 100 --no-pager
```

## BotMux 接入

使用仓库中的可选 BotMux adapter 包装 core client。它是 `integrations/botmux/` 下的独立集成，不被 `src/` 中的 agent 核心 import。首次 spawn 的实际形式为：

```text
/opt/pi-ops-agent/bin/ops-agent-botmux --session-id <BotMux生成的UUID> '<initialPrompt>'
```

后续消息由 BotMux 在同一个 PTY 中用 bracketed paste 写入。session ID 由 adapter 生成并维护，不要在 `bots.json` 手写占位符。

把 `config/botmux.bots.json.example` 中的对象合并进 BotMux 账户的 `~/.botmux/bots.json`。最小关键配置如下：

```json
{
  "name": "ops-agent",
  "cliId": "pi",
    "cliPathOverride": "/opt/pi-ops-agent/bin/ops-agent-botmux",
  "defaultWorkingDir": "/var/lib/ops-agent/workspace",
  "allowedUsers": ["owner@example.com"],
  "p2pOpen": false,
  "disableCliBypass": true,
  "backendType": "tmux",
  "sandbox": false,
  "writableTerminalLinkInCard": false
}
```

这里的 `sandbox: false` 是必须配置，不是为了给模型放权。BotMux 的 Linux 文件 sandbox 会用私有 tmpfs 覆盖 `/run`，导致 core client 看不到 `/run/ops-agent/agentd/agentd.sock` 和 root-helper socket。模型实际运行在独立 `ops-agent` UID 的 `ops-agentd.service` 中；`ops_bash` 仍由 agentd 自己的离线 bubblewrap 约束，高权限操作仍只能通过 `SO_PEERCRED` 校验和类型化 root-helper 协议执行。不要用 BotMux `sandboxReadonlyPaths` 暴露 socket 来替代这套边界。

adapter 为 core 创建专用 FD 3。core 只写版本化 `completion.v1` NDJSON；adapter 读取事件、校验当前 session，再以固定 argv 和 0600 临时文件发送。adapter 会在 spawn core 前移除 `BOTMUX_*`、`FEISHU_*`、`LARK_*` 环境变量。不要改成 `OPS_AGENT_CALLBACK=<command>` 一类任意回调：这会把消息桥环境变成命令执行入口。接入其他 IM 时应新增 `integrations/<bridge>/` adapter，复用事件协议而不修改 core。

BotMux Pi adapter 对较长的首次 prompt 可能传入 `@<absolute-file>`；client 只会读取当前 UID 所有、非符号链接的普通文件，且上限为 64 KiB。adapter 在 durable/deferred 首次投递时还可能注入 `--extension <path>`，client 会接受并忽略该参数，不会加载或执行扩展。当前不实现 BotMux 的 deferred extension 命令语义；此兼容仅避免冷启动因未知参数退出，定时任务应优先续用已存在的 session，并在目标版本上做端到端验证。

不要配置 `allowedChatGroups`：当前语义会允许该群全员 talk，不符合审批者隔离要求。`allowedUsers` 可使用完整邮箱或确定的 `ou_xxx`，必须是真实 owner/canOperate 身份。

当前 BotMux Pi adapter 的 resume 命令会调用 PATH 中的 `pi --session-id ...`，只配置 `cliPathOverride` 不足以恢复旧会话。安装器提供 `/opt/pi-ops-agent/botmux-bin/pi`；启动 BotMux daemon 时必须把该目录放在 PATH 最前面。若 BotMux 由 systemd 托管，可基于 `config/botmux-systemd-dropin.conf` 添加 drop-in：

```ini
[Service]
SupplementaryGroups=ops-agent
Environment=PATH=/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NoNewPrivileges=yes
```

修改组或 drop-in 后必须重启 BotMux 服务；只在当前 shell 执行 `newgrp` 不会改变既有 daemon 的 supplementary groups。若使用 `botmux autostart enable`，不要再叠加另一套 PM2/user-systemd 守护；选择一种生命周期管理方式，并确认 daemon 实际继承了上述 PATH。

现有 bot 可先用 `botmux setup edit` 修改 CLI，再运行 `node /opt/pi-ops-agent/scripts/configure-botmux.mjs` 原子备份并收紧非密钥字段。脚本要求恰好一个 owner、零群聊，并只输出字段计数和备份路径，不回显 App Secret。

BotMux 初始化与核验：

```bash
botmux setup --no-open-platform-auto
# 合并 config/botmux.bots.json.example 到 ~/.botmux/bots.json
botmux setup list --json
botmux restart
botmux status
botmux logs --lines 150
```

`--no-open-platform-auto` 避免自动申请超出当前用途的飞书开放平台权限。

BotMux 侧必须满足：

1. daemon 的本机 `User=` 与安装时 `--approver-user` 完全一致，并通过 `SupplementaryGroups=ops-agent` 获得 socket 访问。
2. 飞书 `allowedUsers` 在 BotMux 层执行；不允许模型根据名字或消息正文判断身份。
3. `/approve`、`/rollback` 与 `/reject` 仅接受 allowlist 用户私聊。群消息、转发、机器人消息和定时任务不得发审批命令。
4. 每个 chat 最多一个在途 prompt；超时先发送 Ctrl-C/中止，再重启该 worker，不能并发写同一个 stdin。
5. 不把 DeepSeek key 交给 BotMux。BotMux 仅有飞书 connector credential 和两个 Unix socket 的组权限。
6. 交互回复由独立 adapter 调用固定参数的 `botmux send`；core 和 agentd 不查找 BotMux CLI，也不读取 BotMux 配置。

## 分阶段冒烟

### 1. 本地 client

以审批账户执行：

```bash
/opt/pi-ops-agent/bin/ops-agent --session-id local-smoke-001
```

输入只读请求，确认响应状态包含 `deepseek-v4-flash`，并检查三份 audit 均新增记录。随后准备一个 `package.install`，先 `/status` 再 `/reject`，确认没有宿主变更。

### 2. 恢复与边界

```bash
sudo systemctl kill --signal=SIGKILL ops-agentd.service
sleep 50
systemctl is-active ops-agentd.service
journalctl -u ops-systemd-helper -n 50 --no-pager
```

预期 systemd 或 watchdog 在限流范围内恢复 agentd，并记录原因。再要求模型执行 `sudo`、读取 `/root/.ssh`、访问 Docker socket或联网的 `ops_bash`；预期在 sandbox/协议层失败。

### 3. 飞书端到端

在 allowlist 私聊中依次发送：

```text
只读巡检这台机器，给出负载、磁盘、内存和失败 unit，不要做任何修改
准备安装 jq，但不要执行；列出备份、验证和回滚计划
/status <changeId>
/reject <changeId>
```

验收证据：飞书回复、BotMux message ID 与 session ID 映射、agentd route、root-helper `changeId/auditId`、`REJECTED` 终态。最后才在一次性测试包上验证 `/approve`、`COMMITTED`、`/rollback` 和 `ROLLED_BACK`。

## 定时巡检

`ops-agent-healthcheck.timer` 每 5 分钟运行无网络、只读检查，报告进入：

```bash
journalctl -u ops-agent-healthcheck.service --since today --no-pager
```

如需飞书主动推送，只允许 BotMux 账户读取最新报告，并对既有 session 调用：

```bash
botmux send --session-id <既有session> --no-mention --content-file <report.md>
```

也可显式使用 `--top-level --chat-id <oc_xxx>`。该命令需要读取 BotMux session data 和飞书 connector credential，因此不能由 `ops-agentd` 调用，也不能把 `bots.json` 或飞书 key 共享给 agentd。本 MVP 未实现跨 UID reporter；默认报告留在 journal，并在下一次会话中由用户要求摘要。定时任务不得带 `/approve`，也不得直接调用 root-helper mutation 方法。
