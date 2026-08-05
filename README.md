# Pi Ops Agent

Pi Ops Agent 是一个面向 Linux 服务器和开发机的常驻运维 agent。它以 Pi 作为 agent harness，通过三个独立进程把“理解意图”“读取系统”“执行 root 变更”拆开，并为每次高权限变更保留审批、备份、验证和回滚证据。

当前是可部署的 MVP，默认模型路由为 `deepseek/deepseek-v4-flash`，仅支持 systemd Linux。它不把模型、消息桥、日志或命令输出当成安全边界；最终边界由独立账户、Unix peer credential、bubblewrap 和 root-helper 的类型化协议共同提供。

## 架构

| 进程 | 身份 | 职责 | 明确不能做 |
|---|---|---|---|
| `ops-agentd` | `ops-agent` | Pi 会话、模型路由、工具编排、agent 审计 | `sudo`、直接写系统目录、批准自己的变更 |
| `ops-systemd-helper` | root，强 systemd 沙箱 | 只读主机巡检、journal 查询、agentd 心跳与有界重启 | 任意 shell、业务文件变更、代理审批 |
| `ops-root-helper` | root，最小 RPC 面 | 准备不可变变更、备份、执行、验证、回滚 | 原始 root shell RPC、接受模型发出的审批 |
| `ops-agent` client | 审批账户 | Unix socket 客户端；本地截获审批命令；向继承的 FD 发布通用 `completion.v1` 事件 | 绕过 peer UID 校验、执行消息发送命令或读取 IM 凭据 |
| `ops-agent-botmux` adapter（可选） | 消息桥账户 | 包装 core client、消费事件并向当前会话回信 | 把 BotMux/飞书环境变量传给 core，或参与模型/高权限执行 |

详细数据流见 [架构文档](docs/architecture.md)，威胁和信任边界见 [安全模型](docs/security-model.md)。

## DeepSeek V4 Flash 路由

默认只使用一个低成本常驻模型，通过 thinking level 控制成本和推理深度：

| 路由 | 触发语义 | thinking | 权限含义 |
|---|---|---|---|
| R0 | 状态、健康、磁盘、负载、版本 | `low` | 只读，不因此获得写权限 |
| R1 | 日志、故障诊断、一般运维问题 | `high` 或 `medium` | 可读系统状态；写操作仍须走 R2 |
| R2 | 安装、更新、配置、重启、删除、回滚 | `high` | 只能准备变更；真实用户必须另发 `/approve <changeId>` |

模型定义位于 `config/models.json`。API key 不出现在 JSON、环境变量、命令行或仓库中；`ops-agentd.service` 只通过 `LoadCredentialEncrypted=` 获得 `deepseek_api_key`。如果供应商实际发布的 endpoint 或 model ID 不同，应同步修改 `models.json` 与 `agentd.json`，先做只读冒烟，禁止用别名静默回退到其他模型。

## 快速部署

在目标 Linux 主机上，以普通用户完成构建和测试：

```bash
npm ci
npm run check
npm run build
mkdir -p bin
go build -trimpath -o bin/ops-root-helper ./cmd/ops-root-helper
go build -trimpath -o bin/ops-systemd-helper ./cmd/ops-systemd-helper
```

再以 root 安装。`--approver-user` 必须是实际接收受信请求的本机审批账户，不能是 root 或 `ops-agent`：

```bash
sudo ./scripts/install.sh --approver-user "$USER"
sudo /opt/pi-ops-agent/scripts/encrypt-credential.sh
sudo systemctl start ops-agent.target
sudo systemctl start ops-agent-healthcheck.timer
sudo /opt/pi-ops-agent/scripts/healthcheck.sh
```

安装器把当前 Node 22.19+ 可执行文件复制到 `/opt/pi-ops-agent/runtime/node`，因此 systemd 不依赖登录 shell 中的 NVM/fnm。安装器还会把审批账户加入 `ops-agent` 组；该账户需重新登录或重启消息桥 service 才能获得新组。core CLI 是 `/opt/pi-ops-agent/bin/ops-agent`。BotMux 的 `cliPathOverride` 使用独立的 `/opt/pi-ops-agent/bin/ops-agent-botmux`；专用 PATH 中的 `/opt/pi-ops-agent/botmux-bin/pi` 只用于兼容其恢复命令，不会覆盖系统已有 `pi`。

本地冒烟：

```bash
/opt/pi-ops-agent/bin/ops-agent --session-id local-smoke-001
```

依次输入：

```text
只读检查这台机器的负载、磁盘和失败的 systemd units，不要修改任何东西
准备安装 jq，但不要执行，先给我变更计划
/status <changeId>
/reject <changeId>
```

确认备份和影响范围后，才用新的变更执行 `/approve <changeId>`。已提交或进入 `RECOVERY_REQUIRED` 且 root-helper 标记可回滚的变更，可由真实审批者执行 `/rollback <changeId>`。不要把 `/approve` 或 `/rollback` 写进自然语言 prompt；client 会在本地截获斜杠命令，并直接连接 root-helper。

完整安装、BotMux/飞书接入和验收步骤见 [部署文档](docs/deployment.md)，日常维护、恢复和卸载见 [运维手册](docs/operations.md)。

## 默认安全边界

- `ops_bash` 在无网络的 bubblewrap 中执行，唯一可写宿主路径是 agent workspace；命令黑名单仅用于提前拒绝，不是主安全边界。
- core 与消息桥通过继承的单向 FD 交换版本化 NDJSON 完成事件。core 不认识 BotMux/飞书，不接受任意 callback command，也不读取任何 IM 环境变量或 credential。
- 可选 BotMux adapter 位于 `integrations/botmux/`；它执行固定 argv 的 `botmux send`，正文经 64 KiB 限制和 0600 临时文件传递，并在启动 core 前删除 `BOTMUX_*`、`FEISHU_*`、`LARK_*` 环境变量。
- BotMux 外层文件 sandbox 必须关闭：其 Linux bwrap profile 会用私有 tmpfs 覆盖 `/run`，使 core client 看不到 agentd/root-helper socket。模型和工具仍在独立 `ops-agent` 账户的 agentd 中，命令继续受 agentd 内部 bubblewrap、systemd unit、Unix peer credential 和类型化 root-helper 约束。
- root-helper 使用 Unix `SO_PEERCRED` 区分 agent UID 与配置的审批 UID。模型能准备变更，但只有审批账户能批准或拒绝。
- 普通高权限操作是类型化 tagged union；不存在 raw root command RPC。
- break-glass 脚本默认关闭。启用时也必须绑定脚本摘要、显式备份路径、验证脚本和人工审批。
- agentd、root-helper 和 systemd-helper 分开记录 tamper-evident hash-chain 审计；链可检验事后改写，root 备份和 root 审计目录对 `ops-agent` 不可写。
- systemd 自身重启 helper；systemd-helper 监测 agentd heartbeat，并执行带冷却、窗口和次数上限的重启，避免无限拉起。

## 当前边界

- 仅支持 Linux/systemd/bubblewrap；macOS 和 Windows 不在部署范围内。
- 定时 `ops-agent-healthcheck.timer` 生成只读主机报告并写入 journal。把报告主动推送到飞书属于 BotMux 的消息路由职责。
- 默认 `file.write` 仅允许 `/etc` 和 `/opt`；用户家目录、SSH 凭据、内核、块设备和容器控制 socket 不在默认授权范围。
- 公网发布前仍应在一次性测试机上完成 package install、回滚、helper 崩溃恢复和 prompt injection 对抗测试。
