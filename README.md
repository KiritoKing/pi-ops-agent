<div align="center">

# Pi Ops Agent

**一个原生运行于 Linux/systemd、面向多机器与多账号的最小权限运维 Agent。**

[![CI](https://github.com/KiritoKing/pi-ops-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/KiritoKing/pi-ops-agent/actions/workflows/ci.yml)
![Linux](https://img.shields.io/badge/platform-Linux%20%2B%20systemd-blue)
![Deployment](https://img.shields.io/badge/deployment-native--only-blue)
![Go](https://img.shields.io/badge/Go-%3E%3D1.23-00ADD8)

</div>

Pi Ops Agent 使用 Pi Agent Harness 提供自然语言诊断和受控变更能力。模型始终运行在
非特权账户和无网络 bubblewrap 后面；跨机器访问经 mTLS server，root 能力只存在于
目标机的本地类型化 helper，审批在模型上下文之外完成。

## MVP 能力

- 一个中央 `agentd` 管理多台 systemd Linux 机器。
- 每台机器一个非 root `agentd-server`，管理多个 Target/Unix 账号。
- 多 Session；一个 Session 首次访问时原子绑定一个 Machine + Target，同一机器可有多个
  Session，每个 Session 独占可写 scratch workspace。
- 有界主机、进程、service、journal 和文件巡检。
- 类型化 change、写前备份、不可变计划、人类审批、验证与版本化回滚证据。
- TUI 是始终安装的本地入口；BotMux 等 IM 以独立 Adapter Plugin 后装。
- amd64/arm64 预构建 Release；目标机无需 Git、Node、npm、Go 或本地构建。

MVP 不包含 Docker、非 systemd 部署、任意远端 root shell、记忆/自进化、自动批准写
操作、多人审批和 controller HA。

## 架构

```mermaid
flowchart LR
  U["用户"] --> T["TUI"]
  U --> I["可选 Adapter Plugin"]
  T --> G["Client Gateway"]
  I --> G
  G -->|"prompt"| A["agentd / Pi Harness\n非 root"]
  G -->|"模型外审批"| P["Approval Router"]
  A -->|"HTTPS + JSON + mTLS"| S["agentd-server\n每机器一个，非 root"]
  P -->|"独立 approver principal"| S
  S -->|"Unix typed RPC"| R["root helper"]
  R --> T1["Target: hermes-agent"]
  R --> T2["Target: 其他账号/资源"]
```

`agentd-server` 的服务账户本身不需要拥有业务资源。Root helper 根据 root-owned policy
把 Target 映射到 UID/GID、路径、unit 和固定 recipe；“允许 root 操作”不等于 server
获得 root 或任意 shell。

详见[架构](docs/architecture.md)和[安全模型](docs/security-model.md)。

## 一条命令初始化

Pi Ops Agent 只提供原生 systemd 部署。PVE LXC 不需要 Docker：

```bash
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/main/scripts/install.sh \
  | sudo sh -s -- init
```

GitHub Raw 脚本只做平台探测、Release 下载和完整性校验；版本化 Release 安装器创建账号、
配置、systemd unit、模型 credential，启动核心并执行冒烟。目标机不会构建源码。

`init` 不安装或初始化 BotMux。完成后重新登录并进入 TUI：

```bash
ops-agent tui
```

BotMux 本体是外部依赖，不由 `init` 或插件包暗中联网安装。先按
[BotMux 官方文档](https://deepcoldy.github.io/botmux/)安装 `botmux`，随后直接向 Agent 发送：

```text
帮我安装 BotMux adapter
```

Agent 会查询可信插件目录、说明权限和包摘要、准备类型化安装计划，并等待管理员
`/approve <changeRef>`；Agent 自己不能审批或执行任意安装脚本。提交完成后，在同一个
交互式 TUI 输入精确命令 `/botmux-setup`：client 在模型外调用 BotMux 官方 setup、把
首个 bot 固定到 ops-agent wrapper、关闭开放私聊与 CLI 免审批绕过，再重启 BotMux。
Lark secret 只进入 BotMux 的终端交互，不进入模型、Agent transcript 或 argv。

固定 Tag、`.deb`、GitHub artifact attestation、PVE LXC 和后续机器 `join` 见
[部署文档](docs/deployment.md)。

## 权限与变更

有效能力取以下交集：

```text
Harness 固定工具
∩ Principal/Session 权限
∩ 已知 capability schema
∩ server capability
∩ root-owned policy
```

模型不能传 endpoint、证书、UID、`runAs`、任意宿主路径或 root argv。所有写操作遵循：

```text
PREPARED -> APPROVED -> EXECUTING -> COMMITTED
     |                        |
     +-> REJECTED/EXPIRED     +-> ROLLED_BACK/RECOVERY_REQUIRED
```

审批绑定 server、machine、Target、change、plan hash、policy/capability revision、前置条件、
期限和 nonce。连接中断后只查询原 change，不能重放 mutation。

## 目录

```text
src/             TypeScript Harness、Session、Client Gateway 与共享协议
cmd/             Go 命令薄入口
internal/        server、root helper、策略、备份、审计与恢复
plugins/         Adapter manifest；MVP 首个为 adapter-botmux
integrations/    Adapter runtime
systemd/         原生 systemd unit 与 tmpfiles
scripts/         Raw bootstrap、Release 安装、健康与卸载
packaging/       可复现原生 Release、Debian 与插件打包
docs/            架构、安全、部署和运维事实
```

## 开发验证

本地开发仍需仓库工具链，但它与目标机部署无关：

```bash
npm ci
npm run check
npm run build
go vet ./cmd/... ./internal/...
go test -race ./internal/...
git diff --check
```

Linux 发布前还需验证 systemd unit、bubblewrap、干净 systemd VM/LXC、enrollment、真实模型和
Adapter 端到端。不能通过关闭 sandbox、放宽 UID/路径策略或跳过审批制造通过结果。

## 文档

- [架构与领域模型](docs/architecture.md)
- [安全模型](docs/security-model.md)
- [原生部署与接入](docs/deployment.md)
- [升级、审计与恢复](docs/operations.md)
