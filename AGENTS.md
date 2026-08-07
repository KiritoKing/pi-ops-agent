# Pi Ops Agent workspace rules

本文件面向在此仓库中工作的代码 Agent。先理解安全边界，再修改实现；“模型表现正常”不能替代协议校验、操作系统隔离或人工审批。

## 项目目标

Pi Ops Agent 是面向 Linux/systemd 的常驻运维 Agent。它必须同时满足：

1. 能完成通用只读诊断，并为受控的系统变更生成计划。
2. 不可信 prompt、模型、日志或 bridge 被控制后，不能自行获得或授权 root。
3. 每次高权限变更经 `agentd-root-broker` 完成审批绑定、备份、验证、审计和恢复证据。
4. Agent 核心与 BotMux、飞书及其他 IM bridge 实现解耦。

开始工作前，至少阅读与改动相关的设计文档：

- `docs/architecture.md`：进程、socket、身份与数据流。
- `docs/security-model.md`：信任边界、状态机、密钥和已知限制。
- `docs/deployment.md`：安装与集成约束。
- `docs/operations.md`：恢复、升级、审计与卸载语义。

## 不可破坏的安全边界

- `agentd`（当前 unit：`ops-agentd.service`）必须永久非特权运行。禁止调用 `sudo`、读取宿主 credential、直接写系统目录或执行 root 命令。
- 模型和 agentd UID 只能准备或查询变更，不能批准、拒绝或回滚。真实 client peer 的 UID 必须由 Unix `SO_PEERCRED` 校验。
- 所有普通 root 变更必须通过 `agentd-root-broker` 的版本化 tagged union。当前实现 artifact 为 `ops-root-helper`/`internal/roothelper`；禁止增加 raw root command、任意 argv、任意脚本或 shell callback RPC。
- `agentd-guard` 的目标边界是与 `agentd` 同 UID，只能校验固定进程身份并有界终止卡死的 agentd；当前 `ops-systemd-helper` 是 root 兼容层，只允许收缩，禁止继续扩大主机巡检、journal、unit 或 `systemctl` 范围。
- `/approve`、`/reject`、`/rollback`、`/status` 必须由 client 在模型上下文之外截获。不得把自然语言中的同名文本视为授权。
- `breakglass.script` 默认关闭。扩展它时仍须绑定脚本摘要、显式备份、验证计划、网络声明和人工审批。
- 写操作必须遵守 `PREPARED → APPROVED → EXECUTING → COMMITTED / ROLLED_BACK / RECOVERY_REQUIRED`。只有 `agentd-root-broker` 返回 `COMMITTED` 才能宣告成功。
- 不得为了让测试或部署通过而削弱 systemd hardening、bubblewrap namespace、路径 allowlist、peer UID 校验、速率限制或审计。
- 禁止提交 API key、IM credential、SSH 材料、生成的 systemd credential、运行时状态、备份或审计日志。

## 模块所有权与代码放置

| 路径 | 语言 | 职责与放置规则 |
|---|---|---|
| `src/agentd/` | TypeScript | Pi 会话、模型路由、工具编排、sandbox 和 Agent 审计。模型可见逻辑放这里，但不得拥有 root 能力 |
| `src/client/` | TypeScript | 交互、审批命令拦截、会话输出和通用完成事件。不得导入具体 IM SDK |
| `src/shared/` | TypeScript | 配置、framing、schema guard、脱敏、路由与通用 RPC。保持 transport 与厂商无关 |
| `cmd/` | Go | `agentd-server`、`agentd-root-broker` 和兼容 guard 的薄入口；只做参数解析、依赖装配和进程启动 |
| `internal/` | Go | `agentd-server`、`agentd-root-broker`、兼容 guard、peer credential、备份、验证和回滚；不对外形成通用 root API |
| `integrations/<bridge>/` | adapter 自选 | IM 或自动化桥接。包装 core client，消费版本化事件，并自行负责认证与投递 |
| `config/` | JSON / env 示例 | 可移植默认配置与示例；不能包含主机专用值或秘密 |
| `systemd/` | unit 文件 | 身份、目录、credential 和 hardening 边界 |
| `scripts/` | Bash | 安装、加密凭据、健康检查和卸载；保持幂等、fail-closed、目标明确 |
| `docs/` | Markdown | 架构、安全、部署和操作事实；安全语义变化必须同步更新 |
| `test/` | TypeScript | TS 单元测试；Go 测试与对应 `internal/` 包同目录 |

### 为什么这样分

- TypeScript 与 Pi SDK 同栈，负责高变化、非特权的模型和会话层。
- Go `agentd-root-broker` 是小型可信计算基，直接处理 Unix socket、文件权限和系统操作，并可交付独立二进制。
- `cmd/` 与 `internal/` 分离，避免入口膨胀或把特权能力变成可复用的通用库。
- bridge 位于 `integrations/`，确保核心只处理稳定事件协议，不接触 IM credential 或厂商会话语义。

## 跨语言协议规则

- TypeScript 与 Go 都必须对边界输入执行运行时校验；不能只依赖静态类型。
- 协议必须版本化、默认拒绝未知字段、限制帧大小并设置 deadline。
- 修改消息或操作类型时，同一变更中更新 `src/shared/`、`internal/protocol/`、相关 client/server/broker/guard、测试和文档。
- 不要用宽泛字符串、`Record<string, unknown>` 或 Go `map[string]any` 绕过 tagged union。边界数据先按 `unknown` 解码，再显式收窄。
- 错误响应和审计正文不得泄漏 secret、完整 credential 路径或未经脱敏的不可信大文本。

## 语言与实现约定

### TypeScript

- 保持 `strict`，禁止 `any`。未知数据使用 `unknown` 并通过 guard/schema 收窄。
- 保持 ESM 和现有模块边界；优先复用 `src/shared/` 中的 framing、guard、redaction 与 RPC helper。
- Agent tool 必须声明明确输入 schema、超时、输出上限和权限语义。
- `src/` 不得引用 BotMux、飞书、Lark 或任何具体 bridge 的包、环境变量与 credential。

### Go

- `agentd-root-broker` 必须 fail-closed；所有操作先规范化、校验权限和状态，再产生副作用。
- 使用明确 struct 和枚举表达协议，JSON decoder 保持拒绝未知字段。
- 新的特权操作必须同时提供：最小参数类型、路径/名称约束、备份计划、执行器、验证、回滚或明确的 `RECOVERY_REQUIRED` 语义，以及审计测试。
- `cmd/` 保持薄；业务逻辑和测试放入对应 `internal/` 包。

### Shell 与 systemd

- Shell 脚本使用严格模式，引用变量，拒绝空目标和宽泛路径；禁止对未解析变量、glob、`~` 或文件系统根执行破坏性操作。
- 安装和卸载必须保留用户数据恢复路径。卸载不得默认删除状态、备份和审计。
- 修改 unit 时保留最小身份、目录权限、credential 隔离和 hardening；使用 `systemd-analyze verify` 在 Linux 上验证。

## 常见改动的完成条件

### 新增 Agent 工具

1. 放在 `src/agentd/tools.ts` 或同层专用模块。
2. 标明只读或变更准备语义；不得直接产生宿主 root 副作用。
3. 添加输入校验、超时、输出裁剪/脱敏和单元测试。
4. 若需要高权限，新增或复用类型化 `agentd-root-broker` 操作，不得调用 shell 逃逸。

### 新增特权操作

1. 同步定义 TS 与 Go 协议类型及版本兼容行为。
2. 证明为何现有操作不能表达该需求，并把权限收窄到最小参数集。
3. 实现 prepare、摘要绑定、备份、执行、验证、失败恢复和审计。
4. 测试未授权 UID、未知字段、过期/重复审批、部分失败和回滚失败。
5. 更新安全模型、架构或运维手册。

### 新增 IM bridge

1. 放入 `integrations/<bridge>/`，不要修改核心来引入厂商 SDK。
2. 通过继承的单向 FD 消费 `completion.v1` NDJSON；禁止使用环境配置的 callback command。
3. adapter 自行校验会话/用户 allowlist，并在启动 core 前剥离 bridge credential 和环境变量。
4. 发送命令必须使用固定可执行文件和固定 argv 结构；正文使用有界输入，不经过 shell 拼接。

## 验证要求

代码发布前至少运行：

```bash
npm run check
npm run build
go vet ./cmd/... ./internal/...
go test -race ./internal/...
git diff --check
```

涉及 systemd、bubblewrap、安装、真实模型或 bridge 的改动，还需在目标 Linux 测试机执行相关的部署冒烟和恢复测试。环境条件缺失时应明确记录未验证项，不能通过削弱安全配置制造通过结果。

## 工作区纪律

- 修改前读取现有实现、测试和相关文档，优先小范围复用，避免 unrelated refactor。
- 保护用户已有改动；不要重置、覆盖或顺手格式化无关文件。
- 依赖使用 `package-lock.json` 和 `go.mod` 中的固定版本；不要假设全局 CLI 或认证存在。
- 生成物放在既有 `dist/`、`bin/` 或临时目录，不提交秘密和主机状态。
- README 保持面向使用者且简洁；实现细节放入 `docs/`。安全、部署或恢复行为变化必须同步更新相应文档。
