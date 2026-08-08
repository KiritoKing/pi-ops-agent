# v0.3 重构基线、上游更新与迁移路线

本文记录 2026-08-08 这次重构的决策、已实现状态和仍需补齐的工作。架构事实由
[architecture](architecture.md)、安全边界由[security-model](security-model.md)、部署/恢复由
[deployment](deployment.md)与[operations](operations.md)约束。

## 心智模型

### Core 只负责安全和控制面

Core 包含：

- `agentd` 的非 root Harness、Session workspace 和 bubblewrap；
- 同 UID guardian；
- 非 root HTTPS/mTLS `agentd-server` 与 root/Unix-only broker；
- Machine/Target/policy/capability identity；
- typed root operations、备份、验证、审计和恢复状态；
- 模型外审批、独立 reviewer、root-only PASSWD/TTY submitter、grant/nonce。

Core 不以“内置多少工具”衡量能力，也不注册 Agent 可见的业务工具；实际可用系统由必须逐次
批准的 `adapter.tui`、`workload.base` 和按需业务 Plugin 组成。必需 Workload 仍只能在真实
no-network bubblewrap/user namespace 中运行；该条件不可用时初始化整体 fail closed 并回滚，
不能退化成宿主 shell 或进程内 loader。

### Adapter 决定如何交互

Adapter 管理外部 Session、入站消息、出站事件和审批意图。TUI 是保底 Adapter；BotMux 等
外部 Adapter 默认不能审批，直到能证明 sender、owner private DM 和 replay state，并通过
版本化 ApprovalIntent 进入未来独立的模型外 approval gateway；当前
`agentd-client-gateway` 只负责本地 peer/session 隔离，不消费远端审批意图。

### Workload 决定会做什么

Workload 提供 sandbox/只读工具或 typed root recipe。Plugin 的批准是对一份源码 digest、
capabilities 和 requested scopes 的持久 grant；每次安装/更新都在模型外本地流程逐次批准，所有
源码更新都改变 digest 并使旧 grant 失效。第一方/第三方使用同一规则。

Plugin grant 不等于 root 免审。Root-owned Target policy 的资源 allowlist 决定操作能否 prepare，
只有独立、显式、精确的 `authorization.standingScopes` 才允许普通 operation 在 prepare 内消费
既有授权；legacy policy、字段缺失或空数组全部逐次人工审批。当前 package/artifact 安装、
package/artifact 安装、`plugin.register`、`plugin.install`、`workload.deploy`、manual root capsule 与 rollback 永不 standing。
有效权限始终取 plugin grant、Target 资源 policy 与 standing scope/本次人工 grant 的交集。
通用 `file.write`/`service.action` 由 Core 根据真实 `workload.base` caller 注入摘要；要 standing
还必须由 Target 的 `authorization.baseWorkloadDigest` 精确绑定该摘要，更新后自动失效。

`workload.pve` 是仓库随附的标准 Source Workload，但 Core PVE typed ABI 不把该 ID 当 authority：
PVE endpoint 只安装 non-root server、core broker 和独立 PVE
broker；PVE domain 只把 typed operation 映射到固定 `/usr/bin/pvesh` path/argv，并使用独立 receipt
key。任意 root capsule 只能走同一 endpoint 的 core broker，不能穿过 PVE broker。

## 上游更新审计

### Pi Ops Agent `v0.2.0`

审计时仓库最新公开 tag 是 [`v0.2.0`](https://github.com/KiritoKing/pi-ops-agent/tree/v0.2.0)，
当前工作分支已包含该 tag 的完整历史。按
[`v0.1.0...v0.2.0` 版本差异](https://github.com/KiritoKing/pi-ops-agent/compare/v0.1.0...v0.2.0)，
这版上游不是简单改名，主要加入：

- schema v2 `.opspkg` 与 release catalog，artifact identity 绑定
  `id/kind/version/publisher/digest`；
- 通用 `managed-workload` manifest、typed `workload.deploy` 与 broker-side OCI executor；模型
  不能传 Docker executable/argv、host namespace、额外 mount 或 capability；
- 模型外 credential bundle/configurer、root-owned Target pin 和升级时禁止静默扩权；
- `workload.hermes` 端到端样例，包括固定 image digest、loopback、资源限制、进程身份、健康
  验证与 rollback evidence；
- catalog/release 构建、升级兼容测试和额外 systemd hardening drop-in；
- 文档把逻辑组件统一为 `agentd` / `agentd-guardian` / `agentd-server` /
  `agentd-root-broker`，同时保留现有 `ops-*` artifact 名称。

本次重构保留并继续验证上述 change、catalog、Hermes executor 和 recovery state，作为 legacy
兼容路径；新的 Adapter/Workload 默认采用可编辑 Source Plugin + typed broker recipe，不能因
迁移而删掉 `v0.2.0` 已部署实例的恢复能力。

除此之外，Pi packages 有一个可直接吸收的 patch 更新：

```text
@earendil-works/pi-ai            0.84.0 -> 0.84.1
@earendil-works/pi-coding-agent  0.84.0 -> 0.84.1
```

依赖使用 exact version 与 lockfile，不能浮动到未审计 patch。上游 compare：
<https://github.com/earendil-works/pi/compare/v0.84.0...v0.84.1>。

### Pi 0.84.1 的直接变化

根据随包 changelog，`0.84.1` 增加/修复：

- Qwen Token Plan Individual provider；
- `pi auth check` provider/model credential readiness preflight；
- blocked `tool_call` handler 的 terminating batch；
- fullscreen multi-click selection、half-page scrolling 和较快 theme detection；
- active run 中 `Agent.reset()` 现在拒绝，避免清空运行中状态；
- Bun standalone/TUI/Windows 的若干修复。

这些变化没有要求改写本项目 C/S 或 root broker。`pi auth check` 可作为管理员安装前诊断参考，
但本项目通过 `ModelRuntime` + systemd credential 注入，不应把 CLI 输出 credential 的模式接到
Agent 或审计。

### 与本项目相关但不是 0.84.1 新增的公开 API

- `agent_settled` 已是公开 session event；`agent_end` 只表示一次低层 run 完成，可能仍有 retry、
  compaction 或 queued continuation；
- `ToolDefinition.promptSnippet` / `promptGuidelines` 是公开 custom-tool prompt metadata，可在
  Workload runtime 成熟后使用，无需私有 import；
- Pi 的 extension/skill/plugin 系统不替代本项目 root policy，也不能加载到特权 broker。

本项目不采用 Pi 的实验/通用 server 作为 `agentd-server`：它没有本项目所需的 mTLS role、
Machine/Target policy、root peer UID、approval grant 和 recovery state。也不私有 import 尚未
稳定导出的 Harness factory；需要新 API 时先提交最小 RFC/issue。Session JSONL 到其他存储的
迁移也不与本次安全重构混在同一变更中。

## 从真实运行带回的纠偏

| 问题 | 当前修正 | 归属 |
|---|---|---|
| `agent_end` 后仍 retry/compact，completion 重复或过早 | `agent_settled` authoritative；`agent_end(willRetry=false)` 只作短 fallback，retry/compaction/start 取消 timer | Core，可向 Pi 报 prompt settlement contract 的最小复现 |
| agentd socket 断开后旧 CLI 仍占 PTY | Client/Adapter 解绑并 pause stdin，等待队列后退出，由 BotMux/tmux 重建 | Core/Adapter，本仓库 |
| callback 经 shell、FD3 丢失 | runner 以 `shell:false` 启动 Source/compiled Client sibling；固定 FD4 typed inbound、FD3 completion、runner-only FD5 context，bounded terminal-safe stderr | Adapter contract，可向 BotMux 提交结构化 launcher PR |
| BotMux multiline wrapper 被正文 tag 截断 | 只在完整 prefix 时解包 first-open + last-close；sender 从 suffix 取 | BotMux Adapter；可提 upstream envelope schema PR |
| 人类/bot 回复 @ 行为混乱 | human `--mention-back`，bot `--no-mention`；关闭 streaming cards/reactions | BotMux Adapter/config |
| 远端 sender 被误当 approver | 所有外部 Adapter 的 action 当前拒绝，只能 status；私钥迁到 root-only submitter，owner approval 回到 PASSWD/TTY TUI | Core security |
| zsh/default PATH 导致 CLI/恢复失败 | `/bin/bash`、固定 PATH，`botmux-bin` 第一；必须存在名为 `pi` 的 wrapper | Adapter/deployment |
| `npm --ignore-scripts` 造成 `node-pty` 不可用 | Adapter 安装显式 build/load verification | BotMux packaging；可向上游补安装诊断 |
| Debian merged-/usr 下 bwrap bind 失败 | 运行时按实际存在路径构建只读 bind；发布必须测试 merged/non-merged layout | Core sandbox/release |
| 审计包含无限 stderr/secret | transport stderr/response 有界，错误脱敏；仍禁止把 secret 放入 `ops_bash` | Core/Adapter |
| sudoers/wrapper 参数匹配过宽 | wrapper 必须固定 executable/argv；无参 sudoers command spec 使用 `""`；root 不执行 user-writable CLI | 部署/业务 Workload |
| Go/Release 在 LXC 或跨架构失效 | `CGO_ENABLED=0 -trimpath`，amd64/arm64；排除 `._*`；cache 异常时用干净 GOCACHE 重建 | Release |
| root watchdog 权限过大 | same-UID guardian 已替代旧 `ops-systemd-helper`，release/target 不再打包或启动旧 binary | Core migration |

`ops_bash` 的 Agent audit 当前仍记录 command/result，因此“错误脱敏”不能被扩张成“所有模型
可见内容都不落盘”。文档和测试必须描述真实边界。

## 应同步到上游的内容

### Pi upstream

适合提交：

1. 若能稳定复现 `agent_settled` 已发但 `prompt()` 永不 settle，提交最小 SDK reproduction、
   期望 contract 和 regression test；不要提交本项目整个 supervisor；
2. 如果 Workload runtime 需要当前 public exports 无法表达的 Harness factory，先开 API RFC，
   说明最小 type/ownership/lifecycle，不引用 private path；
3. 可补一份 status integration 文档示例，明确 `agent_settled` 而非 `agent_end` 是 final boundary。

不应提交到 Pi：mTLS、root broker、Target policy、approval grant、PVE recipe、systemd unit；这些
是本项目安全域，不是通用 coding harness 行为。

### BotMux upstream

适合拆成独立 PR/issue：

1. 提供版本化、长度有界的结构化 inbound envelope，正文不靠可冲突 XML delimiter；
2. launcher 原生支持 direct executable/argv、额外继承 FD 和 disconnect-exit contract；
3. sender type 与 reply mention policy 使用 typed field；
4. resume 路径一致遵循 configured executable/PATH，不隐式查找另一个 `pi`；
5. 安装/doctor 明确检查 `node-pty` native addon；
6. 提供关闭 streaming card/reaction 与 bot reply rate limit 的稳定配置文档。

PR 应带伪造 sender、tag-like正文、split paste、disconnect、FD 与 bot mention tests。不要把本项目
的 approver private key 或 root policy 放入 BotMux。

### 本项目保留

Source Plugin digest/scope、reviewer、typed broker、guardian、PVE operations、release static build、
merged-/usr 与 AppleDouble 检查均应留在本仓库。它们可以形成通用设计说明，但不应为追求
“上游统一”削弱本项目边界。

## 当前实现状态

| 主题 | 已落地 | 尚未完成 |
|---|---|---|
| Pi | exact `0.84.1` deps；settlement wrapper/tests | release/真实模型回归尚待最终验证 |
| Guardian | 同 UID heartbeat、PID/UID/exe/cgroup/starttime 复核、有界 TERM/KILL；旧 root helper 已退出 release/runtime，uninstaller 仍兼容清理 | 目标 Linux 上补完整 restart smoke |
| Reviewer/submitter | reviewer 独立 UID、只看真实用户输入与权威 plan、普通 `file.write` 完整有界正文+digest/bytes、manual capsule script 原文与缺少 backup/verify critical finding、risk floor、two-step；submitter root-only key、pre/post signed status、PASSWD + exact TTY | LLM/AST explain、split plan、基于 reviewer 风险的 auto-approval |
| Source Plugin | strict manifest/tree、digest、snapshot、grant、TUI/base bootstrap；`plugin.register` 绑定 version/publisher/capabilities/digest/requestedScopes 并由 broker register/verify/rollback；每次新 digest 本地逐次批准；非 root strict Adapter runner 与无网络 Workload host，bwrap/userns 不可用时 init rollback | 受控分发/源码编辑工作流 |
| Adapter | 通用 `.mjs` Source runner、TUI local-only 特例、BotMux immutable entrypoint、Source/Client sibling + strict FD4/FD3/FD5、统一 bounded stdin ingress、envelope/sender/completion/disconnect 修正 | handoff/compact/clear consumer、trusted ApprovalIntent、outbox/dedup/rate limit |
| Workload | isolated Source workload host；descriptor/manifest capability exact match + provider-name requested-scope policy；资源 policy 与显式 standing scope 分离；PVE digest-bound typed arms；Hermes/BotMux source-owned profile + generic service provider；legacy Hermes OCI | Hermes/BotMux CLI/conversation/config content 与更多 audited provider |
| C/S | TLS 1.3 mTLS roles、strict HTTP、server/broker split、revision grant；每次 prepare 后用 domain pinned key 验证 signed `change.status`，仅 PENDING 暴露审批 side-channel；join 先匹配独立渠道传入的 controller CA SHA-256 pin，再验证 bundle 签名 | distributed limiter、controller HA、online enrollment consumption |
| Release | static Go、Node runtime、tar/deb/SBOM/checksum/attestation、`._*` cleanup | 本次 OrbStack/systemd/PVE/release workflow 结果未在本文预先宣称 |

## 近期实施顺序

1. 完成 reviewer/guardian/source registry/PVE 的跨语言 tests 和 unit hardening；
2. 扩展现有 `agentd.adapter/v1` / `agentd.workload/v1` runtime 的 typed provider，不允许任意 callback；
3. 继续把 BotMux、Hermes 的 CLI/config/conversation 能力迁到窄 Source Plugin provider，并保留旧
   `.opspkg` recovery 读取；
4. 实现持久 Session writer lease 与 Adapter handoff；
5. 增加结构化 ApprovalIntent、AST/模型 advisory reviewer，再评估基于风险的动态 auto-approval；
   当前只允许管理员在 root-owned policy 中逐项配置 exact standing scope；
6. 在隔离 systemd Linux 做 init/join/upgrade/rollback、disconnect、review、plugin update 和 PVE
   failure-injection E2E；
7. 最后才发布 tag，并以远端 CI/Release 结果作为交付证据。

## 验收原则

- 没有 `adapter.tui`/`workload.base` grant 时服务 fail closed，不悄悄恢复内置能力；
- 真实 bwrap/userns 不可用时 init 整体回滚，不仅是隐藏 `ops_bash`；
- 第一方 Plugin 更新需要新 digest 批准；
- Agent、reviewer、Client 和 Adapter 都不能读取私钥或签名；外部 Adapter 不能批准；
- 同一计划第一次只 review；第二次仍需每次 PASSWD sudo 与 submitter 的完整 scope/planHash
  TTY 确认，且确认前后 plan 不漂移；
- Target allowlist 不自动变成 standing authority；只有显式 exact `authorization.standingScopes`
  允许普通 operation 在 plugin/resource policy 交集内执行，legacy/空配置仍逐次人工审批；
  plugin/package/artifact/deploy、manual capsule 与 rollback 永不 standing；
- 普通 root broker operation 不接受 raw command/PVE argv；任意 root Target 可 prepare manual root
  capsule，但仍只允许本地 TUI/PASSWD/TTY 逐次人工批准；完整 script/network 进入 plan，缺少
  backup/verify 被 reviewer 标为 critical，且不提供自动 rollback；PVE broker 不接受 raw script；
- agentd disconnect 后旧 CLI/PTY 退出；completion exactly once；
- legacy change/recovery 在迁移后仍可读；
- 每次 prepare 后必须用对应 domain pinned broker key 验证 signed `change.status`；只有
  `PENDING_APPROVAL` 暴露审批 side-channel，signed `COMMITTED` 才表示 standing execution 或
  人工批准操作已经成功；
- 文档、三个 repo Skills 和实现必须在同一变更中同步。
