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
`plugin.register`、`plugin.install`、`workload.deploy`、manual root capsule 与 rollback 永不 standing。
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

截至 2026-08-09，`v0.84.1` 仍是 Pi 最新正式 Release。Pi `main` 已继续加入 Harness durable-state
设计、event/watch API 与 provider/TUI 修正，但这些仍是
[`936aff0`](https://github.com/earendil-works/pi/commit/936aff00918de1187f085f123c2812d8f2d67745)
所代表的未发布主干；本项目不会绕过 tag 直接跟随它。未来只在新 Release 发布后重新审计 public
API、changelog 与 lockfile，再决定是否升级。

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
| callback 经 shell、FD3 丢失 | runner 以 `shell:false` 启动 Source/compiled Client sibling；固定 FD4 typed inbound、FD3 completion、runner-only FD5 context，bounded terminal-safe stderr | Adapter contract；BotMux 当前 CliAdapter 已具备 direct bin/argv，专用 FD contract 留在本仓库 |
| BotMux multiline wrapper 被正文 tag 截断 | 只在完整 prefix 时解包 first-open + last-close；sender 从 suffix 取 | BotMux Adapter；可提 upstream envelope schema PR |
| 人类/bot 回复 @ 行为混乱 | human `--mention-back`，bot `--no-mention`；关闭 streaming cards/reactions | BotMux Adapter/config |
| 远端 sender 被误当 approver | 所有外部 Adapter 的 action 当前拒绝，只能 status；私钥迁到 root-only submitter，owner approval 回到 PASSWD/TTY TUI | Core security |
| zsh/default PATH 导致 CLI/恢复失败 | `/bin/bash`、固定 PATH，`botmux-bin` 第一；必须存在名为 `pi` 的 wrapper | Adapter/deployment |
| `npm --ignore-scripts` 造成 `node-pty` 不可用 | Adapter 安装显式 build/load verification | 本地错误安装路径；只有在 BotMux 支持的安装流程可复现时才提 doctor/docs issue |
| Debian merged-/usr 下 bwrap bind 失败 | 运行时按实际存在路径构建只读 bind；发布必须测试 merged/non-merged layout | Core sandbox/release |
| 审计包含无限 stderr/secret | transport stderr/response 有界，错误脱敏；仍禁止把 secret 放入 `ops_bash` | Core/Adapter |
| sudoers/wrapper 参数匹配过宽 | wrapper 必须固定 executable/argv；无参 sudoers command spec 使用 `""`；root 不执行 user-writable CLI | 部署/业务 Workload |
| Go/Release 在 LXC 或跨架构失效 | `CGO_ENABLED=0 -trimpath`，amd64/arm64；排除 `._*`；cache 异常时用干净 GOCACHE 重建 | Release |
| 协议测试时钟与真实 `context` deadline 跨日漂移 | Parse 与 dispatch 使用同一 server clock 计算 `(0, 10m]` 剩余窗口，再转为 monotonic timeout；过期/回退扩窗在 broker 前拒绝 | HTTPS/Unix transport；防止 admission 槽过早释放 |
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

2026-08-09 重新核对 BotMux `master` 后，`CliAdapter` 已有 resolved bin/build args、typed sender、
structured-input hook 与一致的 resume policy；Pi Adapter 也已对长/控制字符 initial prompt 使用受控
`@file`。因此不再重复提交历史建议中的 direct executable/argv、sender type、resume executable 或
long-prompt PR。

仍适合先开 issue/RFC 的是用户正文边界：当前
[`buildNewTopicPrompt` / `buildFollowUpContent`](https://github.com/deepcoldy/botmux/blob/c54cf25b294dc86e3f53039f947cb8df81e70270/src/adapters/cli/pi.ts)
仍把原始正文直接放入 `<user_message>...</user_message>`；正文中的 closing/tag-like 文本可能与
envelope 冲突。Issue 应先给 tag-like 正文、multiline/split、title/resume extraction 的最小复现与
兼容目标；maintainer 确认编码或 sidecar 方案后再拆小 PR。`node-pty` 只在上游支持的安装路径能
稳定复现时提交 doctor/docs 修正，不能把刻意使用 `--ignore-scripts` 造成的 native addon 缺失当作
上游 bug。不要把本项目的额外 FD、approver private key 或 root policy 放入 BotMux。

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
| Source Plugin | strict manifest/tree、digest、snapshot、grant、TUI/base bootstrap；`plugin.register` 绑定 version/publisher/capabilities/digest/requestedScopes 并由 broker register/verify/rollback；每次新 digest 本地逐次批准；非 root strict Adapter runner 与无网络 Workload host；双层 outer/inner procfs 分别匹配各自 PID namespace；Noble restricted-userns controller 持久 mutation 前 fail closed；BotMux 按实际 restricted-userns/AppArmor evidence 跨发行版拒绝 | Noble restricted-userns 支持需要独立 typed spawn supervisor；受控分发/源码编辑工作流；BotMux 真实 main→wrapper profile 设计仍未支持 |
| Adapter | 通用 `.mjs` Source runner、TUI local-only 特例、BotMux immutable entrypoint、Source/Client sibling + strict FD4/FD3/FD5、统一 bounded stdin ingress、envelope/sender/completion/disconnect 修正 | handoff/compact/clear consumer、trusted ApprovalIntent、outbox/dedup/rate limit |
| Workload | isolated Source workload host；descriptor/manifest capability exact match + provider-name requested-scope policy；资源 policy 与显式 standing scope 分离；PVE digest-bound typed arms；Hermes/BotMux source-owned profile + generic service provider；legacy Hermes OCI | Hermes/BotMux CLI/conversation/config content 与更多 audited provider |
| C/S | TLS 1.3 mTLS roles、strict HTTP、server/broker split、revision grant；每次 prepare 后用 domain pinned key 验证 signed `change.status`，仅 PENDING 暴露审批 side-channel；join 先匹配独立渠道传入的 controller CA SHA-256 pin，再验证 bundle 签名 | distributed limiter、controller HA、online enrollment consumption |
| Release | static Go、Node runtime、tar/deb/SBOM/checksum/attestation、`._*` cleanup；disposable native ARM64 Linux 已完成 `0.3.0` tar/deb build 与 `verify-release.sh`；exact branch commit 对应的 PR synthetic merge 已完成 GitHub-hosted non-publishing 双架构 candidate verification | exact version-tag publish/attestation 尚未运行；`ubuntu-22.04` hosted image 只是将退役前的过渡 Adapter gate，仍需迁移到后续受支持环境 |

## 本轮验证证据（2026-08-10）

以下结论只描述实际执行过的候选，不把 disposable VM、fake API 或一次安装事务扩大为生产验证。
表中的 hosted candidate 与 live controller 行都绑定具体 source SHA、artifact digest 和测试机；
不得把 branch HEAD、PR synthetic merge、Actions artifact archive digest、archive 内部 payload digest
或一次 VM 结果互相替代：

| 场景 | 已取得的证据 | 仍不能证明 |
|---|---|---|
| Native ARM64 Release | Release run `31340632941` 的 ARM64 native artifact `9045738753`（Actions archive digest `sha256:441bdca64c7fa1f61e9104be77a77e7e592b767e9ba388c7097549fb88d98466`）经独立下载；内部 `ops-agent-linux-arm64.tar.gz` 为 `sha256:f646a11921f649d7f19bd5db1306af367a3b4e7e9ad79c8991e10cbb55431556`、deb 为 `sha256:25ae4d7c32f1875a86516056d02fa7d10972f84740d3d1a111a33d3f217066d4`，并与 aggregate candidate 内对应文件逐字相同。完整 Release gate 已验证 ELF、tar/deb parity、随包 Node `22.23.2` 与 Client/Reviewer 加载 | Actions archive digest 不是内部 tar/deb digest；payload 尚未由 exact version-tag publish path attest 或发布 |
| Bookworm controller `init`/start | fresh isolated OrbStack Debian 12 / systemd `252.39` 从上述 exact ARM64 tar 完成 `init --no-start`；installer 的未削弱 static double-bwrap probe 通过，随后 controller topology 全部启动，healthcheck 为 `0 failures / 1 warning`。唯一 warning 是 OrbStack 基线 `sys-kernel-debug.mount`/`kmod-static-nodes.service`，不是 managed unit、socket、credential、Plugin 或 broker failure | 这是 OrbStack/Linux systemd 252 的 fresh controller 证据，不等于 bare-metal/普通 VM、外部模型 provider、真实 Proxmox 或长期运行验证 |
| Scripted model-protocol / Source / local approval E2E | 同一 fresh controller 使用 root-owned loopback fixture（fixture source `sha256:3e2313f9867e75e346005a16c46958752361d382604440346e01f1b8cec9a61c`）严格实现锁定的 Pi `openai-completions` 两轮 SSE/tool-call 协议；production compiled TUI/gateway/agentd/双层无网 `workload.base` 真实运行。`ops_bash` 由 fixture 验证 Source PID 1、`CapEff=0`、只读 `/usr`、loopback blocked；`ops_inspect` 返回必需 host snapshot 字段且不产生 change；package change 经 fresh signed status 为 `PENDING_APPROVAL` 后由真实 PASSWD sudo、PAM、`/dev/tty` exact confirmation 进入 `REJECTED`，测试包未安装；`file.write` 第一次 `/approve` 只得 reviewer `REVIEW_REQUIRED`，第二次才进入 PAM/TTY，在确认点同时观测 Client 与 root submitter 两个独立 shared digest lease 且 exclusive lock 被拒，最终 `COMMITTED`，随后同样 two-step/PAM/TTY rollback 到 `ROLLED_BACK`。broker/agentd restart 后 fresh Client 再次验证 signed `REJECTED`/`ROLLED_BACK` | 这是 deterministic scripted OpenAI-compatible transport，不是真实模型推理、外部 provider TLS/rate-limit/retry 或抗提示注入证据；fixture 也不验证 real PVE。首次 PAM harness 因对 Debian `/dev/tty` alias 的过窄假设 fail closed，留下一个未批准的 `PENDING_APPROVAL` package change；它没有执行或获得批准 |
| systemd 252 `openat2` compatibility | 实机二分证明 systemd 252 的 `RestrictSUIDSGID=yes` 让 `openat2` 按策略返回 `ENOSYS`；candidate 仅在该错误上进入逐组件 `openat(O_NOFOLLOW)` + nonzero `STATX_MNT_ID` fallback，其他错误仍 fail closed。上述真实 `file.write` 在 root-helper effective `RestrictSUIDSGID=yes` 保持不变时成功提交 exact root:root `0644` 内容、生成一个 backup ref，再完整 rollback 到 pathname absent；root-helper `Result=success`，未靠重启或降低 hardening | 证明的是受控 write root 上的真实 positive path与 rollback；不把 fallback 扩大为任意路径、mount crossing 或非 `ENOSYS` 兼容承诺 |
| Clean Noble controller `init` | clean OrbStack Ubuntu 24.04/LXC 在 AppArmor kernel state 不可用时，当前 installer 于账号、unit、Plugin、sudoers、policy、probe 或 transaction 等产品 surface 发生持久 mutation 前明确拒绝 `init --approve-required-plugins --no-start`；前后 inventory 证明零产品改动 | 这是 unsupported host 的 early fail-closed 证据，不是 controller 成功安装；也没有证明 bare-metal、普通 VM 或 typed spawn supervisor，不能以旧 managed state、direct bwrap、省略 outer proc、单层或降低 hardening 解锁 |
| Noble AppArmor direct smoke | GitHub-hosted Ubuntu 24.04 保持 `kernel.apparmor_restrict_unprivileged_userns=1`，核验发行版 `apparmor-profiles` source/version/hash 后加载 `bwrap-userns-restrict` 与 exact host-wide `/usr/bin/bwrap ix,`；直跑双层 bwrap 证明 inner Source 为 PID 1、label stack 包含 `unpriv_bwrap`、`CapInh/CapPrm/CapEff/CapBnd/CapAmb` 全零，且后续 `unshare --user` 与 nested bwrap 均失败 | AppArmor exec rule 不绑定 argv，会扩大宿主 path-level authority；direct Node smoke 只证明底层机制，不能建立 controller support，也不能证明 BotMux main→pi wrapper 生产链可用 |
| Noble restricted-userns controller | exact NNP static boundary 已证明正确 outer `--proc /proc` 在 `ProtectProc=invisible` 下以 `EPERM` 失败；随后 GitHub Actions [run 31319405888](https://github.com/KiritoKing/pi-ops-agent/actions/runs/31319405888)（commit `7091ecfbc28ae6410f06d4e2b64462c96dd83726`，installer-runtime job `93259846767`）精确验证 outer-proc-removal 候选失败为 `bwrap: open /proc/3/ns/ns failed: No such file or directory` | 结论是本 Release controller/`init` unsupported，并在持久 mutation 前 fail closed；旧 managed files/kernel profiles 只保留证据，不自动 remove；真正支持需要 typed spawn supervisor，不能以 sysctl/SUID/single-layer/降低 `ProtectProc`/unconfined 规避 |
| Noble non-PVE endpoint `join` | fresh Noble endpoint 以 signed enrollment 执行 server/core-only join：先注入安装失败并核对事务回滚，再使用同一 signed token 成功 join；live TLS 1.3 mTLS agent client 经 HTTPS→core broker 完成 `host.snapshot`，server/core broker 分别重启后再次成功，endpoint healthcheck 为 `0 failures / 0 warnings` | `join` 不安装或运行 controller/Source Plugin，因此这份 Noble endpoint 成功证据不改变 restricted-userns controller 的 unsupported 结论；它也不包含真实模型、Workload Source host、Plugin invocation lease 或本地 TTY 审批 |
| Signed fake-PVE endpoint `join` | fresh isolated endpoint 使用 signed PVE enrollment 与 readiness-patched ARM64 artifact 完成 live join；server、core broker、PVE broker 三个 unit/socket 均就绪后 endpoint healthcheck 为 0 failures / 0 warnings，证明 installer 在提交后等待 core/PVE broker socket readiness | `/usr/bin/pvesh` 是严格 fake fixture；该结果只验证 enrollment、安装拓扑、readiness、mTLS/broker transport、DAC/receipt/audit 健康，不验证真实 Proxmox API、pmxcfs、quorum 或 guest mutation |
| PVE fake E2E | fresh strict fake-PVE fixture 中，额外 argv 被拒且状态摘要保持不变；automatic/standing start 经 fresh signed status/receipt 进入 `COMMITTED`；held task 在 PVE broker restart 后沿同一 UPID 续跑到 `COMMITTED` 且只产生一次 mutation/task；最终注入 failure 得到签名 `RECOVERY_REQUIRED`，原 task 为 `stopped/ERROR`、guest 保持 `stopped`，cluster-global VMID lock 与恢复证据继续保留 | Harness 从 compiled HTTPS client 开始，明确绕过 model、Source Workload host 与 Plugin invocation lease；fake fixture 不具备真实 Proxmox、pmxcfs、quorum、storage 或 guest side effect，因此不是 real PVE 验证 |
| Fast async `change.status` receipt race | fresh fake-PVE E2E 暴露的 observation race 已改为对同一次校验所得 immutable Store clone 签名，不二读可变 state，也不让 status 等待长 mutation lock；确定性并发 regression、Go race suite 与 live immediate-status 复验均通过。修正现已进入下述 exact hosted candidate，并由 fresh Bookworm controller 的 restart 后 signed status 读取再次覆盖 | 仍不把 scripted core/file path冒充 PVE task worker、真实集群或所有 deadline/recovery 组合的证明 |
| Hosted Release candidate gates | branch commit `d0fb459c5fd4a0a386643cc5a8c300dfcf90268c` 对应 PR synthetic merge/source SHA `64eb83b34b558f95479630499b280ed2593a6988`；GitHub Actions [Release run 31340632941](https://github.com/KiritoKing/pi-ops-agent/actions/runs/31340632941) overall success：validate `93313693600`、reusable check/Adapter/installer/join gates、real Adapter `93313858724`、amd64 `93313858737`、arm64 `93313858787` 与 candidate verification `93314209679` 均成功。push CI `31340630184` 与 PR CI `31340632849` 也全部成功 | Release artifact 的 source identity 是 PR synthetic merge，不是 branch SHA；该成功不等于 exact tag publish/attestation、外部真实模型或真实 Proxmox 验证 |
| Hosted Adapter runtime | 同一 Release run 的 real Adapter job `93313858724` 在 `ubuntu-22.04` 上使用 root-owned、versioned Node `22.23.2` fixture，以及 SHA-256 固定 source 构建、root-owned `0755`、无 SUID/SGID/file capability 的 bubblewrap `0.9.0`，成功运行未削弱的 `test:adapter-linux-runtime`：保留 outer/inner 双层 PID/procfs、outer sync/info FD 与 exact init process identity completion barrier | 只证明该 hosted 环境的真实 Adapter runtime probe；`ubuntu-22.04` runner 只是退役前过渡 gate，不证明 Noble restricted-userns controller、外部真实模型、真实 Proxmox 或 BotMux 生产链 |
| Aggregate candidate / publish boundary | candidate verification 上传 artifact `9045769334`，名称 `release-candidate-64eb83b34b558f95479630499b280ed2593a6988`，Actions archive digest `sha256:5cf2327873babb2182a6aaa11d108e13d22f8a88c7ba7c791e16477d5ce5fa60`；PR event publish job `93314296936` 按契约 skipped，没有创建 tag、attestation 或 GitHub Release | aggregate candidate 尚未发布；外部真实模型与真实 Proxmox 仍未验证，这些边界闭合前不创建 `v0.3.0` tag |

上述 OrbStack/live E2E 已实际覆盖 compiled Client、Pi model protocol、双层 Source Workload、Plugin
lease、typed broker、signed receipt、reviewer、PASSWD sudo、真实 `/dev/tty` exact confirmation、
commit/rollback 与 restart；但模型响应来自 deterministic loopback transport，不是外部真实模型，PVE
仍是 fake runner。两者不能组合成对真实模型判断或 real Proxmox 整条生产链的验证。

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
