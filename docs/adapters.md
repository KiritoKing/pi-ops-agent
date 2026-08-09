# Adapter：会话、消息与审批边界

Adapter 把 TUI、BotMux、飞书或其他外部系统转换成 Core 的稳定输入/输出。它不是“消息转发
脚本”：session mapping、sender authentication、replay、防泄漏和审批降级都属于 Adapter
的安全职责。

## 能力接口

Adapter 契约分为四组：

| 接口 | Adapter 负责 | Core 负责 |
|---|---|---|
| Session | 外部 conversation/thread 到 Session ID 的稳定映射、handoff 请求、去重 | Session binding、workspace、Pi compaction 与 transcript |
| Inbound | 平台认证、sender/conversation 类型、bounded ingress ID、envelope normalize | 将正文标为不可信、精确命令截获、模型输入上限 |
| Outbound | send/reply/quote/mark/display 等 typed 平台动作、retry/outbox | 产生版本化、bounded、脱敏的 completion event |
| Approval intent | 真实 sender、owner private DM、replay 和 change correlation 证明 | reviewer、plan/grant、签名与 broker action |

`src/shared/adapter-runtime.ts` 已定义三组 strict tagged union：

- `agentd.adapter-inbound/v1`：当前只有 `text`，绑定 bounded ingress/session ID、conversation 类型、
  正文、时间与来源。`authenticated` 来源必须携带 issuer/subject/evidence ID/observed time；这些字段
  是待独立验证的证据元数据，不是 ApprovalIntent，也不能单独产生审批权限；
- `agentd.adapter-session-control/v1`：`bind`、`handoff`、`compact-request`、`clear-request`；
- `agentd.adapter-outbound-action/v1`：`send`、`reply`、`quote`、`mark` 与本地 TUI `display`。

三者逐 variant 拒绝未知字段，限制整帧与 UTF-8 正文大小，并拒绝 NUL、终端 escape、bidi override
等隐藏控制字符。`agentd.adapter/v1` descriptor 必须分别列出 `supportedTypes`、
`supportedControls` 与 `supportedActions`，并用 `runtimeAuthority` 明示 execution、宿主文件
系统、网络、runtime UID 可读 credential 和 action-scope enforcement。runner 会把行为声明确定性映射为
`adapter.inbound.<type>`、`adapter.session.<control>`、`adapter.outbound.<action>` capability，
以及带 Adapter namespace 的同名 scope，并与获批 manifest **完整精确相等**；不能用宽泛
`message.outbound` grant 在 typed IPC 中把 `send` 混淆为 `quote`。

动作级 capability/scope 是 **digest review grant 与 typed IPC contract**，不是 credential-bearing
Source Adapter 的 OS action sandbox。可执行 `.mjs` 保留宿主网络、以专用 Adapter UID 看到的文件和
credential，并能绕过 typed outbound contract 直接调用该 UID 可执行的平台接口；因此不能声称
`send` scope 在操作系统层阻止源码执行 `quote` 或其他平台动作。`plugin.register` 的 canonical
ApprovalPlan 与 deterministic reviewer 会显示 runtime identity、`host-as-runtime-uid` 文件权限、
host network、`runtime-uid-readable` credential，以及 direct platform call 不受 action scope 的事实。
新 digest 必须重新审批；独立非 root UID、status-only、CAS 与 lease 只限制 root/审批/lifecycle
边界，不把平台 credential 收窄成 typed action 权限。

外部 Source Adapter 的 `text` 与 `bind` 已通过固定 FD 4 的 strict NDJSON transport 进入 compiled
Client：Client 先按 descriptor 的原始 wire-byte ceiling 截帧，以 fatal UTF-8 解码并拒绝
duplicate/trailing JSON，再执行 declared union 与 bind/session/ingress replay 校验。FD 3 是反向的
`completion.v1` 单向流。BotMux 的第一条及后续消息都只能从 stdin 的 bounded bracketed-paste
frame 进入 Source；Source 与 Client argv 都拒绝 positional/`@file` prompt，不能绕过 raw-byte
ceiling、fatal UTF-8 与 envelope parser。同一 gateway 进程内跨 Client connection 的 namespace
live-writer lease 已实现；当前仍没有跨 gateway restart、多个 gateway 实例或 Adapter handoff 的
持久化 writer lease，也没有通用 outbound platform mediator、handoff/compact/clear consumer、
持久 outbox 或远端 ApprovalIntent。

Source manifest 使用 `kind: "adapter"`、`adapter.*` ID，并声明精确 capabilities/scopes。参见
[Source Plugin](plugins.md)与[`adapter.tui` 示例](../plugins/adapter-tui/manifest.json)。当前的
固定 Adapter runner 可执行获批 snapshot 中的 `.mjs` entrypoint，并先后两次验证 current、
CAS 与 strict `agentd.adapter/v1` descriptor，并强制非 root、sanitized env、`shell:false`。
`adapter.tui` 是不可执行 `profile.json` 特例：runner 只解析固定 descriptor 并启动 compiled Client；
它只声明 `text`、`bind` 与 `display`；只有这组精确 capability/scope 可声明 `local-tty` 和
`approval.submit.local`，其他 ID 一律 status-only。
启动前 runner 以真实 UID 连接固定 `agentd-plugin-lease-broker` socket，为 exact active digest
取得 registry shared invocation lease，并持有到 Source 与 compiled Client 两个 sibling
子进程都退出；同一 plugin 的更新只能在旧 runtime 结束后取得 exclusive lease。可执行 Source
Adapter 的 descriptor 探测和正式入口都会进入各自的双层 bubblewrap PID namespace。outer 保留
bwrap 默认 PID 1 reaper 且只启动固定 inner bwrap。outer 不使用 `--proc` 重挂 procfs，只继承
systemd 已保护的 service proc 视图；inner 使用 `--proc /proc --as-pid-1 --disable-userns`，让
Source 成为 PID 1 并禁止继续嵌套。outer 的 `--sync-fd` 在 initial child 中关闭、只随 outer PID 1
生命周期持有；该 init 无论经正常 `ECHILD` 收拢还是 parent-death cleanup 终止，runner 都要在
sync EOF 后继续等待有界 `--info-fd` 返回的 exact `child-pid` + start identity 消失，而不是只等
monitor status；sync error 仍先等 identity
disappearance，初始 stat 不可读则只接受该 PID 后续 ENOENT，info 无法给出 PID 时保持 fail-stop，
因此 managed settlement 的摘要 lease 不会落在进程树清理窗口之前释放。最终 Source 只看见
inner PID namespace 的私有 procfs；outer 仍有独立 PID namespace/reaper，省略 outer proc remount
不是 PID containment 降级。bwrap 自己通过
`--dev /dev` 构造只含 `/dev/null` 等基础节点的最小 synthetic device view；不得改成把宿主
`/dev` 重新 `--dev-bind` 进去。该 namespace 保留 Adapter 的网络、宿主用户权限与
controlling TTY，所以这里只声称生命周期收拢，不声称像 Workload host 一样无网络或只读隔离。
descriptor 的 `runtimeAuthority` 必须与这个事实逐项一致；它是可审计声明，不会凭空产生更强隔离。
这里的“宿主用户权限”必须在真实 Linux 上验证，而不能从 argv 推断：非 root bwrap 可能通过 user
namespace 创建 PID/mount namespace，发行版或内核行为若清除了 supplementary groups，专用 Adapter
会失去 `ops-agent-client` 的 CAS、lease、observer identity 与 client socket DAC。发布前先执行
`npm run build`，再由 root 执行 `npm run test:adapter-linux-runtime`；探针创建
`root:ops-agent-client 0640` 文件与 group `0660` Unix socket，显式降权到 primary group 为
`ops-agent-botmux`、supplementary group 为 `ops-agent-client` 的真实账号，并同时验证 detached
child 的真实宿主 PID/starttime 先被清理、exact digest lease 后释放，以及继承的 FD 3/4 确实穿过真实 bwrap exec 并完成
分片双向传输。探针通过 transient systemd service 复现 BotMux drop-in 的
`PrivateDevices=yes`、`ProtectKernelTunables=yes`、`ProtectProc=invisible`、`ProcSubset=all`、
`RestrictNamespaces=user pid mnt` 与精确
`/proc/sys/user/max_user_namespaces` 可写例外；该例外只供 bwrap 在新 user namespace 内禁止继续
嵌套，Adapter UID 对宿主 sysctl 仍没有 DAC/capability。探针用 unit-name-specific late drop-in
抵消 host-wide `service.d` 的 list reset，并在执行 Source 前核对 `systemctl show` 的 effective
vector。`ProcSubset=all` 会保留未被其他 hardening 屏蔽的只读非 PID procfs 全局 metadata，
`ProtectProc=invisible` 只隐藏其他 UID 的 PID 目录而不隐藏 same-UID PID 或这份 metadata。
非 Linux、非 root、systemd、账号/组或
bwrap 缺失会用退出码
`77` 明确报告 `SKIP`，不计作已验证。
声明式 TUI 直接运行 compiled Client 以保留 host sudo/PAM；Client 会独立持有 exact TUI digest
lease 到退出，所以外层 runner 崩溃也不能留下仍可审批却已释放 lease 的 Client。

## TUI

`adapter.tui` 是必须安装的本地恢复入口。`/usr/local/bin/ops-agent` 每次启动都要求 active
registration，重新 hash immutable snapshot，核对精确 capability/scope，runner 在 descriptor
解析前后再次确认 current 未漂移，并要求 snapshot 只有非 executable 的 `manifest.json` 与
`profile.json`。随后 runner 以当前非 root 交互用户直接启动固定 compiled Client；profile 本身
从不执行。runner 与 compiled Client 各自保留 exact profile digest 的 shared lease，因此旧 TUI
退出前更新不能切换 current，也不能让已撤销 digest 的 Client 继续使用审批能力。registration 缺失、过度
授信、kind/ID 错误或 snapshot 失效均 fail closed。

Client 不会凭 group DAC 或外部 `sessionId` 直接进入 agentd。公开 socket 由
`agentd-client-gateway` 接收；gateway 以 `SO_PEERCRED` 取得真实 UID，重验 exact active Adapter
ID/digest，并把外部 Session ID 放入 UID+Adapter+digest namespace。descriptor 的
`session.writerLease` 固定为 `gateway-global`：同一 gateway 进程内每个 canonical namespace 只有一个
live writer，BotMux/其他 Adapter 即使猜中 TUI Session ID 也只能进入自己的 namespace。digest 更新
故意产生新 namespace；gateway restart 会断开全部 live writer，而不是保留模糊 ownership。

本地 TUI 是当前唯一能 approve/reject/rollback 的入口。`localConsole=true` 还要求：

- 没有外部 completion event sink；
- stdin 和 stdout 均为 TTY；
- plan 已完成第一次 reviewer 展示，并在短窗口内再次输入相同命令；随后所有 action 都还要
  通过 submitter 的本地密码和精确 TTY 确认。

若第二次确认的 canonical plan 恰好是单步声明式 `adapter.tui plugin.register`，Client 必须先停止
输入、关闭 Agent Session 并释放自己的 digest lease，再经 runner-only FD 6/7 请求外层 runner
释放同一 lease。runner 只有在 broker 确认 release 后才 ACK；submitter 随后启动，旧 Client 无论
提交结果都退出。另一 TUI/runtime 的 shared lease 不会被代为释放，仍会阻止 exclusive update。

这不是“本地终端天然可信”。`adapter.tui` snapshot 不能携带可执行源码；批准它的 digest 是批准
固定 local-TTY profile 与 `approval.submit.local` scope，runner 实际启动的 compiled Client 仍能
看到终端输入并以该本地用户权限运行。因此 profile、digest 或 scope 更新仍必须重新审核。普通
TUI UID 不持有 approver mTLS/Ed25519 私钥；第二次确认后
它只能通过 PASSWD sudo 启动固定 root-owned submitter。submitter 重新拉权威 plan、写
`/dev/tty` 并要求完整输入 action/server/machine/Target/change/planHash，broker 最终校验
两分钟 TTL grant。这里明确信任本机 root、sudo/PAM 与 TTY 完整性。

## 外部 Adapter 的默认降级

当前 Client 只要发现 `OPS_AGENT_ADAPTER_ID`，就拒绝 Adapter 内的 approve/reject/rollback，
仅允许 `/status`。这是显式 fail closed：现有 BotMux envelope 与 `allowedUsers` 尚不足以证明
端到端审批身份。

未来某个 Adapter 要获得远端审批能力，必须新增版本化 `ApprovalIntent`，至少绑定：

```text
adapterId, principalId, ingressId, conversationId,
privateConversationProof, changeRef, action, observedAt, replayState
```

未来的模型外 approval gateway 必须独立验证这个结构；这里不是当前只做本地 peer/session 隔离的
`agentd-client-gateway`。Adapter 永远不能读取 approver 私钥或直接调用 broker；
远端意图即使可信，也不能绕过 root submitter 的本地交互边界，除非未来另行设计同等级远端
principal 与独立审批设备。
群聊、转发、bot sender、身份字段缺失、去重状态丢失或平台签名失败都应降级为聊天/只读，
提示用户回到 TUI。

## Completion 与断线

Core 通过继承的单向 FD 发送 `completion.v1` NDJSON，而不是执行环境变量提供的 callback：

```json
{
  "version": 1,
  "type": "completion",
  "eventId": "...",
  "outcome": "success",
  "content": "...",
  "sessionId": "...",
  "turnId": "..."
}
```

content 在 Client 侧脱敏并限制为 64 KiB。Adapter 必须严格验证 schema、限制单帧和 transport
stderr，并使用固定 executable/argv；消息正文放入文件或 stdin，禁止 shell 拼接。

一次 turn 以 Pi `0.84.1` 的 `agent_settled` 为权威完成点。retry/compaction/queued continuation
尚未结束时不能发送 completion；`turnId` 去重避免重复发送。agentd socket 断开后 Client 会
解绑并 pause stdin，然后退出；Adapter/PTY supervisor 应创建新进程，不应让死连接 CLI 永久
驻留。

## BotMux 当前实现

BotMux 的主路径是 `plugins/adapter-botmux-source`：真实 `adapter.mjs`、配置 hardener 和 manifest
处于同一获批 digest。固定 root setup wrapper 只负责重验 CAS、创建指向该 immutable entrypoint
的 `pi` wrapper 并降权；实际 Adapter 永远以 `ops-agent-botmux` 运行。legacy `.opspkg` 仅保留
历史恢复与审计证据；任何 Source current/registration/digest 校验失败都直接告警并退出。

它的 descriptor 只声明实际存在的 `text` 入站、FD 4 `bind` 与固定 `send` 出站。当前
`botmux send --session-id ... --content-file ...` 不是 message-ID 级 reply/quote，sender 只影响
mention 参数，因此 manifest 不请求 `reply`、`quote`、`mark`、handoff、compact 或 clear scope。
未来实现其中任一动作都会改变 manifest 与源码 digest，必须重新本地审批。

### 启动和环境

- BotMux daemon、tmux backend 和 secret 都属于专用 `ops-agent-botmux` UID；该账号 primary group
  同名，唯一 supplementary group 是连接 agent client socket、读取 CAS 与 observer identity
  所需的 `ops-agent-client`；它不在 `ops-agent` service group；
- digest-validating runner 直接启动 Source 与 compiled Client 两个 sibling，Source 无权 spawn 或
  替换正式 Client；FD 3 从 Client 传 completion，FD 4 从 Source 传 typed bind/text；
- BotMux 的初始消息与后续消息都必须以 bracketed-paste frame 从 stdin 进入；runner 与 Source
  均拒绝 positional/`@file` prompt，`--session-id`（及 BotMux 兼容的绝对 `--extension`）之外的
  argv 不能成为模型输入；
- runner 用 Source 不继承的 FD 5 向 Client 单次传入已捕获 descriptor、active plugin ID 与 digest；
  Client 重新读取 active registration、取得 exact digest lease，并核对 descriptor 派生 grant；
- Client 启动环境删除 `BOTMUX_*`、`FEISHU_*`、`LARK_*`，Source 仍保留其业务 credential；
- `OPS_AGENT_CORE_ROOT` 只能解析为 `/opt/pi-ops-agent/current`；
- Bash 固定为 `/bin/bash`；PATH 固定为：

```text
/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

`/opt/pi-ops-agent/botmux-bin` 必须含一个真正名为 `pi` 的 wrapper。只配置
`cliPathOverride` 不足以支持 BotMux 的 resume 路径。

BotMux 依赖 `node-pty` native addon；若安装时使用 `npm --ignore-scripts`，必须随后显式构建
并验证 addon，不能把“文件已经下载”当成 Adapter 可运行。

### envelope 与 sender

BotMux model-facing envelope 只有同时存在独立前缀 marker、完整 `<user_message>` wrapper 时
才解包。解析使用**第一个 opening tag 与最后一个 closing tag**，因此用户正文内包含类似
tag 的行不会被截断；sender tag 从 wrapper 之后读取。

sender 只影响回复 mention 语义：

- `type="bot"` 使用 `--no-mention`，避免机器人互相 @；
- `type="user"` 使用 `--mention-back`；
- 这不是审批身份，未知 sender 不会获得 approval capability。

配置 hardener 要求一个 `allowedUsers`、无群聊/global/chat grants、无非 mention listeners，
并设置：

```text
p2pOpen=false
disableCliBypass=true
autoGrantRequestCards=false
autoStartOnGroupJoin=false
autoStartOnNewTopic=false
disableStreamingCard=true
silentTurnReactions=true
writableTerminalLinkInCard=false
```

BotMux 的 `sandbox=false` 只表示不再包第二层未知 sandbox；实际 Agent 工具仍受本项目的
systemd/bubblewrap 限制。

### 消息发送

Adapter 只消费 completion，不发送 working/status card。空 content 不发送；正文写入临时
`0600` 文件，再以固定 `botmux send --content-file` argv 发送。Bot 回复不 mention，人类回复
可以 mention-back。session ID 必须同时匹配 CLI 参数和 `BOTMUX_SESSION_ID`，否则禁用 outbound。

当前尚未实现持久 outbox、跨重启 replay-safe dedup、bot-to-bot rate limiter 和可信远端
ApprovalIntent。它们是生产化 Adapter 的必需后续项，文档不能把现有 BotMux runtime 描述成
完整审批 Adapter。

## Secret

`/botmux-setup` 是精确本地命令，进入模型前被截获。Client 只调用固定 argv
`sudo -k -- /usr/libexec/pi-ops-agent/setup-botmux`。root-owned wrapper 不接受参数，通过
`agentd-pluginctl current --runtime` 重新验证 Source registration、snapshot digest 与
entrypoint，然后只以 `ops-agent-botmux` UID 启动固定 setup runner。Runner 通过固定 lease socket
取得 exact `adapter.botmux` digest 的 shared lease，并持有到 `botmux setup`、snapshot 中的
hardener 和 `botmux restart` 全部结束；hardener 作为 inner bubblewrap PID namespace 的 PID 1
运行，outer 默认 reaper 的 lifecycle FD 与 exact init identity barrier 等 detached 后代完全消失后才允许 lease 继续；lease 丢失会终止当前进程并
禁止后续步骤；
secret 直接进入 BotMux 的交互进程，不进入模型、argv 或 completion。

Wrapper 不读取或执行可编辑 `plugin-sources`，也没有 legacy `.opspkg` runtime fallback。Source
current 不存在，或 registration、digest、manifest、entrypoint、snapshot 任一校验失败时都直接
fail closed；旧 `.opspkg` 仅保留历史 change 的恢复与审计证据，不能被新版 Adapter 执行。

BotMux secret 位于专用账号的
`/var/lib/ops-agent/adapters/botmux/.botmux/bots.json`。Hardener 拒绝 root、其他 home、symlink、
错误 owner 或 group/world readable 路径，原子写入并创建 `0600` 备份。该账号无 sudo，唯一
supplementary group 是 `ops-agent-client`；默认卸载保留这个第三方 secret。

## 开发与测试

使用[`agentd-adapter-dev`](../skills/agentd-adapter-dev/SKILL.md)。至少覆盖：

- spoofed sender、群聊/转发/bot、缺失身份、replay 与 duplicate ingress；
- split UTF-8、bracketed paste、正文含 tag、oversized envelope；
- retry/compaction、exactly-once completion、agentd disconnect 和 PTY recreation；
- fixed spawn/argv、FD preservation、secret environment stripping 和 bounded stderr；
- approval fallback，证明 Adapter 无签名 key 且 critical 永远不能远端确认。
- 在目标 Linux 以 `npm run build` 后由 root 运行 `npm run test:adapter-linux-runtime`，不得用 fake
  bwrap、伪造 effective UID/GID 或普通账号替代 supplementary-group DAC 与 PID namespace 探针。
