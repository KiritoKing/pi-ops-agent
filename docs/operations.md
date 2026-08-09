# 运维、升级、审计与恢复

TUI 是当前唯一可执行 approve/reject/rollback 的保底入口：

```bash
ops-agent tui
```

外部 Adapter 当前只能聊天和 `/status`；即使消息来自配置中的 owner，也不能替代本地审批。

## 日常检查

```bash
systemctl status \
  ops-agent.target \
  ops-agentd.service \
  agentd-client-gateway.service \
  agentd-guardian.service \
  agentd-approval-reviewer.service \
  ops-agent-server.service \
  ops-root-helper.service \
  --no-pager

sudo /opt/pi-ops-agent/current/scripts/healthcheck.sh
```

PVE host 另检查 `ops-pve-root-helper.service`；非 PVE host 不安装该 unit，healthcheck 也会明确
跳过 PVE unit/socket/audit，而不是把缺失当故障。
Server-only join endpoint 使用 `healthcheck.sh --endpoint`；该模式只检查 server、core/PVE
broker、socket、TLS/policy 与 receipt DAC，不要求 agentd、reviewer、plugin 或模型 credential。
PVE broker unit 默认由 `multi-user.target` 启动；controller `init` 另行把它加入
`ops-agent.target`，server-only endpoint 不应出现 `/etc/systemd/system/ops-agent.target.wants`。

### 检查 PID 1 的 effective unit，而不只检查磁盘文件

安装器在每次 `init`/controller upgrade 中验证 reviewer、client gateway、guardian、plugin lease
broker、agentd、server、core broker 与 healthcheck 这八个 managed service；PVE host 再验证 PVE
broker。`join`/endpoint upgrade 的集合严格只有 server 与 core broker，且只有 signed PVE enrollment
与本机 `/usr/bin/pvesh` 双向匹配时才加 PVE broker。非 PVE endpoint 上出现 managed PVE unit/drop-in，
或 join 上出现任一 controller-only service/drop-in，都是 topology drift，不应当作“未启用所以无害”。

每个上述 service 的磁盘 unit 与 unit-specific
`zzzz-ops-agent-security.conf` 必须逐字来自当前 Release；更重要的是，PID 1 的 `FragmentPath`、
`DropInPaths`、identity/lifecycle/command/environment/resource limits 与全部 security
scalar/list/path/capability effective value 必须匹配；还要拒绝带 privilege prefix 的
`ExecStartEx.flags`，以及 release 未声明却由 host drop-in 注入的 writable path。Installer 还通过
PID 1 D-Bus typed properties 精确核对 `Conditions`、`Asserts`、Load/Set/Import credential vectors，
并验证 healthcheck `SuccessExitStatus` 与 agentd final credential drop-in。除 exact managed policy 外，
额外 loaded drop-in 必须是固定位置中 metadata 安全、完整语法落入窄 compatibility-reset allowlist 的
host-wide file；未知 unit-specific 或 authority-bearing directive 会 fail closed。日常定位可先查看：

```bash
systemctl show ops-agentd.service \
  -p FragmentPath -p DropInPaths -p User -p Group -p ExecStart -p ExecStartEx \
  -p NoNewPrivileges -p PrivateDevices -p ProtectKernelTunables \
  -p RestrictNamespaces -p ReadOnlyPaths -p ReadWritePaths -p InaccessiblePaths
```

这只是便于人工定位的子集，不能替代 installer 的完整逐项验证。尤其不要根据
`systemctl cat` 的文本顺序猜 effective list：host-wide `service.d` 可以先清空再重建 list，也可以
覆盖 scalar/command。安装后若 distribution、OrbStack/LXC image 或管理员改变任何 type-wide 或
unit-specific drop-in，应进入维护窗口，保留恢复入口，并用同一 immutable Release、同一
`init`/`join` mode 重新跑安装/升级验证；验证失败时保持服务停止并检查 PID 1 的实际合并结果，不能
删除 final drop-in、放宽 hardening 或只重启 service 来宣称恢复。

当前真实 socket：

```text
/run/ops-agent/agentd/agentd.sock
/run/ops-agent/agentd/backend.sock  # ops-agent owner only, mode 0600
/run/ops-agent/agentd/heartbeat.json
/run/ops-agent/reviewer/reviewer.sock
/run/ops-agent/helper/root-helper.sock
/run/ops-agent/helper/pve-root-helper.sock  # only on PVE hosts
```

Controller healthcheck 会检查 guardian/reviewer/local session gateway unit、公开与 backend socket、
heartbeat freshness 和必要
Plugin registration；endpoint 使用上文的独立模式。它不替代日志与进程身份审计。计划维护时
停止整个 target：

`agentd-approval-submit` 没有 unit/socket，平时不存在进程是正常状态；只在一次本地审批期间
由 PASSWD sudo 启动。

```bash
sudo systemctl stop ops-agent.target
# maintenance
sudo systemctl start ops-agent.target
```

不要仅 kill agentd：guardian 与 systemd restart policy 可能将其拉起。

## 审批操作

Agent prepare 后会输出 opaque `changeRef`。本地 TUI 使用：

```text
/status <changeRef>
/approve <changeRef>
/reject <changeRef>
/rollback <changeRef>
```

approve/rollback 的第一次调用只展示 reviewer 结果并返回 `REVIEW_REQUIRED`。确认计划、digest、
Target、backup、verification 和 findings 后，在两分钟内再次输入同一命令只会启动固定的
`agentd-approval-submit`。随后每次都要输入本地 sudo/PAM 密码，核对 submitter 从 server 重新
取得并以 ASCII-only JSON 写入 `/dev/tty` 的 canonical plan，再精确输入：

```text
APPROVE|REJECT|ROLLBACK SERVER_ID MACHINE_ID TARGET_ID CHANGE_ID PLAN_HASH
```

Plan 在确认前后任何一次查询中变化都会 fail closed；grant TTL 是两分钟。

审批命令只在 agentd ready 且 idle 时开始或继续；agent 正在生成、tool 未完成或有排队 prompt 时
必须先结束该 turn。首次 reviewer 开始后，Client 会一直冻结 Agent 的终端输出，跨越
`REVIEW_REQUIRED` 与第二次相同命令，直到 submitter 的 sudo/PAM/TTY 流程结束。冻结内容最多
256 KiB，ANSI/C0/C1/bidi 控制符会转义；完成后只在醒目的 `delayed untrusted agent output`
分隔区显示。不要把这个延迟区当成 reviewer、broker 或 TTY 证据。

reviewer 不可用、返回多个 frame、超时、planHash 不一致或 risk 结果无法解析时一律 fail closed。
不能绕过 reviewer 或 submitter 直接调用 server，也不能把 Agent 的“这很安全”当审核依据。
不要为省事将专用 sudoers 改成 `NOPASSWD` 或恢复可复用 sudo timestamp。

approve/rollback 还要求当前 Client 持有该 change 在成功 prepare 时形成的
`Session + turn + changeRef + bounded/redacted user intent` 绑定。后续无关输入和其他 pending
change 不会替换它；wrong-turn、冲突或超限输入会使该 change 不可审批。Client 重启或 Session
resume 后绑定有意不从 transcript 猜测恢复，此时应从新的简短用户请求重新 prepare，而不是
复制旧 `changeRef`、构造 fallback intent 或重新提交原 mutation request。

`reject` 不执行 mutation 且不走 reviewer，但仍必须经相同 root submitter 的 PASSWD 与精确
TTY 确认。外部 Adapter 中 approve/reject/rollback 全部拒绝；只允许 status。

升级后若旧 v0.1/v0.2 change 没有当前版本可重新计算的 canonical plan，broker 还必须用旧
`serverId NUL machineId NUL targetId NUL policyRevision NUL capabilityRevision NUL operation-bytes`
算法重算并精确命中 stored planHash，才可在签名 status 中返回 `recoveryOnly=true` 且省略
`plan`。仅仅重建失败、operation 不可解析或任意 hash mismatch 全部 fail closed。这类 change 永远不能
`/approve` 或重新执行。旧 `PENDING_APPROVAL` 只能用本地精确 `/reject` 释放；旧
`COMMITTED`/`RECOVERY_REQUIRED` 仅在权威 status 同时声明 `rollbackAvailable=true` 时允许恢复；
该值必须是 persisted flag 与当前 compatibility/evidence 检查的交集，false 时查看
`rollbackUnavailableReason`。

Recovery-only `/rollback` 不伪造 ApprovalPlan，也不把旧 Agent 说明送给 reviewer。第一次本地
命令显示 critical 的权威 recovery metadata（scope、kind、summary、planHash、revision、backup、
verification、lastError 和 signed `recoveryDescriptor`）；descriptor 绑定原 target/action、精确
compensation、rollbackData digest、backup object digest 与 compatibility version。两分钟内相同
状态下第二次精确命令才启动 PASSWD submitter。因为旧
Session/turn 绑定可能已随升级丢失，这个**仅恢复**路径把精确、模型外、本地 `/rollback` 本身
作为恢复意图；该例外不适用于 live change 或 approve。Submitter 仍在 `/dev/tty` 确认前后各
验证一次 signed status，显示 ASCII-only recovery metadata，并把 action、完整 scope、旧
planHash 与 policy/capability revision 绑定到短期 grant。两次状态任一字段漂移都会中止。

当前兼容矩阵只自动恢复旧 service start/stop，以及有完整 commit evidence 的旧 `file.write`。
对后者，broker 必须确认当前目标仍为 regular/non-symlink、content digest 等于旧 operation、
uid/gid/mode 与旧执行语义一致；旧目标存在时 exact backup 必须位于该 change 的 broker state、
为 root:root 0600 regular file 并绑定 digest，再以当前 dev/ino 做 CAS replace。旧新建文件必须仍为
root:root、mode 为 operation override 或 0644，再以 dev/ino CAS unlink。任一证明失败就保持
`rollbackAvailable=false`；不要手工改 state.json 或把旧 package/plugin/workload executor 当兼容。

### Manual root capsule 与恢复

每个 account 为 `root` 的 Target 都可以让 Agent 准备 `breakglass.script` manual root capsule，
用于 typed operation 与已授信 standing scope 无法表达的最终管理动作。可准备性不等于授权：
该 operation 永不 standing，每个 change 都必须经过本地 TUI 的独立 reviewer、第二次相同
`/approve`、PASSWD sudo submitter，并在真实 `/dev/tty` 上核对完整 canonical plan 后输入精确
确认行。Agent、reviewer 和外部 Adapter 都不能完成批准；非 root Target 与 PVE broker 不提供
capsule。旧 server/core `--allow-breakglass` flag 只保留为兼容 no-op，不应出现在新的安全操作步骤
或 systemd drop-in 中；legacy `breakglass.mode=full-root` 也不再授予额外 authority。

`ops_breakglass_prepare` 必须提供有界完整 script、显式 `backupPaths` 数组和明确 network 声明；
`backupPaths` 可以为空，`verifyScript` 可以省略。verify script 是 caller-provided privileged
postcondition，以相同 root 权限运行，不是独立 verifier。Reviewer 对所有 capsule 固定返回
critical，并在缺 backup、缺 postcondition、批量/动态/破坏性/提权/网络命令时继续显示对应风险，
不能因字段为空而把动作降级为普通审批。`network=false` 只让 transient unit 使用 best-effort
`PrivateNetwork`；full-root script 可以逃逸或委托 PID 1，因此它不是不可逃逸的断网边界。
`network=true` 明确把宿主网络与外部系统风险纳入本次 canonical plan，不形成持久网络 grant。

执行前 archive 只覆盖显式列出的 backup paths，是人工恢复证据，不是副作用的逆操作；空数组
表示没有 archive。所有 manual root capsule 都是 `RollbackAvailable=false`，`/rollback` 不会自动
还原。执行或可选 privileged postcondition 失败后按 `RECOVERY_REQUIRED` 冻结相关资源，核对 script/verify、archive、
audit 和实际宿主状态，再用新的 typed change 或新的、独立审批的恢复 capsule 处理；不要重放原
change。等待终态后保留 change、receipt、archive 和审计证据，不需要也不存在“关闭 capsule
能力”的 kill-switch 清理步骤。

## 权威变更状态

Broker 当前持久状态：

```text
PENDING_APPROVAL -> PREPARING -> EXECUTING -> VERIFYING -> COMMITTED
       |                         |                |
       +-> REJECTED              +-> ROLLING_BACK+-> explicit ROLLING_BACK
                                      |                 |
                                      +-> ROLLED_BACK / RECOVERY_REQUIRED
```

`PENDING_APPROVAL` 对应文档里的 PREPARED。不存在“Agent 说 approved 就算 approved”的状态；
批准事件必须由模型外 principal 产生并进入 root audit。

连接中断或 controller 重启后，只查询原 `changeRef`。不要用相同业务参数重新 prepare 并执行，
否则会得到另一个 change。只有 broker 的 `COMMITTED` 是成功；`ROLLED_BACK` 表示原变更失败后
恢复，不是“最终也成功”。

## 故障恢复

1. 冻结目标资源的新 mutation；必要时停止 endpoint server，但保留 broker state；
2. 读取 `/var/lib/ops-agent/root-helper` 与 root audit，不相信 transcript 总结；
3. 核对 change identity、planHash、policy/capability revision、backupRefs、verification 和
   lastError；
4. `COMMITTED`：独立验证资源；
5. `ROLLED_BACK`：仅对原计划明确提供 rollback 的 operation，核对其备份和恢复后资源状态；
6. `RECOVERY_REQUIRED`：保留所有 evidence，由真实管理员选择显式 rollback 或手工恢复；
7. 恢复后先做只读 smoke，再解除资源锁。

文件原子替换可提供较强回滚；package、service、OCI 和 PVE async task 只有 recipe 定义的有限
语义。`rollbackAvailable=true` 不表示整个外部系统是事务数据库；当前 PVE 与 digest-bound
Hermes/BotMux service operation 均始终返回 false。

普通 operation 在 mutation barrier 后中断时，broker 启动恢复会标成
`RECOVERY_REQUIRED`。PVE mutation protocol v1 的例外是已持久的 `EXECUTING/VERIFYING`：
它保留 VMID lock，并由新 broker 进程从 intent/task/UPID evidence 续跑原任务；只有
legacy/不完整 evidence、丢失 UPID、新鲜 task query 失败或验证失败才 fail closed 到
`RECOVERY_REQUIRED`。不要因为目标资源“看起来正常”手改成 COMMITTED。

### PVE

PVE 对同一 VMID 使用 cluster-global `pve/vmid/<vmid>` lock；node 迁移或 qemu/lxc 类型不能产生
第二把锁。旧 `pve/qemu/<vmid>`、`pve/lxc/<vmid>` state 会在启动时迁移；若两者折叠到不同 owner，
broker fail closed，不能任选一个继续。

PVE operation 的 `Prepare` 只做有界只读观察。进入 durable `EXECUTING` 且
`change_execution_started` audit 已落盘后，broker 才能开始 mutation。每个 primary API 前先 fsync
`pve-primary-intent.json`，再完整重算审批绑定的 guest status/lock、node/quorum、storage、snapshot、
backup set、restore VMID 或 migration source/target/mode；destructive snapshot 在 safety `vzdump`
完成后还要验证 `PreviousStatus` 未变，且 backup set 只增加这一个已记录 volume。intent 写失败或
最终只读检查失败可证明 API 未调用；API 已尝试但 UPID 丢失、task query 不确定或 postcondition
失败则必须保留锁并进入 `RECOVERY_REQUIRED`。

PVE API 启动后，broker 先将 node-bound UPID 同时写入 root-only task record 和 change
evidence，再给审批请求返回签名 `EXECUTING`。这只是“已可恢复接管”，不是成功。
审批 HTTP/CLI 结束或 client 取消不会取消任务；broker-owned singleflight worker 用新的
有界 context 查询原 UPID，终态后执行验证。不需要后续 HTTP 或 `change.status` 来驱动
它；status 只观察签名状态，并可幂等确保 worker 已调度。正常 daemon shutdown 保留
`EXECUTING/VERIFYING` 与 lock，重启时自动续跑。运维可用原 change reference 轮询签名
status，但只有 `COMMITTED` 表示原 UPID 已 `stopped/OK` 且 postcondition 成立。

处理 `RECOVERY_REQUIRED` 时不要新建普通 change，也不要手改 state。先查看 parent 的签名 status、
UPID、intent 和 task evidence。新的补偿必须是当前状态下的 typed PVE operation，并在计划中带
`recoveryOfChangeId=<parent>`。它必须同 domain、endpoint、Target 与 cluster-global VMID，永不
standing，且逐次本地审批。批准前 broker 会按每个已知 UPID 查询权威 status；任何 running、
query failure、unsupported status、lost-UPID intent，或既无结构化 `NO_MUTATION_STARTED` 也无
terminal task proof 的 parent 都拒绝转锁。不要把 active-task 列表为空当成已知 UPID 的终态证明。

只有全部已知 task 明确 `stopped`（`OK` 或 `ERROR` 均作为终态 evidence）且没有 unresolved intent，
或 broker 已持久证明 API 未启动，才会原子执行 parent lock -> child lock：parent 成为
`SUPERSEDED` 并绑定 child ID/planHash、mutation disposition、terminal evidence；restart 不得让
parent 重新获得锁。child 在转锁后任何失败都保留 `RECOVERY_REQUIRED` 与 VMID lock；只有 child
`COMMITTED` 才释放。完整 resolution chain 是审计对象，TTL/配额不得单独删除任一端。

若唯一剩余问题是 parent 为 `STARTED_OR_UNKNOWN` 且没有任何已知 UPID（例如已 fsync primary
intent 后 API response/UPID 丢失，或旧版本根本没有 durable task proof），本地审批 submitter 会在
第一次确认 recovery child plan 后请求 broker-internal unknown-result clearance。它先显示固定 node
active-task 空查询、guest location/status/lock、cluster node/quorum 的完整 challenge，然后要求在
真实 `/dev/tty` 输入第二条包含 server/machine/Target、parent、child、childPlanHash、
`pve/vmid/<vmid>` 与 challenge digest 的 exact confirmation。此流程仍必须由管理员通过 PASSWD
sudo 启动；Agent、reviewer、Adapter 或 workload 不能请求、确认或持有 clearance。

遇到已知 UPID 时不要尝试 clearance：running 或 status query failure 永远拒绝，terminal UPID
回普通 reconciliation。Broker 查询 active tasks 使用官方 node-scoped path
`/nodes/<node>/tasks --source active --vmid <vmid> --limit 1`，migration 同时查询 source/target；
空结果只用于 no-UPID 残余风险判断，绝不替代已知 UPID 的 terminal proof。Challenge/grant 默认
90 秒、只在 broker 内存中存在并一次性消费；超时、broker restart、child reject、任何 live state
漂移或持久化失败都应重新从签名 status 和第一次审批开始，不要重用旧 confirmation。

成功时 parent resolution 的 `basis=local-unknown-clearance`，仍明确记录
`parentMutationDisposition=STARTED_OR_UNKNOWN`，并绑定 observation/active-task/guest/cluster
digests；它表示管理员基于当时观察接受继续恢复，不表示原 API 没有发生。最终 state write 与
parent `SUPERSEDED`、child lock transfer 是一个 transaction；任何一部分落盘失败都必须保持
parent `RECOVERY_REQUIRED` 与原 lock owner。

所有 PVE operation 的 `RollbackAvailable=false`，即使伪造该字段，PVE rollback 仍会被 broker
拒绝。Safety backup 是人工恢复证据，不是自动补偿；restore 固定 `--start 0`，验证 guest 确实
stopped 且 unlocked。任何反向/补偿动作都必须重新 prepare、重新观察、重新审批。详见
[PVE Workload](workloads/pve.md)。

### Hermes/BotMux service workload

对 `workload.service.action`，先从权威计划核对 plugin ID/digest、account、manager、unit、action，
以及准备时的 UID、`LoadState`、`ActiveState`、`SubState` 和 unit user。`system` manager 必须确认
unit 的 `User=` 与账号一致；`user` manager 还应确认 `/run/user/<uid>` 中对应 user manager 可用。

执行超时或 transport error 时，`systemctl` 可能已经改变状态，change 会进入
`RECOVERY_REQUIRED`。先以相同 manager 只读查询实际状态和 journal，不要重放原 change，也不要
手改 broker state。Service action 没有自动 rollback；如果管理员决定重新启动、停止或重启，
应使用当前状态 prepare 一个新的 `workload.service.action` 并完成独立审批。`reload` 要求准备时
已 active 且执行后仍 active；`reset-failed` 要求准备时为 failed 且执行后已非 failed。这两种动作
永远要求逐次审批，不会消费 `workload.service.action` standing grant。多账号故障要按
Target 分开处置，不能把另一个账号或 unit 塞进已有 change。

### Hermes/BotMux fixed command diagnostics

`workload.command.inspect` 不是故障时的 shell fallback。先在 Target policy 核对 exact plugin
ID/digest/profileKey、target/run-as account/home、root-owned executable、完整 argv、timeout 与 output
bound。CLI 或任一祖先目录若由业务账号拥有或可被 group/world 写，broker 会在启动 transient unit
前拒绝；应由管理员修复为 root-owned pinned install 或撤销 profile，不能放宽为 warning。

成功 response 必须带 core broker receipt，且 Client 要以 pinned core public key 验证
server/machine/Target/method/plugin/digest/profile/result digest。Root/Agent audit 只提供 output
digest、UTF-8 bytes 与 truncated；正文只存在于当前有界 tool result。BotMux `setup list --json`
shape 变化或 sanitizer 失败时，不要把 raw JSON 复制到对话或审计；升级/修正 source workload、
重新计算 digest、重新审批注册，并在更新后的 root policy 中显式换 digest。

### BotMux policy-mapped config edit

变更前先核对 active `workload.botmux-ops` digest 与 Target 的 `jsonConfigWorkloads` 完全一致。
ApprovalPlan 必须展示 semantic profile/selector/field、tagged requested value、目标账号 UID、实际
config/selector/field mapping、before/after、config digest/identity 和整文档 semantic rewrite；工作
目录字段还要显示 root/directory identity 与 post-verification pathname replacement residual。
缺任一项都拒绝并重新
prepare，不能手工补充解释后继续。

这类 change 只接受本地 TUI 的两次相同 `/approve`，并在第二次提交期间固定 exact source digest；
远端 Adapter、reviewer 或 standing grant 都不能批准。执行成功后检查 signed `COMMITTED` 和 exact
after digest，再单独 prepare service restart。若状态为 `RECOVERY_REQUIRED`，不要直接编辑
`bots.json` 或删除 sealed evidence：先比较 root audit、current digest 与 broker 保存的 before/after；
只有 exact after 才可按当前 change rollback，其他内容漂移需要新的恢复计划。升级后 healthcheck 还
应确认 `/usr/lib/ops-agent/agentd-json-config-helper` 为 `root:root 0755` 且与 current release 相同。

## Source Plugin 运维

查询必要 Plugin：

```bash
/opt/pi-ops-agent/current/bin/agentd-pluginctl current \
  --root /var/lib/ops-agent/plugins \
  --plugin-id adapter.tui

/opt/pi-ops-agent/current/bin/agentd-pluginctl current \
  --root /var/lib/ops-agent/plugins \
  --plugin-id workload.base
```

只有希望通用 `file.write`/`service.action` 复用长期授信时，才把上面权威 registration 的 exact
digest 写入 Target：

```json
"authorization": {
  "standingScopes": ["service.action"],
  "baseWorkloadDigest": "sha256:<exact-current-workload.base-digest>"
}
```

这不是安装器自动推导的默认值。`workload.base` 更新后旧值不匹配，broker 会回落到逐次审批；
管理员必须重新审阅 Source registration 和 Target policy，不能只改 symlink 或沿用旧 grant。

更新流程必须是 editable source → inspect → typed `plugin.register` prepare → reviewer/人类批准
→ broker re-hash/register/verify。权威 plan 必须完整展示并绑定 ID、kind、version、publisher、
digest、capabilities 和排序后的 requestedScopes；Adapter plan 还必须显示 runtime identity、宿主
filesystem/network、runtime UID 可读 credential，以及 action scope 不约束源码 direct platform
call。broker 在 prepare 与 execution 时都从受控源
目录重新扫描并逐项核对。Runtime 从 immutable snapshot 读取 registration，禁止直接编辑
snapshot 或手工替换 `current`。

每个 Workload invocation 会以真实 UID 连接固定 lease broker socket，为 exact current digest 持有
shared registry lease；client runtime 不读取 `root:ops-agent-lease` lock directory。注册、激活、
停用使用同一 plugin lock 的 non-blocking exclusive lease。若更新返回
`active source-plugin runtime`，说明旧 digest 的 Workload/Adapter 调用已经进入明确的 in-flight 区间：本次更新在
原子切换前失败，`current` 仍是旧 digest，broker 应显示 `ROLLED_BACK`，待调用结束后重新 prepare/
approve 更新，不要手改 symlink 或强杀 agentd。相反，更新先取得 exclusive lease 时，旧 Session
的新调用会要求 reopen。更新前已得到签名 `PENDING_APPROVAL` 的旧 digest 计划仍可 reject，且
需要时保留 rollback recovery evidence；但新 digest 成为 current 后不能再 approve 旧计划，必须
重新 prepare。第二次 plugin-bound approve 的 Client/lease-broker shared lease 是前置纵深防御；
root submitter 会在第一次签名 status 后独立解析 canonical 单一 workload ID/digest，直接验证固定
registry 的 current 并持有自己的 exact digest shared lease，覆盖 reviewer、TTY、第二次 status 与
最终 broker action。即使 Client 或 lease broker 随后断开，root lease 仍保持；不能只在提交前重读
一次 `current`，旧计划也不会自动继承新 digest 的 standing grant。候选注册/安装/部署与 rollback
不要求其 digest 仍为 runtime current。

Release 升级只会自动推进仍与上一版 bundled tree 完全一致的
`/var/lib/ops-agent/plugin-sources/<name>`；检测到任何本地修改就原样保留并提示管理员。
无论哪种情况，新 digest 都不会继承旧授权：管理员必须审阅 diff、生成新 digest 并重新批准；
若 Core 需要新 capability 而本地 source 未更新，应在启动前 fail closed，而不是静默扩大旧 grant。

Source Plugin register 已进入 broker change/audit 状态机，并保留旧 digest 作为 rollback evidence。
底层 `agentd-pluginctl register` 仍存在，只允许安装器 bootstrap 和离线恢复使用；日常运维绕过
broker 直接运行它，不会形成 change/reviewer/nonce 证据，不能视为标准安装。

旧 `.opspkg` change 的状态与 rollback metadata 仍需保留。不能在迁移 Source Plugin 时删除
`/opt/pi-ops-agent/plugins`、legacy catalog 或 root-helper change 记录，直到所有已部署 artifact
完成恢复演练。

## Adapter 运维

Adapter 生命周期：

```text
SOURCE_REVIEWED -> REGISTERED -> CONFIGURED -> VERIFIED -> ENABLED
                                           \-> DEGRADED / DISABLED
```

每次更新重新验证 sender、私聊/群聊、forward/bot、ingress replay、completion exactly-once、
disconnect 和 approval fallback。任何一项失败都不能保留审批能力。

本地 `ops-agent tui` 不允许绕过 Source registration：固定 runner 每次重验 `adapter.tui` 的 CAS
digest、固定 `profile.json` 和 current 防漂移，再启动 release 内 compiled Client；它不会执行
TUI snapshot。缺失、损坏、夹带 executable 或过度授信时 fail closed。Client 以本地用户权限
运行并能观察终端；runner 与 Client 分别通过固定 lease broker socket 为 exact adapter digest
持有 shared lease 到 Client 退出。普通更新若遇到旧 TUI/Adapter runtime，会在切换 current 前失败，
待旧进程退出后重试。当前 TUI 更新自身时，只允许一个单步 canonical `adapter.tui plugin.register`
在第二次本地确认后执行受控 quiesce：停止输入、关闭 Agent Session、依次等待 Client lease 与外层
runner lease 的 release acknowledgement，再启动 submitter；旧 Client 无论 register 成败都退出，
因此之后需重新运行 `ops-agent tui`。另一 TUI/runtime 仍持 lease 时更新仍 fail closed，不要删除
lock 或手改 `current`。profile digest 更新
必须重新批准；root 签名 key 仍只在独立 submitter 中。

### BotMux

BotMux setup guard 以实际 host evidence 为准，而不是只识别 Ubuntu Noble。任何 host 读取到
restricted-userns=`1` 且 AppArmor=`Y/y` 时，真实 `NoNewPrivileges=yes` main→pi wrapper chain 都在
wrapper/config mutation、hardener 或 restart 前 unsupported/fail closed；Noble 缺少/无法读取
restriction evidence 也拒绝，其他 host 只有该 sysctl 安全不存在时才可跳过。core/base host-policy
helper 仍只支持 Noble，且不覆盖 BotMux 链；给 BotMux main 复制 `AppArmorProfile=-bwrap` 会让 wrapper
过早进入 `unpriv_bwrap`，阻断后续 sandbox setup。direct Adapter probe 成功也不能解除该 guard。

`/botmux-setup` 只在本地 TUI idle 且有 TTY 时运行。Client 固定调用
`sudo -k -- /usr/libexec/pi-ops-agent/setup-botmux`，wrapper 不接受参数；通过 PAM 后，所有 BotMux
命令和 Source snapshot 中 digest-approved hardener 都降权到 `ops-agent-botmux`。Wrapper 先用
`agentd-pluginctl current --runtime` 复核 registration/snapshot，再以该 UID 启动固定 setup runner；
runner 通过 `/run/ops-agent/plugin-lease/lease.sock` 为 exact `adapter.botmux` digest 持有 shared
lease，直到 `setup`、hardener 与 `restart` 全部完成；hardener 在 inner bubblewrap PID namespace
内作为 PID 1，runner 必须等 outer 默认 PID 1 reaper 的 lifecycle FD EOF 与 exact init identity
消失，证明 detached 后代完全清理。Lease 丢失会终止当前子进程且禁止后续步骤，
并发注册只能在切换 `current` 前失败。active Source registration 缺失、current 无效或任一
snapshot 校验失败都直接中止；legacy `.opspkg` 只保留 artifact/change/rollback 恢复证据，不能
作为新版 Client 的 runtime fallback。配置前创建 `0600` 备份；secret
位于该账号的 `/var/lib/ops-agent/adapters/botmux/.botmux/bots.json`，不进入 Agent。排障重点：

- `bots.json` owner/mode、唯一 `allowedUsers`、无 group/grants/listeners；
- `/bin/bash` 与固定 PATH；
- `/opt/pi-ops-agent/botmux-bin/pi` wrapper；
- `ops-agent-botmux` 为非 root、primary group 同名、唯一 supplementary group 为
  `ops-agent-client`，不在 `ops-agent` service/sudo/reviewer/server group；
- `node-pty` addon 实际加载；
- runner 的 Source/compiled Client sibling 均为 `shell:false`，FD 3 completion、FD 4 typed
  bind/text 与仅 Client 可见的 FD 5 descriptor/digest context 都存在；初始与后续消息均来自 Source
  stdin 的 bracketed-paste frame，Source/Client argv 与 `@file` 均不能携带 prompt；
- agentd 断开后旧 CLI/PTY 退出；
- user reply mention-back，bot reply no-mention；
- streaming card/reaction 自动化关闭。

当前没有持久 outbox、bot rate limit 或可信远端 ApprovalIntent。Adapter 失败不应影响 TUI；
禁用/回退 Adapter 默认保留其 dedicated-account config 与 secret。

## 程序升级

程序位于 immutable 版本目录：

```text
/opt/pi-ops-agent/
├── current -> releases/X.Y.Z
└── releases/
    ├── X.Y.Z/
    └── X.Y.(Z+1)/
```

配置、credential、Session、plugin source/snapshot、change、backup 和 audit 位于 `/etc`、
`/var/lib`、`/var/log`，不随 `current` 切换。升级前：

1. 验证 tag/checksum/attestation 与 package/client/plugin manifest 版本一致；
2. 备份 current link、`targets.json`、server registry、endpoint 的 `endpoint-enrollment.json` 和
   plugin registrations；
3. 检查 TS/Go protocol、capability revision、persisted change 和 config schema 兼容；
4. 确认没有 PREPARING/EXECUTING/VERIFYING/ROLLING_BACK change，停止 target 与 core/PVE broker；
5. 检查新 release 的 unit hardening、account 和 source-plugin diff；
6. 核对 release verifier 已证明 archive/deb payload 完全一致、七个 Go artifact 为目标架构静态
   binary、固定 Node runtime 已语法检查全部 compiled JavaScript 并实际执行 Client/Reviewer smoke，
   且旧 root watchdog 不在 payload；
7. 在隔离 systemd 环境做 upgrade + rollback smoke。SBOM 是依赖清单，archive/deb 的逐字内容
   完整性仍以 asset checksum、manifest 和 provenance attestation 为准，不能把 SBOM 当文件签名。

Installer 会先停 agentd/server ingress、检查两个 broker store，并拒绝仍 active 的 broker；这
是显式离线升级，不会通过强停 PVE 长任务制造 `RECOVERY_REQUIRED`。随后生成候选 policy，备份
旧 `targets.json`，再切换 `current`。从账号/组变更开始，
runtime/server/TLS/approver、unit/drop-in、Source 工作树、plugin registry、sudoers、wrapper 和原
unit 状态都处于同一个 root-only 回滚事务；激活、plugin registration 或 sudo 有效策略探针
失败都会恢复，而不是只恢复 link/policy。Adapter state/secret 与 broker state/backup/audit
不进入整树 snapshot。服务在 commit 后才启动；此后的 start/health 失败保留新版本与证据，
不会竞态恢复旧 registry/config。已有 config 不覆盖，新默认写相邻 `.dist`。升级不得自动新增
artifact、PVE guest/storage、read path 或 requested scope。

unit/drop-in snapshot 也必须按 topology 分开：`init` 覆盖 Release 中全部 controller managed unit、
全部 managed service drop-in directory 和待清理的旧 managed `zzzz-ops-agent-*` 文件；`join` 只覆盖
server/core/PVE 三个候选 unit 以及各自 drop-in directory，其中 PVE directory 在 enrollment 判定前
也先无条件纳入 snapshot，避免 conditional install 产生未记录的回滚面。安装只写当前 mode
适用的集合；non-PVE `init`/`join` 会移除 stale managed PVE unit/drop-in，但不得删除该目录中的
第三方文件或 PVE state/audit。`daemon-reload` 后、服务启动前，任一 applicable service 的 exact
unit/final drop-in 或 PID 1 effective lifecycle/security vector 不匹配，都在同一事务内回滚。

多 endpoint 管理域先升级能解析新 schema 的 controller，再升级 endpoint。没有 capability
negotiation 时，旧 controller 遇到未知 capability 应 fail closed。

Server-only endpoint 使用同一 `join` 入口升级，但不得重新使用或新签 enrollment bundle。传入
原 controller URL 与经独立渠道核验的同一 CA fingerprint，并省略 `--token-file`；installer
检测到既有 endpoint surface 后调用新 Release 的 `validate-enrollment`，只读验证
`endpoint-enrollment.json`、identity、当前 policy schema、TLS、DAC 与 core/PVE receipt keypair。
若 endpoint state 只存在一部分、任何 trust material 损坏、PVE host fact 改变，或同时提供了
新 bundle，升级必须在 config 阶段失败并由安装事务恢复旧 release/config/unit 状态。不得删除
单个文件来骗过 fresh 检测，也不得以自动 enrollment 覆盖现有 identity/policy；真正重新接入
必须先显式退役 controller registration 和整个 endpoint topology，再签发新的短期 bundle。
旧版本若在 PVE endpoint 留下唯一的
`ops-agent.target.wants/ops-pve-root-helper.service`，新 installer 会在同一回滚事务中验证并清理；
若该目录含其他 entry、不是 root systemd 目录，或 symlink 不指向固定 PVE unit，升级 fail closed。
Controller 卸载也会精确移除这条 `add-wants` dependency；若 unit-state 卸载事务中断，则先恢复
原 enable/active 状态和同一条固定 symlink，再报告失败。

Ubuntu Noble restricted-userns 的 AppArmor profile 不是普通 release 文件。升级 controller 前先用
固定同一新 Release 的 `ops-agent-bootstrap host-policy inspect` 做持锁、无 probe 的只读 eligibility
核对，再依次运行 `host-policy install` 与 `host-policy status`；Raw 入口必须在每次调用都固定同一个
`OPS_AGENT_VERSION=vX.Y.Z`，离线 tar 使用 release-root wrapper，`.deb` 使用 `/usr/sbin` launcher。
离线 archive 必须由 root 解入独占 `0700` staging；禁止从用户/Agent 可写目录 sudo 执行 wrapper，
其 root path-chain/release-tree owner 与 DAC 校验失败时不得通过复制单个 helper 绕过。
`status` 不修改持久 policy，但在 `managed:enforce` 时会在同一独占目录锁内创建并清理新的
短生命周期 static authority smoke，只有输出 `verified-now` 才是当前时点证据。只有 helper pin 的
package/version/source hash/local-rule bytes、批准前完整展示的 authority-summary hash 与当前 host
exact 匹配，管理员按 canonical approval digest 在模型外重新确认 `install`，helper 的
`NoNewPrivileges=yes` authority smoke 和 installer preflight 都通过，才可把 core/base 视为支持。
当前 GitHub-hosted Noble exact static unit 已证明 outer 的 `--proc /proc` 在
`ProtectProc=invisible` 下返回 `EPERM`。修正候选只移除 outer proc remount：outer 仍保留
user/ipc/pid/net/mnt namespace、默认 PID 1 reaper、sync/info/exact-identity completion barrier，
并继承 systemd-protected service proc 视图来启动固定 inner；inner 仍用 `--proc /proc`，最终 Source
只看见 inner 私有 procfs。这不是 PID containment 降级，但在同一 hosted gate 成功前仍不得称为支持。
任一 version/hash/rule 漂移都必须随新 Release 重新审阅、重新批准；不能用旧 helper 静默覆盖。Agent、
sudoers 与 `join` 永远不能触发这项宿主 policy 维护，也不能以改 sysctl、SUID/unconfined 或单层
bwrap 规避失败。该合同不改变事实优先 BotMux guard：任何 host 实际读到 restricted-userns=`1` 且
AppArmor enabled 时，真实 main→pi wrapper chain 都在 setup mutation 前 unsupported/fail closed；
direct Node Adapter probe 不能作为升级验收证据。
若 fresh helper install 在 kernel profile 可能已 load 后失败，恢复绝不自动调用 parser remove；
只有权威 kernel evidence 证明 `bwrap`/`unpriv_bwrap` 均 absent 才删除本轮 exact fresh files，
loaded/partial/unreadable 则保留 files 与 kernel state、报告 `INCOMPLETE`，不能把它当作已回滚。
若状态原本是 exact managed files + kernel absent，reload 或 smoke 失败同样保留既有 files 与 kernel
evidence；helper 不把它伪装成安全 absent，也不自动卸载 profile。

### 回退

```bash
sudo systemctl stop ops-agent.target
sudo ln -sfn releases/<old-version> /opt/pi-ops-agent/current
sudo systemctl daemon-reload
sudo systemctl start ops-agent.target
```

实际操作应使用 installer 保存的 policy backup并以原子 link replacement 完成；上面只表示
恢复目标，不应在自动化里直接覆盖未知 link。代码回退不能自动逆转数据 schema。若新版本已
写入旧版本不认识的 state，必须使用明确迁移/恢复工具，不能硬启动旧 broker。

## Credential 与证书

模型 credential：

```bash
sudo /opt/pi-ops-agent/current/scripts/encrypt-credential.sh --force
sudo systemctl restart ops-agentd.service
```

Agent、approver、admin、Adapter 和 workload credential 必须分开。Approver mTLS 与 Ed25519
signing key 在 `/etc/ops-agent/approver/root`，是 root:root `0600`，普通 TUI/Adapter UID
不可读；轮换后检查旧 `/etc/ops-agent/approver/<admin>` 副本也已收回为 root-only。轮换 endpoint mTLS 时先配置重叠
有效期并验证 server/machine identity，再吊销旧证书。IP 未变化不能替代 identity pin。

Broker receipt key 与 ApprovalGrant key 分开。Core/PVE 私钥均为 root:root `0600` 且互相隐藏；
轮换必须先在 controller 的对应 server registration 原子更新公钥/key ID，再部署匹配私钥并
验证 signed status，不能只替换 endpoint 私钥。远端公钥路径按 serverId 不可覆盖；key ID 的
作用域是该 registration，并非全局 key locator。

Enrollment bundle 是短期 bearer；当前无在线一次性消费，成功后立即删除全部副本。重新签发或
转移 bundle 时，controller CA SHA-256 pin 必须经独立的已认证渠道重新核验，不能从 bearer
bundle 或同一中转消息中学习；endpoint 缺少或不匹配该 pin 时应拒绝 enrollment。BotMux secret
不受 systemd credential 管理；按第三方账号的 owner-only 文件策略轮换。

## 策略与 identity 漂移

以下变化必须中止新 approve并要求管理员检查：

- serverId/machineId、证书 pin 或 endpoint identity 变化；
- Target UID/GID、unit/path、PVE node/guest/storage 变化；
- capability 或 Source Plugin digest/scopes 变化；
- prepare 与 approve 之间 policy/capability revision 变化；
- precondition、backup 或 verification digest 变化。

Status 可以查询旧 change；新的 approve 不能跨当前 revision。Rollback 使用原 change identity、
plan 和持久 recovery metadata，但仍需当前模型外 principal。

## 审计

检查：

```bash
sudo journalctl \
  -u ops-agentd.service \
  -u agentd-guardian.service \
  -u agentd-approval-reviewer.service \
  -u ops-agent-server.service \
  -u ops-root-helper.service \
  --since today

sudo less /var/log/ops-agent/root-helper/audit.jsonl
```

至少关联：adapter ingress、principal、Session/turn、server/machine/Target、request/change/plan、
policy/capability revision、approval nonce、backup、verification、rollback。Guardian 只记录
heartbeat/identity/termination；reviewer 只处理 plan 与用户意图 digest。Root audit 不应由
`ops-agent` 可写。

Hash-chain 不能抵御宿主 root 同时替换程序与日志。生产环境应将 audit digest/records 只追加
发送到独立系统；当前项目尚未实现这一外部锚定。

## 卸载

默认意图是删除程序/unit，保留配置、credential、Session、plugin snapshots、backup 与 audit：

```bash
sudo /opt/pi-ops-agent/current/scripts/uninstall.sh
```

脚本先停 agentd/server ingress，并检查 core/PVE broker store；发现四个 transient state 中任一
状态会恢复 ingress 并拒绝卸载，绝不先强停长 PVE task。随后只有在所有 active managed unit
均确认停止、enabled unit 均成功禁用后才删除文件；任何 stop/disable 失败都会中止。若
`ops-agent-botmux` 仍有进程也会中止。进入文件删除前，脚本会保存所有受管 unit 的
active/enabled 状态；上述失败会尝试完整恢复，恢复不完整时明确报错而不会声称卸载成功。默认保留
`/etc/ops-agent`、`/var/lib/ops-agent`、`/var/log/ops-agent`、所有 service accounts，以及
legacy 恢复所需的 `/opt/pi-ops-agent/plugins`；其余 release、wrapper、unit、drop-in、tmpfiles
和专用 sudoers 会删除。

默认卸载永久保留 helper 管理的宿主 AppArmor profile/local rule；卸载脚本不会把 host-wide
authority 当作普通项目文件顺带删除。本 Release 虽保留 `configure-noble-bwrap-apparmor.sh remove`
命令形状用于明确拒绝，但调用永远 fail closed，不接受 `--maintenance-safe` 或 REMOVE approval。
原因是用户态扫描“当前没有 active `bwrap`/`unpriv_bwrap` label”后，仍可能有新进程在卸载 kernel
profile 前进入 setup profile，无法把检查与 unload/remove 原子化。不要用停止已知 service 或重复
扫描把这条竞态误写成安全。

确需移除时必须另行设计和审计宿主级维护流程，处理新 exec admission、kernel profile unload 与
文件恢复的一致性；它不属于本 Release 的自动卸载或 helper authority。状态不确定时保留文件与证据
并 fail closed。`join` endpoint 从不管理这项 policy，因此也没有对应清理动作。

永久清理：

```bash
sudo /opt/pi-ops-agent/current/scripts/uninstall.sh --purge-state --yes --remove-user
```

`--purge-state` 不可恢复，并会删除 credential、plugin grant、change、backup、audit 和 legacy
plugin。它不能由 Agent 或外部 Adapter 自动批准。`--remove-user` 只允许与
`--purge-state --yes` 同时使用；届时才删除 `ops-agent`、`ops-agent-server`、
`ops-agent-reviewer`、`ops-agent-botmux`、`ops-agent-lease` 账号、同名组及 `ops-agent-client`
group。执行前仍应确认这些专用 identity 没有
被站点上的其他服务误用。
