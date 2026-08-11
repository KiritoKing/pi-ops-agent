# 安全模型

## 安全目标

Pi Ops Agent 保护的是**未授权边界**，不是人为限制最终管理员能做什么：

1. Prompt、模型、日志、工具输出、Adapter 或 `agentd` 被控制后，不能自行批准或取得 root；
2. 未获批准的 plugin 代码和 scope 不会成为持久能力；修改源码后旧批准不能复用；
3. Agent 发起的普通 root 操作只能落入 root broker 的已知 tagged union 和 root-owned policy；
4. 每个写操作能关联计划、审批、备份、执行、验证、终态和恢复证据；
5. 断线、重试和重复消息不会以新的 requestId 静默重放同一次 mutation；
6. 一个 Session/Target 的权限不能借模型参数扩展到另一个 Machine、账号或资源。

内核漏洞、root broker/approval submitter 实现漏洞、已获得宿主 root 的攻击者、被控制的
sudo/PAM/TTY 栈和被控制的已授权上游二进制不在此模型能完全防御的范围内。Prompt 和 System
Prompt 只帮助模型表现，不能替代协议、OS 隔离或人工审批。

## 不可信输入

以下内容全部按不可信数据处理：

- 用户 prompt、Agent 的解释和“我只会做……”等承诺；
- 日志、文件、命令输出、PVE API 响应、网页和历史对话；
- Adapter envelope、sender 字段、群聊/转发元数据和 webhook 重试；
- server capability、插件 manifest、publisher 名称和“第一方”标签；
- package/image 元数据、外部 registry 和 enrollment bundle 的复制件；bundle 内携带的 CA 也不
  是信任锚，只有其证书 SHA-256 与独立、已认证渠道传入的显式 pin 匹配后才能使用。

审批 reviewer 刻意不读取 Agent 的自然语言解释。它只看 Client 在成功 prepare 时按
Session/turn/change 不可变绑定的真实用户非命令输入和 broker
返回的规范化计划。普通 `file.write` 的完整有界正文、digest 与 bytes 都进入计划；正文缺失或
疑似 secret 时 reviewer 将风险提升为 critical，提示改用专用 credential flow。manual root
capsule 必须包含有界的完整 script text 及其 digest；verify script 与 backup paths 可以为空，但
缺少其中任一恢复/验证证据时 reviewer 必须增加 critical finding。这让 reviewer 检查真正要写入
或执行的内容，同时不读取 Agent 叙事和计划外数据。
Reviewer response 本身也按不可信边界处理：除了内部 canonical `reviewDigest`，Client 还逐次要求
`reviewId`、`planHash` 与请求完全一致，`userIntentDigest` 等于本次 bound user input 的 canonical
digest，并拒绝任何不属于该 plan 的 `finding.stepId`。只匹配 planHash 不能证明结果属于当前
review request 或用户意图。

## 分层强制控制

| 层 | 强制机制 | 不能证明什么 |
|---|---|---|
| Harness | 关闭 Pi built-in tools/skills/extensions；只注册 active Source descriptor/manifest capability 一致且 provider-name required scopes 获批的工具 | 不能阻止 Core/provider 自身漏洞 |
| Sandbox | `ops-agent` 非 root；Source Workload host 与 `ops_bash` bubblewrap 无网络、系统只读、仅当前 workspace 可写；固定 root-owned runtime、cap-drop、nested-userns deny 与 `prlimit`；任一边界不可用时初始化 fail closed | 同 UID guardian 不是隔离边界 |
| Session | Machine/Target 首次绑定后不可改，policy/capability revision 进入上下文；local session gateway 用真实 peer UID + Adapter ID/digest 派生 namespace，并为每个 namespace 维护进程全局 live-writer lease | gateway restart 会断开全部 writer；该租约不是跨主机分布式锁，也不隔离共享同一 Adapter OS UID 的进程 |
| Local client transport | 公开 socket 只到 `agentd-client-gateway`；`SO_PEERCRED`、active registration exact digest、strict hello、owner-only agentd backend | group DAC 只提供可达性；gateway 与 agentd 同 UID，不能防御该 UID 或宿主 root compromise |
| Transport | HTTPS/TLS 1.3、mTLS 单一且显式的 agent/observer/approver role、严格 JSON、deadline、有界 body/response | LAN 与 IP 不代表身份；observer 只能 status |
| Server | 专用非 root UID；角色与固定 Machine/Target 转成 Unix RPC | Server 被控后仍可滥用已授予的 prepare/read 范围 |
| Root broker | root、PrivateNetwork、Unix socket、`SO_PEERCRED`、typed union、root-owned policy、domain-separated signed receipt | broker 或宿主 root 被控时不能自保 |
| Approval | 显式 standing scope 或精确 client 命令、独立 reviewer、PASSWD root submitter、TTY 精确确认、Ed25519 grant、revision/nonce 绑定；每次 prepare 后验证 signed status | submitter 是 root HTTPS client；信任本机 root 与 sudo/PAM/TTY 完整性；reviewer 当前不做 AST、模型推理或风险型自动批准 |
| Plugin | 严格 manifest、源码 tree limit、digest、不可变 snapshot、scope grant；独立非 root lease broker 以 `SO_PEERCRED` 绑定 runtime UID/plugin class，client 不可读 lock | 已批准 plugin 代码仍可能恶意；lease broker compromise 可阻塞更新但不能批准或取得 root |
| Recovery | 写前准备、fsync mutation barrier、验证、自动回滚或 `RECOVERY_REQUIRED` | package/service/PVE 等操作不都是完整事务 |

模型 provider 的 `200` response headers 或持续 SSE keep-alive 都不是进度/完成证据。agentd 对每个
Pi turn 使用固定 180 秒 absolute monotonic deadline，显式关闭 OpenAI-compatible provider 内层 retry，
且不允许 token、keep-alive、Pi 串行 retry 或 compaction 延长总时限。deadline 后必须先以一次
`AgentSession.abort()` 取得 idle completion barrier，随后才可清除 turn correlation 或向 Client 返回
固定 timeout error；迟到的 `agent_settled` 不可转成 `done`。abort 立即拒绝或 10 秒 grace 到期都表示
旧执行是否仍在运行不可证明，必须 poison Session 并让 agentd fail-stop/systemd restart，不能在同一
进程中自动重放 prompt 或接受下一个 turn。

backend `hello` 的 canonical `SessionId` 另受 agentd 进程内 opaque-token reservation 保护；reservation
从 strict hello 解析后、异步 open 之前开始，贯穿 active turn 与 disconnect cleanup。断连不会直接
`dispose()` 或释放名字：cleanup 必须复用 active turn 的同一 abort latch，并在 10 秒内同时取得 Pi
idle barrier 与 prompt wrapper quiescence；只有该证明或明确 open failure 才能 compare-delete 原 token。
abort 拒绝、hang 或 wrapper 未静止都会一次性 poison/fail-stop 并保留 reservation，所以 external gateway
释放 writer 后也不能让旧 provider/tool 与新同名 Session 在同一 agentd 进程并发。这个 reservation
不是跨进程锁；fatal recovery 依靠 systemd 的新进程，并且恢复后仍须先查询 broker 权威状态，不能自动
重放旧 prompt。

`AgentSession.abort()` 在 Pi internal preflight 尚未提交时会因 idle 立即 resolve，不能单独作为取消
证明。agentd 因而绑定 pinned Pi `preflightResult(true)` 同步 callback：若 close/manual abort/deadline
已经请求，callback 在 `_runAgentPrompt()` 前抛错并阻止 main agent run 及其工具、同时保持零 Pi abort；
否则先不可逆标记 committed，Pi 在同一同步栈进入 active run，随后共享 latch 才能调用 abort。该 callback
晚于 pinned Pi 的 `_checkCompaction()`，所以 auto pre-compaction 可能已经使用模型并产生 compaction
history；这里只能把它约束在同一 grace 和 Session reservation 内，不能声称零模型流量。raw Pi prompt
resolve/reject 使用独立 finished signal，避免 deadline 等 latch、latch 又等外围 wrapper 的循环；如果
pre-compaction 没在 grace 内结束则 fail-stop 并保留 reservation。disconnect close 仍要求外围 wrapper
quiescence，不能用 raw finished 直接释放 Session reservation，也不能自动重放旧 prompt。

### systemd effective 配置也是安全边界

Repository 内的 base unit 不是 PID 1 最终执行配置的充分证据。systemd 会合并 distribution、container
runtime、`service.d` 与 unit-specific drop-in；其中一个更晚的 scalar override 或 list reset 就可能把
`NoNewPrivileges`、`PrivateDevices`、namespace/path allowlist、capability bounding set 或实际
`ExecStart` 改回更宽权限。攻击者不需要修改 Release 内的文件即可利用这种配置漂移，因此 installer
不能只做 `cmp`、`systemd-analyze verify` 或检查某个 `zzzz` 文件存在。

每个 installer-managed service 都必须随 Release 提供 unit-name-specific final
`zzzz-ops-agent-security.conf`。Installer 在 `daemon-reload` 后同时验证两层证据：

1. installed unit/drop-in 是 exact Release 的 `root:root 0644` non-symlink single-link file，PID 1
   的 `FragmentPath`/`DropInPaths` 也确实引用它们；
2. PID 1 返回的 lifecycle/identity/command/environment/resource limits 与 security
   scalar/list/path/capability effective vector 和 Release 预期一致；`ExecStartEx.flags` 必须为空，
   未声明 `ReadWritePaths`/`SupplementaryGroups` 时相应 effective set 也必须为空，且没有额外
   pre/post/reload/stop command 或第二个 `ExecStart`。`Conditions`、`Asserts` 与 Load/Set/Import
   credential vectors 必须通过 PID 1 的 typed D-Bus property 与 exact unit 比较，healthcheck 的
   `SuccessExitStatus` 也必须精确；agentd generated credential drop-in 必须逐字、metadata 与 loaded
   path 同时匹配。

`ImportCredential=` 是 systemd v254 才加入的 service property。对暴露该 property 的 PID 1，installer
仍要求 typed `as` 且精确为空；property query 的任何失败都不能按错误文本忽略。唯一兼容例外是 PID 1
的 typed `Manager.Version` 为 canonical 且 major `<254`、同一个已加载 unit object 的
`Introspect` 明确包含唯一结构化 Service interface、4 个既有 credential property anchor 均以精确
type/access 唯一存在、但不存在 `ImportCredential` property，并且 exact unit、
managed drop-in 与完整 PID-1-loaded `DropInPaths` 闭包都只包含空的 `ImportCredential=` reset 或完全
不包含该 directive。三项证据同时成立时才把缺失 property canonicalize 为 typed empty vector；version
畸形、未来版本缺 property、introspection 结构/anchor 不符、非空/续行/含混 directive 或任一其他 D-Bus 错误都
保持 fail closed。

`DropInPaths` 不是只检查 final filename 是否出现：除 exact managed security/credential policy 外，
installer 只接受固定 host-wide `service.d` 位置中 root-owned、non-symlink、single-link 且完整语法落入
窄 compatibility-reset allowlist 的文件。未知 unit-specific drop-in，或能改变 root/image/bind view、
新增 runtime/state directory、credential/environment/condition/command authority 的未验证 directive，
必须在启动前 fail closed。该闭包检查与 effective property matrix 共同生效，不能用其中一层代替另一层。

`init` 验证 controller 的 reviewer、gateway、guardian、lease broker、agentd、server、core broker
与 healthcheck service；本机存在固定 `/usr/bin/pvesh` 时才验证 PVE broker。`join` 只验证
server/core broker，signed PVE enrollment 与本机固定入口双向匹配时才加 PVE broker。把 controller
全集装到 join、让非 PVE endpoint 保留 managed PVE unit/drop-in，或只验证两种 mode 的交集都会
扩大 endpoint authority，必须 fail closed。PVE broker 的 final drop-in 必须保留唯一精确
`/etc/pve` 写例外；它不能被复制到 core/server/agentd。

Controller commit 后的 readiness 也必须按实际 gateway topology 验证：gateway 可在 owner-only
`backend.sock` 和本代 heartbeat 出现前先发布 public `agentd.sock`。installer 必须锁定 restart 后的
非零 agentd `MainPID`，记录该时点 heartbeat file identity，等待 private backend，并要求同一 PID
下 heartbeat 随后原子换代；之后才在固定 deadline 内运行一次完整 health contract。PID 漂移、命令
timeout 或最终 health failure 都保留已提交证据并 fail closed，不能用 public socket 或仍新鲜的旧
heartbeat 掩盖 agentd 未 ready。

Installer 的 unit migration 不能把 `systemctl disable` 当作受管 topology 清理器：该命令会删除所有
匹配 unit 的 link，而不仅是 installer 创建的 link。stale PVE 与 legacy `ops-systemd-helper` 只允许
删除 allowlist 中 exact persistent/runtime `.wants` path，且 symlink 必须解析到固定的受管 unit；这些
path 在 mutation 前逐项 snapshot。管理员另建的 custom wants/alias 不属于清理 authority，必须保留；
路径类型或 target 含混时整轮事务 fail closed。

这仍是 installation transaction 中的时点检查，不是对宿主 root 的持续 containment。安装后拥有
systemd 控制面的主体可以写入更晚 drop-in 并 reload manager；因此该主体和 host root 本来就在此
模型之外。运维上必须把 OS/container runtime 的 type-wide drop-in 变化当作 security-relevant
upgrade，重新执行 mode-specific effective validation；静态文件仍逐字正确不能推翻 PID 1 的漂移
证据。

## root 权限模型

### 普通操作

所有普通高权限操作必须是跨 TypeScript/Go 一致的 tagged-union arm。每个 arm至少定义：

- 最小参数类型与 unknown-field rejection；
- Target policy 中的资源 allowlist；
- prepare/precondition、backup 与资源锁；
- 固定 executable/API path 和固定 argv 结构；
- bounded timeout/output；
- authoritative verification；
- 确定回滚或明确的 `RECOVERY_REQUIRED`。

Agent 不能提交 `executable`、任意 `argv`、`runAs`、UID、host path、shell callback、PVE API
path 或原始 `pvesh/qm/pct` 参数。即使用户愿意批准，也不能把普通 operation 伪装成通用 root
RPC；需要新能力时应新增并审核更窄的 tagged arm。

### break-glass

“管理员最终可以执行任意操作”只通过与普通 tagged operation 分离的 break-glass capsule
表达。任何 root account Target 都可以 prepare，不依赖额外 server/broker kill-switch 或 legacy
policy pregrant。该可准备性不等于批准：`breakglass.script` 没有可表示的 standing scope，Agent、
reviewer、外部 Adapter 和远端审批都不能批准它，PVE domain broker 也完全不接受 raw script。

完整 script 与其 digest/bytes、network 声明必须进入权威 `planHash`。verify script 与 backup
paths 可以为空，以保证管理员理论上仍可完成任意操作；verify script 是调用者提供、以同样 root
权限运行的 privileged postcondition，不是独立 verifier。Reviewer 必须为每个 capsule 增加
critical finding，缺少 postcondition 或 backup evidence 时再增加对应 finding。批量命令、动态
shell、破坏性/身份/网络行为也只能提高风险，不能降低。当前确定性 reviewer 使用有界、引号与
嵌套感知的词法/结构分析展示顶层 segment、operator、dependency 和 source span；它不执行命令，
也不是完整 Shell AST 或语义证明。未知 argv、wrapper、展开或解析上限一律提升为 critical/opaque。
findings 最多返回 128 项；溢出时保留 critical truncation finding，不能生成 reviewer 自己无法解析
的响应。最终始终只允许本地 TUI 经过两阶段
review、PASSWD sudo 和 `/dev/tty` 精确确认启动 root submitter。这里的“本地”指审批 principal
位于 controller 的真实 TTY；capsule 可以在所选受管 endpoint 的 core broker 执行。

Capsule 以 root 在有界 transient systemd unit 中运行，带 PrivateTmp、严格 umask、最长运行时间。
`network=false` 只让该 unit 启用 best-effort `PrivateNetwork`；full-root script 仍可逃逸 namespace
或委托 PID 1 创建宿主网络任务，所以该字段只是绑定进计划的意图声明，不是不可逃逸的断网边界。
`network=true` 明确把宿主网络与外部系统副作用纳入本次人工审批。它故意是 full-root 例外，因此
普通 `file.write`/`service.action` 的路径与 unit denylist 不是它的权限上限，理论上可产生任意宿主
或外部副作用。声明的 backup paths 会先归档，但 archive 只是人工恢复
证据，不能逆转服务、账号、磁盘、网络或外部系统状态；`RollbackAvailable=false`，失败进入
`RECOVERY_REQUIRED`，不会自动回滚。它不能作为常规 Workload scope、standing authorization、
低风险自动放行或远端 Adapter 审批的替代品。

## 审批与 reviewer

用户精确输入的 `/approve`、`/reject`、`/rollback`、`/status` 在进入模型前被 Client
Gateway 截获。自然语言里出现这些字符串、Agent 输出同名文本或 IM 内模糊匹配都不构成授权。

Broker 为 live change 返回规范化、有界的 `ApprovalPlan`。普通 `file.write` 同时携带完整
`contentText`、content digest 与 bytes；break-glass 同时携带完整 script text/digest、可选 verify
text/digest、backup paths 与 network 声明，因为这些内容本身就是被批准对象：

```text
serverId, machineId, targetId, changeId,
planHash, policyRevision, capabilityRevision,
pluginDigest, preconditionDigest, typed steps
```

已持久化的旧 change 若缺少当前 provenance，不能伪造新 plan。Broker 必须同时严格解析 stored
operation，并重算确认其 planHash 精确等于 v0.1/v0.2 的 scope NUL-prefix 算法，才签署
`recoveryOnly=true` 并省略 plan；单纯 current plan 重建失败或 hash mismatch 不会自动得到恢复
authority。approve 永久拒绝，Pending change 只可 reject。每个 recovery-only status 还必须签署
严格 `recoveryDescriptor`，绑定原 target/action、精确 compensation、rollbackData digest、backup
object digest 和 compatibility version；submitter 对确认前后的 descriptor 与完整 status 做常量
时间绑定，grant 仍覆盖原 planHash、scope 和 revision。

`rollbackAvailable` 必须等于 persisted rollback flag 与当前兼容/证据检查的交集，并在 false 时给出
有界原因。当前旧 service schema 可复用固定 start/stop compensation；旧 `file.write` 只有在当前
regular non-symlink target 仍精确匹配原写入 content digest、预期 uid/gid/mode/dev/ino，且 exact
broker backup object 为 root:root、0600、有界 regular file 并绑定 digest 时，才通过 CAS
restore/remove。新建文件还必须证明 root:root 和 operation mode（缺省 0644）；任一字段无法证明
即不可回滚。旧 package/plugin/workload/break-glass 等 schema 不复用当前 executor。这个例外只能
释放或恢复旧状态，不能把 legacy operation 带回 prepare/execute 路径。

本地 Client 仅在 agentd ready/idle 时开始或继续审批，并从 reviewer 开始直到第二次 submitter、
sudo 与 `/dev/tty` 完成冻结 Agent 终端输出。期间输出经控制字符转义后进入 256 KiB 有界缓冲，
完成后才以明确的 untrusted/delayed 分隔显示；Agent 不能用 ANSI、并发输出或 flood 覆盖审批证据。

Target mutation allowlist 只允许 prepare，不等于免审授权。只有 root-owned policy 显式、非空的
`authorization.standingScopes` 中与 operation 完全匹配的普通 scope，且 plugin digest/scope grant、
Target 资源 allowlist 与前置条件仍全部匹配时，broker 才能在 prepare 内消费既有授权并执行。
legacy policy、字段缺失和空数组都继续逐次人工审批。当前 `file.write`、`service.action`、
`workload.service.action` 中除 `reload`/`reset-failed` 外的精确动作与非 critical PVE operation scope 可 standing。PVE stop/reboot、
snapshot delete/rollback、restore、migrate，以及 package/artifact 安装、`plugin.register`、
package/artifact 安装、`plugin.register`、`plugin.install`、`workload.deploy`、`breakglass.script`、workload service 的 `reload`/`reset-failed`
和 rollback 永不 standing。

`file.write` 与 `service.action` 的 live protocol 还必须携带 `pluginId=workload.base` 和当前
source digest；这些字段由 trusted provider 根据实际 caller 注入，Source Workload 不能自行声明。
若要让两种 operation standing，Target 必须同时设置完全相同的
`authorization.baseWorkloadDigest`。调用者不是该 registration、current digest 漂移或字段缺失时，
broker 不会消费 standing authorization。v0.2 已持久化且没有 provenance 的 operation 只可读取和
恢复，不能被重新 prepare 或批准执行。

每次 prepare 后，controller 都必须用新的 requestId 查询 `change.status`，并用 server registration
固定的该 domain Ed25519 broker key 验证 receipt。只有签名 status 为 `PENDING_APPROVAL` 才能把
change reference 放入审批 side-channel，并绑定原始用户 intent；签名 `COMMITTED` 表示 standing
execution 已完成，其他 terminal 状态同样必须按签名结果处理。prepare response 或非 root server
转发的无签名终态都不能作为成功证据。

对 `PENDING_APPROVAL`，当前 approve/rollback 是两阶段 UI：

1. Client 查询权威状态，把 plan 与该 change 的 prepare turn 所绑定的有界、脱敏用户意图送到
   独立 reviewer；绑定来自 Client 已发送的真实输入与 trusted-provider prepare correlation，
   不是 Agent/Source Plugin 提供的说明；
2. reviewer 应用 deterministic risk floor，返回 `REVIEW_REQUIRED`、findings 和解释；
3. 两分钟内同一 command、同一 plan、同一 review digest 再次确认，Client 才能调用固定
   root-owned `agentd-approval-submit`；Client、Agent 和 Adapter 都没有私钥；
4. sudoers 对该唯一 binary/argv 形态使用 `PASSWD` 与 command-specific `timestamp_timeout=0`，
   因此每次提交都要通过本地 sudo/PAM；安装器不仅检查 fragment 语法，还检查完整
   `/etc/sudoers`，执行 `sudo -k` 后以该管理员运行 `sudo -n` 负向探针。若站点的
   `NOPASSWD`、`exempt_group` 或覆盖规则使固定 helper 能启动，或错误结果无法证明需要密码，
   安装事务 fail closed 并回滚；
5. submitter 以 euid 0 读取固定 `/etc/ops-agent/servers.json` 与
   `/etc/ops-agent/approver/root` 中 root-only approver mTLS/Ed25519 key，在人工确认前后各拉一次
   权威 status，并以 registration 固定的 broker 公钥验证 receipt。对 runtime plugin-bound
   `approve`，第一次签名 status 验证后 submitter 独立从 canonical plan 提取唯一 workload
   plugin ID/digest，拒绝混合、缺失或冲突 provenance，并直接在固定
   `/var/lib/ops-agent/plugins` 验证 exact current、持有 root-owned shared lease，直至 reviewer、TTY、
   第二次 status 与最终 broker action 全部结束；Client/lease-broker lease 仅是前置纵深防御，丢失
   不能撤销这把 root lease。候选注册/安装/部署与 rollback 不做 current runtime 依赖。随后把
   ASCII-only canonical plan 写到 `/dev/tty`，并要求精确输入对应的
   `APPROVE|REJECT|ROLLBACK SERVER_ID MACHINE_ID TARGET_ID CHANGE_ID PLAN_HASH`；
6. submitter 签发短 TTL grant 后 POST，server 校验 approver/admin mTLS role，broker 校验
   Ed25519 grant、revision 与 nonce；submitter 仍须验证 action response 的 broker receipt。

ApprovalGrant 绑定：

```text
action, serverId, machineId, targetId, changeId,
planHash, policyRevision, capabilityRevision,
issuedAt, expiresAt, nonce, keyId, signature
```

reviewer 的进程身份、socket 和文件系统与 `agentd` 分开；PrivateNetwork 且看不到 `/etc/ops-agent`、
broker socket、Agent state 和 audit。其结果中 `canAuthorize` 固定为 false，它不能读取签名密钥、
提交 action 或降低确定性最低风险。本地管理员因 TUI IPC 可访问 reviewer socket 不等于获得
审批能力。reviewer 当前是规则实现，不是另一个 LLM；上述结构分析不是完整 AST 拆分，也不根据
风险判断自动批准。`split-required` 只作为含完整 review/findings 的结构化非授权响应返回，不能
缓存成第二次确认或触发 submitter。
standing execution 来自显式 root-owned policy，不读取 reviewer 结论。若未来增加模型解释或
低风险策略，最终授权仍必须由确定性 policy 与模型外 principal 产生，模型 reviewer 只能提高
风险或要求拆分。

`reject` 不产生副作用，不经过 reviewer，但仍需要正确的模型外 principal 和签名。
Client 不维护可用于猜测审批的全局“最后输入”。多个 pending change 分别绑定；后续 prompt
不能覆盖旧绑定。Client 重启或 Session resume 后不会从 transcript 恢复该短期绑定；绑定缺失、
changeRef/session/turn 冲突、wrong-turn correlation 或 intent 超限时 approve/rollback fail closed，
用户必须从新的简短真实请求重新 prepare。不得使用“approve exact plan”之类合成 fallback 代替。
被完全控制的 `agentd` 仍可能伪造 Client wire 上的 prepare correlation，但它最多只能把 Client
已经真实发送过的有界输入选作 advisory reviewer 上下文，不能提供任意 intent、读取 approver
key 或产生 grant；root submitter 仍重新获取并展示 broker 的 canonical plan，要求 PAM 与精确
TTY confirmation。因此 intent correlation 不是授权因子，也不能替代 plan/grant/TTY 绑定。

## 变更状态与持久化

概念状态是：

```text
PREPARED -> PENDING_APPROVAL -> human APPROVAL --+
        \-> exact standing authorization --------+-> EXECUTING -> COMMITTED
                                                       |       \-> RECOVERY_REQUIRED
                                                       \-> separately approved rollback -> ROLLED_BACK
```

当前 broker 的持久化名称更细：

```text
PENDING_APPROVAL -> PREPARING -> EXECUTING -> VERIFYING -> COMMITTED
       |                         |                |
       +-> REJECTED              +-> ROLLING_BACK+-> explicit ROLLING_BACK
                                      |                 |
                                      +-> ROLLED_BACK / RECOVERY_REQUIRED
```

`PENDING_APPROVAL` 对应尚无 standing authorization 的外部 PREPARED。人工 grant 或精确 standing
authorization basis 先写入 change/audit，backup/rollback metadata 先 fsync，`EXECUTING` 持久化
成功后才跨 mutation barrier。standing basis 必须形如 `standing-policy:<revision>:<scope>` 并随
状态持久化；prepare requestId 的 replay barrier 必须在执行前落盘。进程在执行中崩溃时，恢复
逻辑将不确定终态标为 `RECOVERY_REQUIRED`，不会猜测成功。

只有 pinned key 验证通过的 broker `change.status` receipt 返回 `COMMITTED` 才能对用户宣告
成功。PVE API 返回的 node-bound UPID 在 root-only task record 与 change evidence 都已落盘后，
broker 可立即返回签名 `EXECUTING`；该回执只表示任务已被可恢复地接管，不是
提交完成。后续由 broker-owned per-change singleflight worker 在独立有界 context 中查询原
UPID 并执行 postcondition verification，不依赖发起它的 HTTP/CLI context，也不要求 client
持续发送 `change.status` 才能推进状态。Daemon shutdown 只停止当前 observer，保留
`EXECUTING/VERIFYING` 与 VMID lock；重启后从持久 evidence 续跑。原 UPID 终止为
`stopped/OK` 且 postcondition 通过后才可 `COMMITTED`；新鲜查询 timeout/error、task failure、
丢失 UPID 或验证失败都不得重启 mutation，必须保留 lock/evidence 并 fail closed。

PVE 的锁身份是 cluster-global `pve/vmid/<vmid>`，不含 node 或 guest type。普通新 change 不能
越过 `RECOVERY_REQUIRED` owner。补偿 change 的 `recoveryOfChangeId` 进入 canonical ApprovalPlan，
但该引用本身不是授权：broker 还会验证同 PVE domain、endpoint、Target、VMID，禁止 standing，
并在本地逐次审批前后两次核对 parent 的 root-only intent/task evidence。每个 primary PVE API
之前必须先 fsync mutation-version-bound intent；因此 lost-UPID intent、running/unknown/unqueryable
task 或 legacy 无证据空集都不能转锁。已知 UPID 只能用其 node-bound task status endpoint 证明
terminal，不能用 active list 为空替代。

这里的 cluster-global 是资源 key 的形状，不是分布式锁实现。v0.3 的 durable lock 只存在于单个
PVE broker 的本地 state，Target/lock 也尚未绑定 cluster fingerprint；因此一个 PVE cluster 必须
指定且只指定一个 mutation endpoint。其他节点必须把写请求路由到该 endpoint，或保持只读。
多个 PVE broker 分别接受同一 cluster 的 mutation 不能互相排斥，属于不受支持的部署，不能把
当前机制描述成 cluster-wide/distributed locking。

安全转移是一个 durable state transition，而不是先 unlock 再执行：

```text
parent RECOVERY_REQUIRED + pve/vmid/N lock
  -> local child approval + terminal/no-start proof
     OR local child approval + independent unknown-result clearance
  -> atomically parent SUPERSEDED(resolution evidence) + child owns pve/vmid/N
  -> child RECOVERY_REQUIRED (failure, lock retained) | COMMITTED (lock released)
```

parent resolution 绑定 child ID/planHash、`NO_MUTATION_STARTED|TASKS_TERMINAL` 与终态 UPID evidence；
restart 不能复活 parent lock，TTL/quota 不能拆开 closed chain。结构化 disposition 不从 `LastError`
文本推导。普通 reconciliation 对 API 是否启动仍不明的 parent 保持 fail closed；唯一例外是独立的
broker-internal local unknown-result clearance，不能由 workload/provider、Agent、reviewer、Adapter 或
standing policy 调用。它只接受 `STARTED_OR_UNKNOWN` 且没有任何已知 UPID 的 lost-UPID/no-proof
parent；已知 UPID running、查询失败一律拒绝，已知 UPID terminal 必须回到普通 terminal
reconciliation，不能用 clearance 绕过。mutation protocol v1 完全没有 intent/task artifact 时仍走
普通 `NO_MUTATION_STARTED`，不要求人工风险接受。

Clearance prepare 先在每个相关 node 执行固定的
`/nodes/<node>/tasks --source active --vmid N --limit 1` 查询；migration 同时查询 source 与 target，
并采集 `/cluster/status`、`/cluster/resources --type vm` 与 guest `status/current`。只有 active task
精确空集、node/quorum 可用、guest 仍位于获批 node/type 且 unlocked 时，才产生绑定这些观察摘要的
短时 challenge。本地管理员必须经 PASSWD sudo 与真实 `/dev/tty`，在普通 child plan 审批之外再
输入一条包含 parent/child/planHash/resource/challenge digest 的 exact confirmation。Broker 在
confirmation 与最终转锁前各自重新观察；任一漂移或查询失败都撤销。Grant 只在 broker 内存中短时
存在且一次性消费，expiry、restart、child reject 或状态变化均使它失效。

最终 transaction 同时消费 grant、写入 `basis=local-unknown-clearance` 的 parent resolution 并把
VMID lock 转给 child；resolution 精确绑定 parent/child/childPlanHash/resourceKey 与
observation/active-task/guest/cluster digest，parent mutation disposition 仍保留
`STARTED_OR_UNKNOWN`。这表示管理员在当前权威观察下接受继续恢复的残余风险，不是“原 mutation
没有发生”的证明。旧 v1 resolution 只有空 basis 且 disposition 为 `NO_MUTATION_STARTED` 或
`TASKS_TERMINAL` 时可继续读取；空/未知 basis 的 `STARTED_OR_UNKNOWN` 必须 fail closed。

## Target、路径与 Workload policy

Root-owned policy 将 Target 映射到允许的 unit、package、read/write path、plugin identity、
PVE node/storage/guest/migration target 和 operation 集合。模型不能选择 UID/GID 或改变 Target。
这些 allowlist 只约束可准备的资源；`authorization.standingScopes` 是独立字段，只有显式精确
普通 scope 才允许复用先前授权。不得把 legacy allowlist 静默迁移成 standing authority。

Linux 文件读取使用 fd-bound `openat2` 约束，拒绝 symlink、magic-link 和目录逃逸。目录级
metadata 授权不自动授予文件正文；`file.read` 需要精确文件允许。写入还要通过 broker 的
允许根与关键路径拒绝列表。普通 `file.write` 永久拒绝 agent policy/runtime/TLS/receipt/
credential、release/libexec executable payload 与 systemd unit 控制面，也不能创建 executable
mode；Target allowlist 不能取消这些拒绝。此类管理只能新增专用 tagged operation，或在明确
计划绑定的 manual root capsule 中逐次本地人工批准。

配置的 `file.write` 允许根可以恰好位于独立 filesystem 或 bind mount 的挂载点。broker 从 `/`
解析这个 root anchor 时拒绝 symlink 与 magic-link，但允许抵达该精确挂载点；取得 fd 以后，所有
root 内部相对解析继续强制 `RESOLVE_NO_XDEV`，所以嵌套挂载不能扩大 policy。prepare/execute/verify
仍绑定 parent 与 target 的 device/inode；允许 root 自身跨 mount 不等于允许授权路径在审批后漂移。
Debian 12/systemd 252 的 `RestrictSUIDSGID=yes` 可让 `openat2` 返回 `ENOSYS`；broker 只对这个精确错误
回退到逐 component、fd-relative、`O_NOFOLLOW` 的目录打开，并用 `statx(AT_EMPTY_PATH,
STATX_MNT_ID)` 的非零 mount ID 保持相同 `NO_XDEV` 边界。其他 `openat2` 错误、statx 失败或缺失
mount ID 一律 fail closed；不能通过移除 `RestrictSUIDSGID` 或放宽 unit hardening 取得兼容性。

Service workload policy 必须把实际 source caller 的 plugin ID 和精确 digest 绑定到 Target
account、`system|user` manager、完整 unit allowlist 与 `reload|reset-failed|restart|start|stop` 集合；Core 不维护
Hermes/BotMux 标准 ID 或 unit/path profile。业务 source descriptor 自己校验 profile，通用
`workload.service.manage` provider 再重验 active caller、拒绝 `workload.base` 并注入 provenance。一个
Target 只表示一个 Linux 账号；多账号必须拆成多个 Target。system unit 的权威 `User=` 必须等于
获批账号，user unit 只经固定、无 shell 的 `runuser`/`env -i`/`systemctl --user` argv 执行。
计划绑定当前 UID、load/active/sub state 与 unit user；状态漂移会在 mutation barrier 前拒绝。
这些操作不宣告自动 rollback，因为反向 service verb 不能恢复被丢弃的内存或外部工作；任何
补偿都必须是新计划、新前置条件和新审批。`reload` 只允许 active 起点且验证仍为 active；
`reset-failed` 只允许 failed 起点且验证不再 failed。两者即使 Target 配置
`workload.service.action` standing scope 也固定回落到逐次人工审批。

JSON config workload policy 只把 semantic profile/selector/field 映射到一个非 root UID 的
home-relative document 和 closed scalar constraint；它不接受 caller 提供的 path、JSON key、helper、
argv、object 或 array。`workload.json-config.edit` 永不 standing，必须由签名
`PENDING_APPROVAL` 进入本地二次确认并绑定 exact source digest。固定 root-owned helper 在 target
UID transient unit 中使用 openat2/no-symlink strict JSON 与 rename-exchange digest CAS；root-sealed
before/after 不 bind 给目标 UID。CAS outcome 不确定、当前内容既非 before 也非 after、或目录 identity
漂移都保持 `RECOVERY_REQUIRED`。Absolute-path 目录 proof 只能检测验证时 identity，不能阻止同 UID
或其他获得父目录写权的本地主体稍后替换 pathname，ApprovalPlan 必须显示该
residual risk。

`workload.command.inspect` 只表示 root-owned fixed read recipe。Source input 不含 executable、argv、
shell、path 或 env；通用 provider 拒绝 `workload.base`、重验 current caller，并把实际 ID/digest 与
semantic profileKey 送入专用 HTTPS route。Target policy 精确 pin target/run-as account、home、
executable、argv、timeout 与 output bound。执行前 broker 解析 symlink，并对原路径与 resolved path
的每一级要求 root owner、非 group/world writable，最后目标还必须是 executable regular file；用户
可写安装或任一可写祖先直接拒绝，不能只返回 warning。执行固定通过 system manager 创建 non-root
transient service，保持 `ProtectSystem=strict`、`ProtectHome=read-only`、`PrivateNetwork=yes`、
clean env、RuntimeMaxSec 与 cgroup KillMode；不更改 core broker 自身的 `ProtectHome=yes`。
core broker receipt 将该只读结果绑定到 server/machine/Target/method/plugin/digest/profile/result
digest。Root 与 Agent audit 永不保存 output 正文；Agent audit 只保存 output SHA-256、UTF-8 bytes、
truncated 与 profile identity。Core 的通用文本 redaction 只是下限，标准业务 Source 还必须做字段
白名单；尤其 BotMux setup JSON 必须由 digest-covered、有界且拒绝 duplicate key/trailing value/过深
或截断输入的 parser 处理，只复制 exact safe fields，并整体丢弃 env、cliRuntime、update、
command/path/credential、未知或混淆字段和 object-map key。

PVE policy 必须绑定所选合法 `workload.*` caller 的精确 plugin ID 与源码 digest，并分别列出：

- node、storage、QEMU/LXC VMID；
- 允许的 start/shutdown/stop/reboot、snapshot、backup、restore、migrate 操作；
- migration target；
- 对 destructive snapshot/restore 路径要求的 backup storage。

Broker 将这些字段映射成固定 API path/argv，绝不把 raw PVE CLI 暴露给模型。更详细的风险与
已实现范围见[PVE Workload](workloads/pve.md)。若另配 exact PVE standing scope，它也只能在
上述 digest 与资源集合的交集内生效；PVE broker 不接受 `breakglass.script`。

Destructive snapshot 的 safety backup 不是 `Prepare` 副作用：`Prepare` 只读，只有 durable
`EXECUTING` barrier 与 `change_execution_started` 后才 fsync safety intent、调用 `vzdump`、持久化
UPID/volume，再写 primary intent。Primary API 紧邻一次完整权威前置条件重验；safety backup 后
仅允许已记录 volume 这一项预期集合增量，并继续绑定 `PreviousStatus`、snapshot、storage、
node/quorum 与 guest lock。确定的 intent 写失败/API 前漂移可作为 no-mutation；API call 已尝试、
UPID/volume 不明或 task 未知一律 `RECOVERY_REQUIRED`。

## Plugin 信任模型

Plugin 的安装意味着对一份源码和一组能力/scope 做持久 grant，不是普通文件复制，也不单独等于
root standing authority。规则是：

1. 第一方与第三方同等不可信；publisher 只是 identity 字段；
2. manifest 严格拒绝未知字段，capabilities/requestedScopes 必须有界、排序且去重；
3. registry 拒绝 symlink、device、socket、路径逃逸、超限文件和 snapshot 期间变化；
4. typed `plugin.register` 的 operation、权威计划和批准必须精确匹配 plugin ID、kind、version、
   publisher、canonical digest、完整 capabilities 与完整排序 requestedScopes；Adapter plan 还必须
   由 broker 权威派生并展示 runtime identity、host filesystem/network、runtime-UID-readable
   credential 与 direct platform authority，不能只展示 action scope；
5. 激活的是只读 content-addressed snapshot，不是可编辑 source directory；
6. 任一源码或 mode 变化都会改变 digest；每次安装或更新都必须在模型外本地流程逐次审批，更新
   不能复用旧 digest 的 grant；
7. 常规注册使用 typed `plugin.register`，broker 推导 source path、执行前 re-hash，并保存旧
   registration 作为 rollback evidence；
8. Adapter 不因有 `approval.*` capability 就获得签名密钥；Workload 不因安装就获得通用 broker；
   Workload tool capability 与 provider name 独立，capability 只做 descriptor/manifest 所有权匹配，
   provider authority 必须来自 manifest `requestedScopes` 覆盖该 name 对应 policy 的全部 scopes；
9. 有效 root 能力取 plugin ID/kind/digest、descriptor/manifest capability 一致性、provider-name
   scope grant、server capability、Target 资源 policy 与 exact standing scope 的交集；`plugin.register`、
   `plugin.install` 与 `workload.deploy` 自身永不 standing。
   Adapter 的 `agentd.adapter/v1` descriptor 必须把 inbound type、session control、outbound action
   和固定 `runtimeAuthority` 逐项声明；runner 将行为项确定映射为动作级 capability/scope 并要求与
   manifest 完整相等。宽泛 `message.outbound`、extra scope 或在 typed IPC 中把 `send` grant 用于
   `quote` 都 fail closed。该 grant 只约束 digest review/typed IPC；Source Adapter 的直接平台调用
   仍拥有完整 runtime UID/credential/network authority，不得宣称由 action scope 做 OS enforcement。
10. 每个 Source Workload invoke 在读取 exact current digest 后，以真实 runtime UID 连接固定
    `/run/ops-agent/plugin-lease/lease.sock`。独立的 `ops-agent-lease` broker 用 `SO_PEERCRED` 校验
    principal 与 plugin class，在 client 不可读的 `root:ops-agent-lease` lock directory 中取得 exact
    digest 的 non-blocking shared `flock`，并在同一锁下返回经重验的 runtime registration。Runtime
    lock directory 必须精确为 `0750`；初始化在 `2750` registry parent 下创建它以后显式清除继承的
    setgid（GNU `chmod` 需用 `00750` 才明确清零目录 special bits），再做 owner/group/mode 校验，
    不能把 parent 的 client-plane 目录语义带入 broker-only 边界。
    必须保持 framed connection 到 host、provider、签名 status 处理和 audit 全部 settle，再显式
    release 并等待 acknowledgement；断连、broker restart 或 hard deadline 都使调用结果 fail
    closed并触发 runtime termination。当前 socket lease 不持久跨这些异常，所以这里不声称 registry
    lock 本身 crash-persistent；managed settlement 必须等 lifecycle barrier，异常残余窗口见“已知限制”。
    Client、Agent 与 Adapter 永不直接打开 lock，abort 也不能在忽略 abort 的 provider 尚未结束时释放 lease。
11. register、activate 与 deactivate 必须取得同一 lock 的 non-blocking exclusive `flock`。若 A
    invocation 已开始，更新不能切换 `current`，broker 将 pre-activation failure 幂等恢复为原
    状态；若更新先取得 exclusive lock，新的 A invocation 不能启动。Adapter runner 也必须把
    exact digest shared lease 持有到 Adapter/TUI 子进程退出。已完成的 A invocation 不被追溯
    取消；A pending plan 可保留 reject/rollback，但 B current 后不能再 approve。plugin-bound
    第二次 approve 的 Client/lease-broker lease 必须保持到 root submitter 完成，但它只是前置纵深
    防御；root submitter 还必须在第一次签名 status 后直接打开固定 registry lock、独立验证并持有
    同一 exact digest shared lease 到最终 action settle。Client 或 lease broker 退出不能缩短该边界，
    且 pending plan 不能获得 standing。
12. Workload 的 outer/inner bwrap 都只创建 `user/ipc/pid/net/mnt`，agentd systemd unit 的 namespace
    allowlist 必须与之逐项一致并继续拒绝 cgroup/UTS/time。outer 保留默认 PID 1 reaper，inner 才让
    Source 成为 PID 1 并禁止后续 userns；outer 在这段窗口内只能启动同一个固定 root-owned inner
    bwrap。outer 的专用 `--sync-fd` 必须只随 PID 1 生命周期持有；该 init 无论经正常 `ECHILD`
    收拢还是 parent-death cleanup 终止，有界 `--info-fd` 都同时返回 outer init 的 `child-pid`；
    runtime 绑定其 start identity，等 FD EOF 后还必须等该 exact process
    identity 消失，才能把 monitor exit 视为完整完成。sync 失败仍先等 identity disappearance；首次
    stat 不可读只允许保守等 authoritative PID 出现 ENOENT，info 未给出 PID 则 runtime/lease 保持
    fail-stop。`ProtectHostname=yes` 不因 sandbox 放宽；
    `ReadWritePaths=/proc/sys/user/max_user_namespaces` 不授予宿主写权限，只允许无 capability 的
    agentd 建立这两层固定 user namespace；inner `--disable-userns` 自己以额外
    `CLONE_NEWUSER` 必须失败验证后续嵌套已关闭，不能把最终 procfs 数值当作证明。service 与安装时
    唯一、root-owned、位于 `/run/systemd/system` 的短生命周期 static probe 必须同时固定
    `ProtectProc=invisible`、`ProcSubset=all`、`PrivateDevices=yes`
    和 `ProtectKernelTunables=yes`；`all` 让 namespaced sysctl 路径存在，`invisible` 只隐藏其他 UID
    的 PID 目录。same-UID PID 目录和未被其他 mount hardening 屏蔽的只读非 PID procfs 元数据仍
    可见，不能把该组合描述为完整 `/proc` 隐藏。安装 preflight 必须在复制最终 security drop-in、
    核验 PID 1 effective 配置且执行后精确清理的短生命周期 static systemd boundary 内运行完整双层
    bwrap probe，不能只在同 UID 的普通 shell 中探测。清理必须尝试 `stop` 和 `reset-failed`，但不能
    解析 stderr 或把 static unit 已卸载后的单步非零状态误当成残留；只有 exact artifacts 全部消失、
    `daemon-reload` 成功且 PID 1 的成功查询精确返回 `LoadState=not-found` 才是权威闭包。任一最终证据
    不成立仍 fail closed。
    outer 与 inner 的 procfs 必须分别匹配各自 PID namespace：两层都使用 `--proc /proc`；outer 保留
    默认 PID 1 reaper 与 sync/info/exact-identity completion barrier，inner 继续让最终 Source 只看见
    自己的私有 procfs。outer 若继承 service proc 视图，fixed inner 会因缺少其 namespace FD path 而
    启动失败；因此不能把省略 outer proc mount 描述为等价 sandbox。
13. Ubuntu Noble 的 AppArmor restricted-userns 不能靠“某次 bwrap 能启动”判定。本 Release 已将
    restricted-userns=`1` + AppArmor enabled 的 controller/`init` 定义为 unsupported，并要求在
    账号、unit、plugin、sudoers、host policy 或其他持久 mutation 前 fail closed。证据由同一 hosted
    boundary 的两个互斥失败组成：正确保留 outer `--proc /proc` 时在
    `ProtectProc=invisible` 下返回 `EPERM`；GitHub-hosted run `31319405888`（commit
    `7091ecfbc28ae6410f06d4e2b64462c96dd83726`，job `93259846767`）省略 outer proc 后，fixed inner
    返回 `bwrap: open /proc/3/ns/ns failed: No such file or directory`。所以 direct smoke、历史
    `verified-now`、旧 managed state 或 `host-policy install` 都不能构成当前支持证据。

    不得通过修改 host-wide sysctl、启用 SUID bwrap、删除任一 bwrap 层、降低 `ProtectProc` 或其他
    systemd hardening、使用 unconfined profile 或扩大 AppArmor exec authority 规避失败。正确支持
    需要尚未实现的独立、typed、短生命周期 spawn supervisor；它必须把 setup authority 绑定到固定
    request，而不是让长期 Node Core 持有 argv-blind setup profile。

    旧 Release 可能已留下 exact managed AppArmor files 或 loaded kernel profiles。它们是恢复/审计
    证据，默认卸载保留，helper `remove` 永远 fail closed；`inspect/install` 立即返回 unsupported，
    `status` 只做 strict exact legacy inventory：永不返回 `0`，`3` 仅表示 safely absent，`1` 表示
    managed、drift 或 inaccessible，且后两类可在状态正文前失败；它不能用作成功 gate。任何移除必须另行设计并审计可处理
    active-label 竞态的主机维护流程。BotMux 继续按实际 restriction/AppArmor evidence 在 mutation 前
    拒绝。`join` endpoint 不部署 Source runtime，不受该 controller 限制，也不得管理 host policy。

初始化必须安装 `adapter.tui` 与 `workload.base` 才能工作，所以安装器把它们作为**需明确提示
并批准的必需项**处理。`--approve-required-plugins` 只适用于外部自动化已经批准该 Release
内这两个精确源码树的场景，不是 first-party bypass。若真实 bubblewrap/user namespace 不可用，
安装器必须整体回滚，不能以“只禁用 sandbox command”继续启动无隔离的 `workload.base`。

旧 `.opspkg`/OCI 路径仍存在。它有自己的 artifact digest、catalog 和固定 executor，但尚未
统一到 Source Plugin registry；这是一项兼容边界，不应据此新增另一套信任规则。

## Adapter 审批边界

Adapter 只有同时满足以下条件时才可提交远端审批意图：

- 通过平台签名/连接上下文独立验证真实 sender；
- 明确证明是 owner private DM，而不是群聊、转发、机器人或模糊 actor；
- 持久化 ingress ID 去重并拒绝 replay；
- 保留 message/change correlation；
- 不持有 approver mTLS 或 ApprovalGrant signing key，也不能访问 broker socket。

配置里的 `allowedUsers` 字符串不是身份密码学证明。任一条件缺失都必须将审批回落到 TUI。
当前 BotMux Adapter 的 sender/envelope 处理用于回复语义和安全降级，并未建立完整的远端
ApprovalIntent 签名链，因此不能被描述为可信远端审批入口。
`agentd.adapter-inbound/v1` 的 authenticated evidence 字段也不改变这一点：它只携带 bounded
issuer/subject/evidence ID/time 元数据，必须由未来的模型外 Gateway 结合获批 Adapter digest、
平台认证与 replay state 独立验证；当前任何 Adapter 都不能把它升级为 approve/reject/rollback。

## Secret 与审计

模型 API key 使用 systemd encrypted credential；Agent 读取运行时 FD 后只保存在进程内。
Approver mTLS key 与 ApprovalGrant signing key 位于 `/etc/ops-agent/approver/root`，是 root:root
`0600`，只由短生命周期 submitter 读取；普通 Client 的 server registry 不能包含可由管理员
UID 直接读取的私钥副本。
core/PVE broker 虽以 root 运行，正常执行路径仍用各自 systemd mount namespace 隐藏
approver、agent、observer 和 server private key，并分隔彼此的 state/audit、receipt private key
与 Source registry。该设置减少正常可见面和意外访问，但不约束已被攻陷的 root broker：full-root
进程可以逃逸 namespace、委托 PID 1 或直接控制宿主。domain separation 不能替代 tagged union、
审批校验，也不能被描述成针对 broker/root compromise 的 containment。
本机 `pvesh` mutation handler 需要写 pmxcfs，所以只有 `ops-pve-root-helper.service` 在
`ProtectSystem=full` 下获得精确 `ReadWritePaths=/etc/pve`；没有 `/etc` 或其他更宽例外。core
broker 的正常 mount namespace 将 `/etc/pve` 标为 inaccessible，`agentd-server`、Agent 与 Source
Plugin runtime 也没有这个 mount 或文件权限。PVE broker 只可通过 typed handler 使用它；
`/etc/pve/priv` 的路径、内容和派生 secret 永远不能进入模型输出、RPC response、receipt 或 audit。
Receipt private key 位于 `/etc/ops-agent/broker-receipts/private`，为 root:root `0600`；公钥由
`servers.json` 按 server registration 固定。key ID 只在该 registration 内解释，core/PVE 必须
使用不同 ID、路径和密钥。Enrollment 的 CA 签名同时覆盖 endpoint receipt 私钥、公钥与 key ID；
controller 只保留每个 remote server 的不可覆盖公钥副本。Endpoint 不从该签名 bundle 自举信任：
它先将 bundle CA 与外部 pin 做精确匹配，再用匹配后的 CA 验证 bundle 签名。Fresh endpoint
还把 controller/endpoint/CA pin/identity/PVE 事实固化到 root-owned
`endpoint-enrollment.json`。Release upgrade 不接受另一个 bundle 覆盖这些 trust material；新
binary 必须只读验证 metadata、当前 policy schema、TLS/DAC 与 domain-separated receipt keypair，
任何 partial/damaged state 都 fail closed 并回滚安装事务。
远端模式 broker 如果没有加载 approval verifier 或 receipt signer，会在启动时 fail closed；运行时也会拒绝
缺少 verifier 的远端 action，而不是解引用空配置。
Adapter secret 留在 Adapter 专用账号，启动 Core 前剥离相关环境变量。BotMux 将 Lark secret
明文保存在 `ops-agent-botmux` 专用账号的
`/var/lib/ops-agent/adapters/botmux/.botmux/bots.json`；目录为 `0700`、文件与备份为 `0600`。
该账号无 sudo，唯一 supplementary group 是 status-only client 面所需的 `ops-agent-client`；
它不能读取 `ops-agent:ops-agent 0600` 的 agent mTLS key。这仍是
owner-only 明文存储，不能称为 systemd encrypted credential。

公开的 `/run/ops-agent/agentd/agentd.sock` 是可达性入口，不是身份本身。它由
`agentd-client-gateway` 持有；gateway 对首帧做 strict、bounded、duplicate-key-rejecting hello
解析，从 kernel `SO_PEERCRED` 取得 UID，并要求声明的 Adapter ID/digest 精确等于 registry 的
active adapter。backend Session key 是
`SHA-256(domain, peer UID, adapter ID, adapter digest, external sessionId)` 的固定命名空间，Client
只看到自己的 external ID。因而另一 `ops-agent-client` group 成员、BotMux 或另一个派生 Adapter
即使猜中 Session ID，也不能恢复或占用 TUI backend Session；同一 namespace 同时只允许一个 live
writer，第二个连接在拨号 backend 前拒绝。agentd 本身只监听
`/run/ops-agent/agentd/backend.sock 0600`。
gateway 在解析任意 hello 前先同步取得 `SO_PEERCRED`，再以固定 128 process-total / 32 per-UID
上限 admission；超限连接只获得有界错误并关闭，不创建新的 handler goroutine 或 writer-map entry。
unit 另设 `TasksMax=128`、`LimitNOFILE=512`、`MemoryMax=256M`，作为已授权 Adapter UID 被攻陷时的
资源耗尽纵深防御。上限保护 gateway 可用性，不把该 Adapter 重新分类为可信。

这条边界不声称隔离已被攻陷的 `ops-agent` UID：gateway 与 agentd 同 UID，后者若被完全控制可以
直接连接 owner-only backend；同一专用 Adapter UID 内的进程也属于同一 OS principal。digest 更新
会产生新 Session namespace，不自动延续旧上下文。gateway 重启会关闭连接并清空内存 writer map，
不会在存活连接之外保留 writer claim。
agentd backend 重启与 gateway 重启是两个不同事件：gateway 跨前者保持 active，但 backend EOF
必须关闭对应的旧 Client connection，并在 fresh connection 到达前释放 canonical writer lease 和
process-total/per-UID admission。backend pathname 尚不存在只会让当前连接得到有界 unavailable，
不会让持有公开 socket 的 gateway 退出；每次 production dial 都重新验证 backend owner/mode，并以
dial 前后 device/inode 相等拒绝 pathname replacement。installer 通过 PID 1 typed D-Bus 确认
gateway 对 agentd 有 `Wants`/`After` 启动关系、没有 `BindsTo` 或 `Requires` stop propagation，
同时精确验证 `ops-agent.target.Wants` 仍包含受管 controller 集合。gateway 的 effective `Wants`
还可能因 `PrivateTmp` 出现 `tmp.mount` 等 systemd 隐式项，因此 agentd 关系使用 typed exact-member
验证；显式 unit 与完整 drop-in 闭包仍必须逐字匹配 Release。

`adapter.tui` 的固定 launcher 只读取获批 CAS 中的声明式 profile 并运行 compiled Client；
`adapter.botmux` 则执行获批 CAS snapshot 中的真实源码。对于可执行 Adapter，runner 将 Source
与 release compiled Client 作为 sibling 启动，只把已捕获 descriptor/active digest 的只读单帧
context FD 5 交给 Client；Source 仅持有 FD 4 typed input 写端和 FD 3 completion 读端，不能在正式
路径替换 Client 所见 descriptor。BotMux Source 与 Client 均拒绝 positional/`@file` prompt；初始
及后续消息统一经过 stdin raw-byte ceiling、fatal UTF-8、envelope parser 后才生成 FD 4 union。
Client 仍独立重读 active registration 并持 exact digest lease。
两者分别运行在本地交互用户和
`ops-agent-botmux` UID，且没有 root key/broker socket。批准仍是
真实的用户级权限授信：TUI Client 可观察终端，BotMux 源码可读取其账号内 secret，因此摘要变化必须
重新批准，且任何其他 Adapter 都不得继承 TUI 的本地审批能力。可执行 Source Adapter runner
使用双层固定 bwrap 收拢完整进程树：outer 创建 user/PID namespace 并保留默认 PID 1 reaper，
inner 再创建 user/PID namespace，以 `--as-pid-1 --disable-userns` 让源码入口成为 PID 1 并禁止
后续嵌套；outer 在 inner 之前只执行同一个固定 root-owned bwrap。outer 以专用 `--sync-fd` 和
有界 `--info-fd` 提供 PID 1 lifecycle evidence；runtime 不能把 bwrap monitor 先返回的 initial
status 或 sync EOF 单独当完成，必须继续等 info 绑定的 exact init process identity 消失。exact
digest lease 持有到该 barrier 确认 namespace 内连 detached/unref 后代都消失；outer 不能使用 `--as-pid-1` 或
`--disable-userns`。Adapter 由 bwrap 的 `--dev /dev` 自己建立最小 synthetic device view，
保证 `/dev/null` 等基础 stdio 可用而不重新暴露宿主设备；禁止改用
`--dev-bind /dev /dev` 导入宿主 device tree；
BotMux service 与真实 runtime probe 还固定 `ProtectProc=invisible + ProcSubset=all`：前者隐藏
其他 UID 的 PID 目录，后者保留只读非 PID procfs 可见面并让精确 namespaced sysctl 例外可达；
该全局 metadata 可见面是已知边界，不得宣称 `/proc` 完全不可见。
仍保留业务所需网络、宿主文件系统与本地 UID 权限，不能把该 PID containment 夸大为无网络
sandbox。声明式 TUI 不执行不可信源码，为保留 host sudo/PAM 而直接启动 compiled Client；Client
自己再持有同一 exact adapter digest lease 到退出，因此 runner 崩溃不会让无租约 Client 留存。
声明式 TUI 自身更新不能通过“先提交、再释放”取得 registry exclusive lease。唯一例外流程只对
第二次本地确认的单步 canonical `adapter.tui plugin.register` 生效：Client 先停止输入并关闭 Agent
Session，等待自己的 lease broker release acknowledgement，再通过 runner-only FD 6/7 请求外层
runner 释放 exact digest lease并等待 ACK，之后才启动 root submitter。旧 Client 随后无论提交结果
都退出；任何其他 TUI/runtime lease 未释放仍会让更新在切换 `current` 前失败。多 step、非 TUI、
Source Adapter、第一次 review 或非本地确认都不能触发这项交接。
这些边界阻止 root/审批能力升级并收拢进程生命周期，但不会把 Adapter UID 持有的平台 credential
转换成按 `send/reply/quote` 分隔的 OS capability；该完整 authority 必须进入 plugin approval plan。
由于非 root bwrap 创建 namespace 的方式可能影响 supplementary groups，“保留本地 UID 权限”还
必须由目标 Linux 探针证明：专用账号在 primary Adapter group 不变时，经过真实 bwrap 后仍应能
读取 `root:ops-agent-client 0640` 文件并连接 group `0660` socket。`npm run
test:adapter-linux-runtime` 还把真实 bwrap 后的 FD 4 分片输入/FD 3 反向 completion 与 detached
descendant 的宿主 PID/starttime 消失作为 lease release 的前置条件；host-side driver 在 transient
unit 自己的 procfs 视图中以唯一 argv token、同 cgroup 与嵌套 pid/mnt/user namespace evidence 捕获
该身份，绝不把 inner `--proc` 所见的 `NSpid` 当作 host PID；positional argv/`@file` 永远不是备用
消息入口；
退出码 `77` 是未验证而不是通过。该探针失败时必须阻断发布，不能放宽 client socket/CAS mode 或
把 Adapter 加入 `ops-agent` service group 来掩盖问题。Release workflow 必须在 disposable Ubuntu
runner 上用独立专用系统身份运行该探针；不得修改 runner 默认用户，且 publish job 必须显式依赖
探针成功，不能用 `continue-on-error` 或把退出码 `77` 转成成功。

审计应关联 principal、Session/turn、server/machine/Target、request/change/plan、revisions、
approval nonce、backup、verification 与 rollback。Agent audit 和 root audit 分开；root audit
不是 `ops-agent` UID 可写。当前 hash-chain 只能发现本地日志变化，不能抵御宿主 root 同时替换
程序与日志。另需注意 `ops_bash` 的 Agent audit 当前会记录命令与结果；不要把 secret 放进
sandbox 命令或输出。

## 供应链与已知限制

Release 安装前验证 HTTPS + SHA-256；存在 `gh` 时额外验证 GitHub artifact attestation。
checksum 与 artifact 位于同一 Release 时不能替代独立签名。目标机不运行 npm/Go 构建，
release binary 应静态构建并排除 AppleDouble `._*` 文件。

尚未实现或尚未完成迁移的安全能力：

- Ubuntu Noble restricted-userns controller 支持缺口：correct outer proc mount 在 hardened static unit 中
  返回 `EPERM`，outer-proc-removal 候选又在 run `31319405888` 以
  `open /proc/3/ns/ns failed` 失败。本 Release 因而在持久 mutation 前明确拒绝 controller/`init`；
  后续需要独立 typed spawn supervisor，不能降低 sandbox。BotMux 同样按事实优先在 mutation 前拒绝；
  server/core/PVE-only `join` 不在该限制内；
- Source Plugin registry lease 的 crash-persistent lifecycle proof：正常及受控错误路径已等待 outer
  init exact identity 被 reap，但 broker restart、强制 socket 断连、runtime SIGKILL 或 workload
  hard deadline 会释放当前 socket-backed `flock`。尚无把 supervisor/pidfd completion 或持久
  quarantine 绑定进 broker unlock 的机制，因此不得把这条异常窗口描述成 crash-safe；
- 更广的 Hermes/BotMux CLI、conversation 与 config content typed provider；
- 同一 gateway 进程内跨 Client connection 的 namespace live-writer lease 已实现，但尚无跨 gateway
  restart、多个 gateway 实例或 Adapter handoff 的持久化 writer lease；
- Adapter behavioral unions 已具备 strict parser 和动作级 grant 绑定，但尚无通用 action/session
  transport consumer、持久 outbox 或可信远端 ApprovalIntent；
- 远端审批 Adapter 的完整可信身份链；
- reviewer 模型、Shell AST 拆分或基于 reviewer 风险判断的低风险自动批准；当前只实现 root-owned
  policy 中显式精确 standing scope 的既有授权执行；
- controller HA、多方审批、外部审计锚定和在线 enrollment 单次消费；
- break-glass 的 AST/模型解释与任何 standing/低风险自动放行；现有 deterministic reviewer 只
  提高风险并要求本地人工确认。
