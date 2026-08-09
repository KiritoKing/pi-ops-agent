# Workload：Agent 工具与受控运维 recipe

Core 本身不提供 Agent 可见的业务工具；Workload 扩展 Agent 自身能力。它可以增加非特权工具，也可以把一组 root 操作封装成更容易
理解、审核和恢复的 typed recipe；但安装 Workload 不等于获得通用 shell、argv、文件系统、
Docker 或 PVE API。

## 两类能力

### 非特权工具

适合放入 Workload 的能力包括：

- Machine/Target 发现与有界状态读取；
- 当前 Session workspace 内的离线分析；
- 固定 SDK/API 的只读请求；
- 将复杂结果整理为有界、脱敏的结构。

工具必须有严格输入 schema、timeout、输出上限、secret redaction 和明确的 network 语义。
“非 root”并不自动等于低风险：它仍可能读取敏感数据、对外发送信息或耗尽资源。

### 特权 recipe

需要 root 的 Workload 只能调用 `agentd-root-broker` 已知的 tagged-union arm。一个合格 recipe
包含：

```text
typed input
  -> root-owned Target/policy check
  -> preconditions and resource lock
  -> backup or explicit no-backup reason
  -> fixed broker-side executable/API path and argv
  -> authoritative verification
  -> deterministic rollback or RECOVERY_REQUIRED
```

多个子步骤只有在共享同一资源、不变量和恢复边界时才适合合并成一次审批；计划必须逐项展示
实际效果。当前通用 change 一次只携带一个 operation，尚未实现任意多步 batch recipe。

## `workload.base`

`workload.base` 是运行 Agent 所需的最小基础 Workload。它的 source registration 与 descriptor
目前门控八个 capability：

| capability | 当前工具 | 边界 |
|---|---|---|
| `machine.list` | `ops_machine_list` | 只读 controller-pinned registry |
| `machine.describe` | `ops_machine_describe` | mTLS 刷新 identity/Target/capability |
| `target.inspect` | `ops_inspect` | server-advertised capability 与 root policy 交集 |
| `command.exec.sandbox` | `ops_bash` | 无网络 bubblewrap，仅当前 workspace 可写 |
| `artifact.catalog` | `ops_artifact_catalog` | 旧 `.opspkg` catalog 兼容路径 |
| `change.prepare` | `ops_propose_change` | 发起 prepare；命中 exact standing scope 时 broker 可在同一流程执行，但 Agent 仍不能 approve |
| `change.status` | `ops_change_status` | 查询 broker 权威状态 |
| `breakglass.prepare` | `ops_breakglass_prepare` | root Target 的 manual root capsule prepare；永不 standing |

当前 `workload.mjs` 会在一次性、无网络的双层 bubblewrap host 中加载。outer 使用默认 PID 1
reaper并只启动固定 inner bwrap；inner 才让 Source 成为 PID 1、禁止继续嵌套 userns。outer 的
专用 `--sync-fd` 只随 PID 1 生命周期持有；该 init 无论经正常 `ECHILD` 收拢还是 parent-death
cleanup 终止，有界 `--info-fd` 都返回并绑定该 init 的 exact process identity；runtime 必须等
sync EOF 与该 identity 消失，才结束 invocation 或释放摘要 lease。Source 随后输出
`agentd.workload/v1` descriptor，并通过 bounded IPC 编排 provider。源码不在 agentd 内 import，
也不直接获得宿主能力；实际 Machine/Target、sandbox 与 change 行为仍由 Core 的 narrow typed
provider 执行。Descriptor capability 必须与 manifest capability 精确一致，但 provider authority
只来自 manifest `requestedScopes`：Core 以 provider name 查 policy，并要求覆盖全部 required scopes。
Capability 与 provider 同名不会自动授权。

若 sync 失败，runtime 仍先等 exact identity 消失再报告失败；初次 stat 不可读时只接受该 PID
后续 ENOENT，info 未给出 authoritative PID 时 invocation 保持 fail-stop。该保证覆盖 managed
settlement；socket lease 在 broker restart、强制断连或 runtime SIGKILL 下尚非 crash-persistent，
详见[安全模型的已知限制](security-model.md#供应链与已知限制)。

`workload.base` 发起通用 `file.write` 或 `service.action` 时，Source 输入不包含也不能伪造 plugin
provenance。Core 根据实际 provider caller 注入 `pluginId=workload.base` 与 current digest，并在
prepare 前再次读取 registration。Target 若为这两种 operation 配置 standing scope，还必须设置
相同的 `authorization.baseWorkloadDigest`；否则操作仍可进入逐次人工审批，但不能复用长期授信。
其他 Workload 即使获批了通用 `change.prepare` provider，也不能借用 `workload.base` 的 digest。

第八项 `breakglass.prepare` 只要求所选 Target 的 account 是 root，不依赖额外 capability switch
或 Target pregrant。工具只准备完整 script/digest 与 network 声明；verify script 和
backup paths 可为空，但 reviewer 必须把缺少恢复或验证证据标为 critical。最终仍须本地 TUI 的
PASSWD sudo 与真实 `/dev/tty` 逐次审批，不能由 Agent、Adapter、reviewer 或 standing policy
批准。它不是普通 Workload 的免审 root provider，PVE broker 不接受它，且所有 capsule 都明确
没有自动 rollback。

`ops_bash` 的安全来源是 UID、双层 bubblewrap namespace、PID 1 lifecycle FD + exact process identity barrier、只读 bind、无网络与 workspace 隔离；outer 仍创建 PID namespace 并保留默认 reaper，但不重挂 procfs，只继承 systemd-protected service proc 视图来启动固定 inner；inner 继续用 `--proc /proc`，因此最终 Source 只看见 inner 私有 procfs。这个形状没有削弱双层 PID containment；
host 还必须固定 root-owned `bwrap`/`bash`/`prlimit`，清空 namespace capabilities、禁止再创建
嵌套 user namespace，并限制 CPU、地址空间、进程数、文件大小和 fd。agentd service 固定
`ProtectProc=invisible + ProcSubset=all`：它隐藏其他 UID 的 PID 目录，但为双层 bwrap 保留非 PID
procfs 与精确 namespaced sysctl 路径；未被其他 hardening 屏蔽的非 PID 全局 metadata 对 Source
仍是只读可见面，不能把该组合当作 `/proc` confidentiality boundary。命令黑名单只作为补充。
若这些边界或 user namespace/bubblewrap 不可用，不仅 `ops_bash` 无法注册，必需的
`workload.base` 源码也无法进入隔离 host；`init` 必须 fail closed 并回滚，不能退化成宿主 shell、
进程内 loader、Docker 或 sudo 执行。

每个 prepare 后 controller 都必须以新的 requestId 查询 `change.status` 并验证对应 domain 的
pinned broker receipt。只有签名状态为 `PENDING_APPROVAL` 才能把 change reference 交给审批
side-channel；签名 `COMMITTED` 表示命中 standing policy，不能从 prepare response 或 server
无签名转发自行推断成功。

## 标准 Workload

| Workload | 目标能力 | 当前实现状态 |
|---|---|---|
| `workload.base` | 基础发现、诊断、sandbox、change prepare/status | Source workload host + exact-base typed providers 已实现 |
| `workload.pve` | PVE node、QEMU/LXC、snapshot、backup、restore、migration | Source host 编排 + typed TS/Go provider、policy、inspect/executor 已接入；真实 PVE lab 验收前为 preview，部署细节见专门文档 |
| `workload.hermes-ops` | 多账号 Hermes service/journal/config metadata、fixed CLI diagnostics 与 service lifecycle | Source host + digest-bound command profiles + typed service recipe 已实现；config content unsupported |
| `workload.botmux-ops` | 多账号、多实例 BotMux service/journal/config metadata、受控单字段配置编辑、session/status/setup summary 与 service lifecycle | Source host + digest-bound command profiles + typed service/config recipe 已实现；setup 输出采用本地字段白名单 |
| `workload.hermes` | 部署固定 Hermes OCI managed workload | legacy `.opspkg` executor，继续保留恢复兼容 |

两个 `*-ops` profile 不应通过给 Agent 开放 root shell 快速补全。当前写能力处理 systemd
service lifecycle 与 BotMux policy-mapped 单字段 JSON 编辑；更广的 CLI、对话或配置能力仍应逐项定义输入、输出、secret、备份、验证与
恢复语义，并把 active plugin digest 写入权威 operation/plan。

## Hermes 与 BotMux 运维 profile

只有 active registration 的 ID/kind/digest 保持 current、descriptor capabilities 与 manifest
精确相等，且 manifest requested scopes 覆盖源码声明的每个 provider policy 时，Harness 才注册
对应模型工具。业务 capability 与 provider name 相互独立：

| 工具 | 支持 | 明确 unsupported |
|---|---|---|
| `ops_hermes_config_inspect` / `ops_hermes_health_inspect` / `ops_hermes_service_inspect` | Source schema 固定 Hermes path/unit；经通用 `target.inspect` 读取 status、最多 200 行 journal 和 metadata | 配置正文 |
| `ops_hermes_doctor` / `ops_hermes_gateway_status` | Source 只选择 `hermes.doctor` / `hermes.gateway.status`；root policy 固定 CLI 与 argv | 任意 Hermes CLI argv、用户可写 CLI |
| `ops_hermes_service_manage` | Source schema 固定业务 unit/action；经通用 `workload.service.manage` prepare `workload.service.action` | config write、任意 CLI action |
| `ops_botmux_config_inspect` / `ops_botmux_health_inspect` / `ops_botmux_service_inspect` | Source schema 固定 BotMux path/unit；经通用 `target.inspect` 读取 status、最多 200 行 journal 和 metadata | 配置正文 |
| `ops_botmux_config_edit` | 只提交 profile、selector、semantic field 与 string/boolean/clear tagged value；当前字段为 `model`、`backendType`、`defaultWorkingDir`、`showInTeam` | config path、账号/UID/home、selector key、实际 JSON key、任意 object/array、secret、service restart |
| `ops_botmux_status` / `ops_botmux_sessions_list` / `ops_botmux_setup_summary` | fixed command profile；setup JSON 只输出 safe identity/status 字段 | env、cliRuntime、update、command/argv/cwd/path、credential 与 raw config |
| `ops_botmux_service_manage` | Source schema 固定业务 unit/action；经通用 `workload.service.manage` prepare `workload.service.action` | conversation mutation、config write |

`ops_botmux_config_edit.selectorValue` 的公开 schema 只表达 1–256 字符长度，因为 Workload ABI 的
safe-pattern 子集不接受否定字符类；digest-covered Source 在调用 provider 前仍独立拒绝 C0/C1、
U+061C、U+200E/U+200F、U+2028–U+202E、U+2066–U+2069 与 U+FEFF。provider 与 Go 边界继续做各自
校验，不能把 Source 检查当成授权边界。

实际 read 仍经过 server 的 `systemd.unit`、`journal.tail`、`file.metadata` schema 与 root-owned
Target unit/readPaths allowlist。Plugin digest 门控 Agent-side tool 并进入 Agent audit，但这些
generic read RPC 本身不是 PVE 那样的 digest-bound operation。任何 root 写操作在新增专用
tagged union、digest/policy binding、backup、verification 和 rollback 之前都 fail closed。

Service mutation 则通过单独的 `workload.service.action` tagged union，明确携带 plugin ID、
plugin digest、账号、`system|user` manager、unit 和 `reload|reset-failed|restart|start|stop`。通用 provider 拒绝
`workload.base`、重验 actual caller 并注入其 ID/digest；源码输入不能自报 provenance。root-owned
Target policy 必须精确匹配全部字段，因此 source schema 变宽不会扩大已有 root grant。`system` manager 额外要求
unit 的权威 `User=` 等于获批账号；`user` manager 只使用固定 argv 的
`runuser --user <account> -- env -i ... systemctl --user ...`，不会经过 shell，也不会把任意 argv
交给模型。

Broker 在审批计划中展示账号 UID、当前 `LoadState`/`ActiveState`/`SubState` 和 unit user，并把
这些权威观察绑定为 precondition digest。执行前若状态漂移就拒绝；执行后重新读取状态，只有
`stop` 得到 `inactive`，`start`/`restart`/`reload` 得到 `active`，或 `reset-failed` 得到非 failed 才能提交。
`reload` 只接受 active 起点，`reset-failed` 只接受 failed 起点，而且两者永不 standing。Service lifecycle 可能丢失
内存或外部工作，反向 systemd verb 不能恢复它，所以 v1 的 `RollbackAvailable` 永远为 false；
补偿必须以当前状态重新 prepare 一个 typed change 并单独审批。

Fixed diagnostic CLI 使用独立的 `workload.command.inspect` provider。Workload invocation 只能传
`machineId`、`targetId` 和 bounded semantic `profileKey`；它不能传 executable、argv、shell、path、
env、run-as UID 或 timeout。Core 以 actual active caller 注入 plugin ID/digest，root-owned Target
policy 做 exact lookup。broker 解析 executable symlink 后，要求原路径和 resolved path 的每个组件
均 root-owned 且 group/world 不可写，最终文件为 regular executable；因此 `/home/alice/.local/bin`
等用户可写 CLI 绝不属于 trusted profile。需要这类 CLI 时必须先由管理员安装 root-owned 固定版本，
或使用逐次 manual root capsule，不能把 writable risk 当 warning 后继续执行。

执行由固定 `/usr/bin/systemd-run --wait --pipe --collect --uid=<account>` 创建 transient service，
并固定 `ProtectSystem=strict`、`ProtectHome=read-only`、`PrivateNetwork=yes`、clean `env -i`、
`RuntimeMaxSec` 与 control-group kill。core broker unit 本身继续使用 `ProtectHome=yes`。结果输出经
UTF-8/control/byte bound 后由 core receipt 绑定 server、machine、Target、method、plugin ID/digest、
profileKey 和完整 result digest。Root audit 不存 output；Agent audit 也只存 output SHA-256、UTF-8
byte count、truncated 与 identity。通用 text redaction 只是下限，标准 Source 必须重新构造模型可见
结果：Hermes 原始行永不出 Source 边界，只从正向有限 marker 重建 health enum 与计数，截断或矛盾
一律变成 `incomplete`/`unknown`；BotMux setup 在 digest-covered Source 内使用
64 KiB、16 层深度与有界节点/容器的 strict JSON parser，拒绝 duplicate key（包括 escape-equivalent
key）、trailing value、截断和超限输入，只逐字段复制大小写精确的 safe identity/status allowlist。
`env`、`cliRuntime`、`update`、command/args/cwd/path、credential、未知或 Unicode-confusable 字段及
object-map key 都不会进入结果。

### Policy-mapped JSON 配置编辑

`workload.json-config.edit` 是通用的窄写 provider，不是 JSON patch、任意文件写或 CLI
passthrough。Source 只能提交实际 caller 的 `machineId`/`targetId`，再加 bounded
`profileKey`、`selectorValue`、semantic `fieldKey` 和严格 tagged scalar：

```json
{
  "profileKey": "botmux.bots",
  "selectorValue": "ops-agent",
  "fieldKey": "showInTeam",
  "value": { "kind": "boolean", "booleanValue": true }
}
```

Core 重新读取 active registration，注入真实 `pluginId` 与 `sourceDigest`。root-owned Target
policy 再把 semantic profile 映射成非 root 账号、numeric UID、home-relative config、selector
JSON key、允许的 selector、实际 JSON field，以及字段类型与 closed constraint。Source 不能提交
account、UID、home、config path、selector key、实际 field、helper、executable、argv、shell、object
或 array。`model-id/v1`、closed `enum/v1` 与 lexical `absolute-path/v1` 是当前唯一 string
constraints；绝对路径必须位于列明的 policy root 下。

Broker 先用固定 root-owned `/usr/lib/ops-agent/agentd-json-config-helper`，通过
`systemd-run --uid=<target UID>` 的 no-shell transient unit 检查当前文档。Unit 固定
`ProtectSystem=strict`、`ProtectHome=tmpfs`、`PrivateNetwork=yes`、空 capability、namespace/
syscall hardening、30 秒 runtime 上限和 control-group kill，只 bind 精确 config parent 与一次性
stage。Linux helper 使用 `openat2(BENEATH|NO_MAGICLINKS|NO_SYMLINKS)`、owner/mode/nlink/size 与
strict duplicate-rejecting JSON 检查；非 Linux 或缺少安全 primitive 时 fail closed。

ApprovalPlan 同时显示并绑定 source digest、profile/selector/field、tagged requested value，以及
root 观察到的账号 UID、config path/digest/identity、actual selector/field mapping、before/after 和
`whole-document-semantic-rewrite`。独立 reviewer 的风险下限为 high，且该 operation **永不
standing**：只有签名状态 `PENDING_APPROVAL` 可进入本地 TUI，Client 要求本地 console、逐次二次
确认，并把自己的 exact source-digest lease 保持到 root submit 完成。该 lease 只是前置纵深防御：
root submitter 在第一次签名 status 后独立从 canonical plan 提取唯一 workload ID/source digest，
直接验证 fixed registry current 并持有 root-owned shared lease，贯穿 reviewer、TTY、第二次 status
与最终 broker action；Client/lease-broker 丢失不能提前释放它。digest 更新后旧 plan 不能批准，
Agent、Adapter 与 reviewer 都不能代批。

Prepare 把 before/after 封入 broker-owned `0700/0600` sealed storage；target UID 只看每次调用的
临时副本。执行在 durable `EXECUTING` barrier 后重新观察全部 precondition，再以
`RENAME_EXCHANGE` + digest CAS 提交。只有交换前拒绝，或 exchange-restored 后由 broker 再次观察到
exact approved-before，才可证明最终无已批准变更；“交换已恢复”本身不证明恢复的是 approved-before。
最终观察到 exact approved-after 才可继续提交验证，其他 current digest 或交换结果不确定均进入
`RECOVERY_REQUIRED`，不能猜测成功。审计保留 `mutationAttempted` 与 `exchangeRestored`。Verify 精确检查 after；rollback
只允许 current 仍等于 approved after 时 CAS 回 sealed before。重启恢复只会把 exact before 判为
`ROLLED_BACK`、exact after 判为 `COMMITTED`，其他状态继续保留 recovery evidence。

`defaultWorkingDir` 还要求 helper 在相同 openat2 边界内验证 policy root 与请求目录，并把两者
dev/ino/mode/uid/gid 写入 precondition，执行和恢复前重验。这个检查不能阻止同 UID 或其他获得父
目录写权的本地主体在验证后再次替换路径名；计划明确显示
`pathname_may_be_replaced_after_verification` residual risk，因此它不是目录
内容完整性或未来不可变性的承诺。Config 整文档会按 JSON 语义确定性重写，未知字段值保留但原始
空白/key order 不保留；审批 UI 必须展示这一点。Service restart 是独立 typed change，不随配置
编辑隐式执行。

### Target policy 示例

每个 Target 的 `account` 与 `serviceWorkloads[].account` 必须相同。一个账号可列多个 unit；多个
Linux 账号应建多个 Target，从而让 Session、计划、审批和审计保持单账号绑定：

```json
{
  "version": 1,
  "revision": "policy-service-20260808-v1",
  "targets": [
    {
      "id": "target-alice-hermes",
      "account": "alice",
      "displayName": "Alice Hermes services",
      "inspect": {
        "hostSnapshot": false,
        "processList": false,
        "units": ["hermes-gateway-coder.service", "hermes-gateway.service"],
        "readPaths": []
      },
      "changes": {
        "writePaths": [],
        "units": [],
        "packages": [],
        "plugins": []
      },
      "authorization": {
        "standingScopes": []
      },
      "serviceWorkloads": [
        {
          "pluginId": "workload.hermes-ops",
          "pluginDigest": "sha256:REPLACE_WITH_64_LOWERCASE_HEX_DIGITS",
          "account": "alice",
          "manager": "user",
          "units": ["hermes-gateway-coder.service", "hermes-gateway.service"],
          "operations": ["reload", "reset-failed", "restart", "start", "stop"]
        }
      ],
      "commandWorkloads": [
        {
          "pluginId": "workload.hermes-ops",
          "pluginDigest": "sha256:REPLACE_WITH_64_LOWERCASE_HEX_DIGITS",
          "targetAccount": "alice",
          "profileKey": "hermes.doctor",
          "runAsAccount": "alice",
          "runAsHome": "/home/alice",
          "executable": "/usr/local/bin/hermes",
          "argv": ["doctor"],
          "timeoutSeconds": 60,
          "maxOutputBytes": 32768
        },
        {
          "pluginId": "workload.hermes-ops",
          "pluginDigest": "sha256:REPLACE_WITH_64_LOWERCASE_HEX_DIGITS",
          "targetAccount": "alice",
          "profileKey": "hermes.gateway.status",
          "runAsAccount": "alice",
          "runAsHome": "/home/alice",
          "executable": "/usr/local/bin/hermes",
          "argv": ["gateway", "status"],
          "timeoutSeconds": 30,
          "maxOutputBytes": 16384
        }
      ]
    }
  ]
}
```

BotMux 使用相同结构，但 `pluginId` 为 `workload.botmux-ops`，常见 user unit 是
`botmux.service`。若同一账号确实同时运行两个 workload，可以在同一 `serviceWorkloads` 数组放
两个独立 digest grant；system/user manager 也必须分开列出。数组会规范化排序，通配符、未知
字段、非法 unit、非精确 digest 或未知 action 都会拒绝整份 policy。

BotMux 的 command profile 使用相同 identity/digest/account/home 绑定，标准 semantic keys 与固定
argv 为：`botmux.status` → `["status"]`、`botmux.sessions.list` →
`["list","--plain"]`、`botmux.setup.summary` → `["setup","list","--json"]`。不要根据 semantic
key 名称猜成不存在的 `sessions list` 子命令；仓库随附的 Target policy fixture 对这三个 argv 做
[回归锁定](../plugins/workload-botmux-ops/target-policy.example.json)。
`executable` 应是管理员维护的 root-owned 路径（例如 `/usr/local/bin/botmux`），不能指向账号自己的
npm/pnpm/bin 或 checkout。`setup list --json` 即使上游声称隐藏 secret，标准 Source 仍执行本地
allowlist；不能用原生 `JSON.parse` 的 last-key-wins 语义处理重复字段。上游版本变化导致 JSON shape
不可解析、输出被截断或超过 parser bounds 时 fail closed，而不是回传 raw output。

BotMux 配置编辑另由 `jsonConfigWorkloads` 精确授权。完整可复制示例见
[`target-policy.example.json`](../plugins/workload-botmux-ops/target-policy.example.json)：它把
`botmux.bots` 固定到一个目标账号的 `.botmux/bots.json`、selector key `name`、明确 selector 集合和
四个 semantic field。`pluginDigest` 必须替换为注册后实际 digest；同一物理 config 不能被两个
profile 别名重复映射。这个数组只决定 edit 能否 prepare，不会产生 standing authorization；每次
值变化都仍须本地批准。

示例的空 `standingScopes` 表示每个 service mutation 仍逐次人工审批。只有管理员明确加入
`"workload.service.action"` 时，且 exact plugin digest/account/manager/unit/action 仍全部匹配，
broker 才能在 prepare 内使用 standing authorization；该 scope 不会扩大
`serviceWorkloads[].operations` 或 unit allowlist；`reload`/`reset-failed` 即使列入 operations 也固定逐次审批。

随附 source 的 mutation unit profile 故意与上游生成器完全一致：Hermes 只接受
`hermes-gateway.service` 或 `hermes-gateway-<profile-or-hash>.service`；BotMux 只接受
`botmux.service`。旧 `hermes.service` 是上游明确要求迁移的 pre-rename unit，
`hermes-agent*.service`、`hermes-gateway@*.service` 和 `botmux@*.service` 也不是当前上游契约，
因此不能进入免 argv 审核的标准 recipe。多账号 BotMux 依靠 Target account + user manager
隔离，不靠把账号拼进 unit 名。Source workload ABI 只接受一个受限、anchored、bounded 的安全
pattern 子集，拒绝 group、alternation、lookaround、backreference 和无界量词；业务正负向向量因此
留在 digest-covered source descriptor。Core/Go broker 只做通用 service unit 语法与 root-owned
exact Target policy 校验，不硬编码 Hermes/BotMux profile 或标准 plugin ID。

实现依据上游公开契约，而不是让 Agent 猜命令：Hermes 标准只读 profiles 使用 `doctor` 与
`gateway status`；BotMux 使用 `status`、`list --plain` 与 `setup list --json`。Linux
service profile 继续使用上游 unit 命名。`reload`/`reset-failed` 是 systemd typed service operation，
不是上游 CLI passthrough；只有 root policy 显式列出时才可 prepare，并固定逐次审批。若 unit 不支持
reload，权威 systemctl failure/verification 会阻止提交，不能改用任意 CLI fallback。

Hermes 这两个命令的上游输出并不是安全的机器接口：`doctor` 会混入配置路径、插件或 provider
名称、异常正文和外部 memory 标识，`gateway status` 也可能混入 PID、profile 与 runtime health
自由文本。标准 Source 因而不回传任何原始行，也不使用 secret 关键字黑名单：Doctor 只重构为
`passed/issues/incomplete/unknown`、issue count 与三类 marker 计数；Gateway 只重构为
`running/stopped/conflicting/incomplete/unknown`。截断或相互矛盾的输出不会被解释成健康状态。
这些 coarse summary 只供诊断导航，不是审批、standing authorization 或变更验证证据；需要细节时
使用固定 systemd status、bounded journal 或由本地管理员直接查看 Hermes 原始输出。

- [Hermes CLI reference](https://hermes-agent.nousresearch.com/docs/reference/cli-commands)
- [Hermes messaging gateway service](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/messaging/index.md)
- [Hermes profiles](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/profiles.md)
- [BotMux CLI commands](https://deepcoldy.github.io/botmux/cli-commands.html)
- [BotMux bots.json](https://deepcoldy.github.io/botmux/bots-json.html)

## PVE Workload 边界

PVE 是标准 typed Workload，而不是 Core 的“任意虚拟化 shell”。当前读取 capability：

- cluster、node、storage、task UPID 和 guest current status；
- 每个请求使用固定 `pvesh get <known-path> --output-format json`，模型不能传 API path。

当前 mutation arms：

- guest start/shutdown/stop/reboot；
- snapshot create/delete/rollback；
- guest backup、restore 和 migrate。

每个 operation 绑定实际调用 PVE typed provider 的合法 `workload.*` ID、exact digest、node、
guest type、VMID 和相关
storage/target node。只有 guest start/shutdown、snapshot create 和 guest backup 是可表示的
PVE standing scope；Target 仍须逐项列出精确 scope。Guest stop/reboot、snapshot
delete/rollback、restore、migration 是 critical，broker 固定拒绝把它们配置为 standing；审批
reviewer 也不能降级。获准的普通 PVE operation 可以在 prepare 内执行，但仍必须
满足上述 digest/资源交集并由 controller 取得 signed terminal status。异步命令必须追踪固定
UPID 到终态，不能把任务创建成功当成 `COMMITTED`。

部署时在 PVE host 本机运行非 root `agentd-server` 和 root broker；不要把 PVE root token、
`pvedaemon` socket 或任意 `pvesh` 暴露给 controller/Agent。完整能力表、backup 和验证语义见
[PVE Workload](workloads/pve.md)。

## Hermes 兼容路径

现有 [`workload.hermes`](workloads/hermes.md) 是旧 `managed-workload` 用例：`.opspkg` manifest
固定 OCI image digest、entrypoint、loopback port、resource limits、credential slots 和运行后
验证，broker 生成固定 Docker argv。它证明 typed executor 可行，但不符合“所有业务 Plugin
以可编辑源码交付”的最终方向。

迁移时必须保留旧 change、container label、credential bundle 和 rollback metadata 的读取
能力；不能删掉 legacy executor 后让已部署实例失去恢复路径。新的 Hermes 主机运维 Workload
应单独建模多账号 systemd/CLI，不要把 OCI deploy 与主机运维混成一个万能 operation。

## Plugin digest 与 policy

Workload source grant 只证明用户批准了某份源码及其 requested scopes；root 操作还必须同时
通过 Target policy。有效能力是：

```text
active source registration ID/kind/digest
∩ descriptor/manifest exact capabilities
∩ provider-name policy requiredScopes
∩ server advertised capabilities
∩ root-owned Target resource policy
∩ operation-bound plugin digest
∩ generic base operation 的 exact authorization.baseWorkloadDigest（如适用）
∩ (exact standing scope 或本次模型外人工 grant)
```

任何一项变化都应 fail closed。更新源码后 digest 变化，旧 persistent grant 与已准备 change
不能自动迁移；每次安装或更新都必须在本地模型外流程重新审阅完整 identity/digest/scope，
prepare 新计划。`plugin.register`、legacy `plugin.install`、`workload.deploy` 与 package/artifact
安装本身没有 standing scope。

## 不允许的快捷方式

- `sudo -u <user> sh -c ...` 或 root raw shell；
- 模型提供 executable、argv、UID/GID、host path 或 PVE API path；
- 让 Workload 直接读取 ApprovalGrant signing key；
- 因为 publisher 是本仓库就自动安装或扩大 policy；
- 用一个“万能运维”operation 包住彼此无关、不同恢复边界的命令；
- 将 Adapter 的消息发送能力当成 Workload 的审批身份。

真正不可预先类型化的管理员操作只能进入 root Target 的 manual root capsule，并由本地
TUI/PASSWD/TTY 逐次批准；它没有 standing scope，也不能经 PVE broker 或远端 Adapter 执行。

## 开发流程

使用[`agentd-workload-dev`](../skills/agentd-workload-dev/SKILL.md)：

1. 先写 capability/权限/备份/验证/回滚表；
2. 从[`workload.base`](../plugins/workload-base/manifest.json)复制最小源码布局；
3. 若需 root，先证明现有 operation 无法表达，再同步修改 TS/Go tagged union、policy、executor、
   store/recovery、approval plan、审计、测试和文档；
4. 覆盖未知字段、错误 UID、scope/digest/revision 漂移、replay、并发、timeout、部分失败和
   rollback failure；
5. inspect final source，用 typed `plugin.register` prepare 精确 ID/kind/version/publisher/digest、
   完整 capabilities 与完整排序 requestedScopes，经模型外人类批准后由 broker 重新扫描、逐项
   匹配、注册并验证 snapshot；该操作永不 standing，每次新 digest 都必须本地重新批准。prepare
   后还必须以 pinned broker key 验证 `change.status` receipt；不要直接调用底层 CLI 绕过 change
   audit。
