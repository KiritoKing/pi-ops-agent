# Source Plugin：信任、注册与更新

Pi Ops Agent 的 Plugin 分为 `adapter` 和 `workload`，二者共享一套源码信任规则。Plugin 会
增加 Agent 的能力，也会扩大持久授信范围，因此不能按“第一方默认可信、第三方需要审核”
区分。唯一可复核对象是**精确 manifest identity/capabilities + 精确源码树 digest + 精确
requested scopes**；友好名称或 publisher 声明本身不构成信任。

## 源码与激活快照

推荐目录：

```text
/var/lib/ops-agent/
├── plugin-sources/             # 管理员可编辑源码，不直接执行
│   ├── adapter.tui/
│   └── workload.base/
└── plugins/                    # content-addressed registry
    ├── snapshots/sha256/<hex>/ # 只读不可变快照
    ├── invocation-leases/      # broker-only root:ops-agent-lease flock files
    └── plugins/<pluginId>/
        ├── registrations/<sha256>.json
        └── current -> ../../snapshots/sha256/<hex>
```

运行时只相信 `current` 指向的 snapshot 和对应 registration，不相信可编辑 source directory。
每次读取 active registration 都会重新检查 link、snapshot digest、manifest identity 与 grant。
`init` 将 `plugin-sources` 根设为 `ADMIN_USER` 所有的 `0750`，便于创建和修改自定义源码；它不在
`ops-agent-client` 的读取面。只有 root-owned、`root:ops-agent-client 2750` 的不可变 `plugins`
registry 可供 agentd/TUI/Adapter 读取，root broker 注册时重新遍历 source 并核对摘要。

## manifest v1

根目录必须有严格的 `manifest.json`：

```json
{
  "apiVersion": "agentd.plugin/v1",
  "schemaVersion": 1,
  "id": "workload.example",
  "kind": "workload",
  "version": "0.1.0",
  "publisher": "example/operator",
  "description": "Example typed workload.",
  "entrypoint": "workload.mjs",
  "capabilities": ["machine.list"],
  "requestedScopes": ["control.machine.read"]
}
```

规则由 `internal/pluginregistry/manifest.go` 强制：

- 只允许上述十个字段，缺失、`null`、未知字段、重复 JSON key 或 trailing value 都拒绝；
- ID 必须以 `adapter.` 或 `workload.` 开头且与 kind 一致；
- version 是有界 SemVer，entrypoint 是规范化 package-relative 普通文件；
- capabilities/scopes 最多各 64 项，必须排序、唯一并符合名称模式；
- description、publisher、路径和文本都有限长且拒绝控制字符。

Registry 只接受 snapshot 内普通文件，Core 不会在 agentd 进程中 import/eval Source Plugin。
固定 Source Adapter runner 会重验 active runtime view/CAS、探测 strict descriptor、复查 current
未漂移，再在非 root UID 下以 sanitized env、`shell:false` 运行 `.mjs` entrypoint。可执行 runtime 位于
保留网络/宿主用户权限/TTY 的双层 bubblewrap PID namespace；descriptor 探测和正式入口各自都由
outer 默认 PID 1 reaper 包住固定 inner bwrap，inner 才让 Source 入口作为 PID 1 并禁止继续嵌套
userns。outer 在 inner 启动前不能执行其他程序，也不能先使用 `--as-pid-1`/`--disable-userns`；
专用 `--sync-fd` 只随 outer PID 1 生命周期持有；该 init 无论经正常 `ECHILD` 收拢还是
parent-death cleanup 终止，有界 `--info-fd` 都返回并绑定其 exact process identity；runner 必须等
EOF 和该 identity 消失，不能只等 monitor status 或 FD close；
sync pipe 报错只改变运行结果，不能跳过 identity disappearance；首次 stat 不可读会降级为只等该
authoritative PID 出现 ENOENT，info 连 PID 都无法给出则 invocation 保持 fail-stop，不把证据缺失
当成清理完成；bwrap 的 `--dev /dev` 自行构造最小 synthetic devices，不能替换为
`--dev-bind /dev /dev` 恢复宿主设备面；
FD EOF 只说明 outer init 已终止；再等该 exact `/proc` identity 被回收或明确发生 PID reuse，才
把 PID namespace 清空作为 lease settlement 证据，不能让 runner 提前释放摘要 lease。精确
`adapter.tui` 只能提供不可执行 `profile.json`；runner 核对固定 local-TTY profile 与
`approval.submit.local` grant 后在宿主 TTY 直接启动 compiled Client，Client 自己持有第二份 exact
TUI digest lease 到退出以保留 sudo/PAM 和 runner-crash 安全性；所有其他 Adapter 强制 status-only。
Adapter descriptor 还必须声明版本化 inbound type、session control 与 outbound action 的精确子集。
runner 将它们映射为 `adapter.inbound.<type>`、`adapter.session.<control>`、
`adapter.outbound.<action>` capability，以及追加 Adapter namespace 的 requested scope；两组排序数组
必须与 manifest 完整相等，extra/missing grant 或 `send`/`reply`/`quote` capability confusion 都拒绝。
当前 TUI 只获批 `text + bind + display`，BotMux 只获批 `text + bind + send`。三组 strict union 是
capability-ready boundary；通用 action/session transport、持久 outbox 与远端 ApprovalIntent 尚不存在，
不能仅凭 manifest capability 宣称已实现。
Workload 的 `.mjs` 会在一次性、无网络 bubblewrap host 中执行并通过有界 framed IPC 请求 provider；
Core 以 provider name 查找 narrow typed policy，并只在 manifest `requestedScopes` 覆盖其全部
required scopes 时允许调用。Tool capability 只需与同一 digest 的 manifest 精确匹配，用于工具
所有权与冲突检测；它与 provider name 独立，不能代替 scope grant。自定义 Plugin 可在该 host
中实现工具 schema、业务安全 pattern、纯计算与 provider composition，但 root 行为仍必须新增并
审核 typed broker arm/provider，不能传 shell、任意 argv 或动态扩展 Core。

Provider wire compatibility 不属于 Plugin identity。对 exact DeepSeek `openai-completions`，Core 可在
model-visible tool 浅副本上为一种已由真实 A/B 验证的 schema 形状补冗余根 `type: "object"`：原根
没有 `type`，`anyOf` 非空且每个 arm 都显式为 object。投影不递归、不改 mixed/non-object union、
不按 provider 前缀匹配，也不推广到其他 API。注册时解析的 canonical Source descriptor、invoke 时的
原始 runtime `Check`/execute closure、immutable CAS tree/digest、manifest capability、requestedScopes
和完整 Adapter/Workload authority 都保持逐字相同；不要为适配 provider 重写 snapshot 或复用旧
grant。真实 A/B 的一个 `200`/tool call 只证明该 wire 形状被接受，不是完整 TUI 或 Plugin runtime
验收；Release candidate 仍必须通过真实 provider 回放 installed active 的全部 model-visible tools。

Workload invoke 不是靠“调用 provider 前后各读一次 current”防竞态。Runtime 不能打开 registry
lock；它以自身真实 UID 连接固定 `/run/ops-agent/plugin-lease/lease.sock`，由独立非 root
`agentd-plugin-lease-broker` 通过 `SO_PEERCRED` 将该 principal 限定到允许的 plugin class，再为请求的
exact active digest 打开 root-owned `0640 root:ops-agent-lease` per-plugin lock、取得 shared
`flock` 并返回同一把锁下重验的 runtime registration。Runtime 持有这条 framed connection，直到
Source host、所有 trusted provider 请求、签名 status 处理和 agentd audit 全部 settle，最后发送
显式 release 并等待 acknowledgement；断连、broker restart 或 workload hard deadline 都让当前
调用结果 fail closed，并触发 runtime termination。需要区分 operation fail-closed 与 lock
crash-persistence：当前 broker 的 in-memory socket lease 会在这些异常下释放，尚未把 outer-init
pidfd/supervisor 或持久 quarantine 纳入 registry unlock 条件，所以只能保证 managed/graceful
settlement 不早释，不能宣称 broker crash、强制断连或 runtime SIGKILL 下仍绝无短暂更新竞态。
Client-group process 永不读取 lock directory，abort 也不能与后台 callback 竞速并提前释放 lease。
Registry 的 register/activate/deactivate 必须取得同一 lock 的 non-blocking exclusive `flock`。

Workload host 的 outer/inner 两层都只创建 `user/ipc/pid/net/mnt` 五类必需 namespace；outer
保留默认 PID 1 reaper并以专用 `--sync-fd` + bounded `--info-fd` 提供 completion evidence，inner 使用
`--as-pid-1 --die-with-parent --disable-userns`，不创建
cgroup/UTS namespace。`ops-agentd` 的
`RestrictNamespaces=` 与这份最小集合一致，`ProtectHostname=yes` 提供 service 级不可变 UTS 视图；
`/proc/sys/user/max_user_namespaces` 的唯一可写 mount 只供固定 outer 建立 inner user namespace、
再由 inner `--disable-userns` 设置 namespaced quota，并由 bwrap 自己验证下一次
`CLONE_NEWUSER` 失败；不能用最终 procfs 显示的数值代替该 postcondition。
outer 与 inner 都必须使用 `--proc /proc`，让各自 procfs 与 PID namespace 一致；outer 仍保留
默认 PID 1 reaper 和完整 completion barrier，inner 最终只向 Source 暴露自己的私有 procfs。
省略 outer proc mount 会使 fixed inner 无法解析其 namespace FD，不是可接受的兼容 fallback。
unit 必须同时固定 `ProtectProc=invisible` 与 `ProcSubset=all`；`all` 使该 sysctl 路径存在，
`invisible` 只隐藏其他 UID 的 PID 目录。same-UID PID 与未被其他 mount hardening 屏蔽的只读非 PID
procfs 元数据仍可见，不能声称完整隐藏 `/proc`。除精确 sysctl 例外外继续保留
`ProtectKernelTunables=yes`，并保留 `PrivateDevices=yes`。非 root agentd 对宿主 sysctl 没有
DAC/capability。Node permission mode 不开放 child process。
它的 namespace 同时是无网络/只读 CAS sandbox；Adapter 的 PID namespace 只解决进程树生命周期，
不代表 Adapter 没有网络或宿主用户权限。

Ubuntu 24.04 Noble 若 restricted-userns=`1` 且 AppArmor enabled，本 Release 的 controller/`init`
在任何持久 mutation 前明确 fail closed。正确 outer proc mount 在 hardened static boundary 返回
`EPERM`，省略它又在 hosted run `31319405888` 让 inner 以 `open /proc/3/ns/ns failed` 失败；不得
通过 sysctl/SUID/single-layer/降低 `ProtectProc`/unconfined 绕过。真正支持需要 typed spawn
supervisor。server/core/PVE-only `join` 不执行 Source Plugin，不受这项 controller 限制。

## canonical digest

`agentd-pluginctl inspect` 对整个 tree 计算稳定 digest。Hash 输入包含：

- 文件/目录类型与规范化相对路径；
- 文件 executable bit；
- 文件长度与完整内容；
- 固定的 schema domain separator。

默认限制是 512 entries、24 层、单文件 8 MiB、总计 32 MiB、manifest 64 KiB。Symlink、device、
socket、FIFO、非规范路径、registry/source 重叠和扫描期间发生变化都会 fail closed。

```bash
sudo /opt/pi-ops-agent/current/bin/agentd-pluginctl inspect \
  --root /var/lib/ops-agent/plugins \
  --source /var/lib/ops-agent/plugin-sources/workload.example
```

`inspect` 输出 manifest、digest、文件数和总字节数。批准 UI 必须展示至少：plugin ID、kind、
publisher、version、digest、capabilities 和 requestedScopes；不能只展示友好名称。Adapter 还必须
显示真实 runtime identity、宿主 filesystem/network、runtime UID 可读 credential 与 direct
platform authority，不能把 action scope 描述成源码进程的 OS sandbox。

## 注册与审批

常规 `plugin.register` operation、权威 ApprovalPlan 与人类批准精确绑定：

```text
pluginId + kind + version + publisher + digest
+ ordered capabilities + ordered requestedScopes
+ adapter runtime identity/filesystem/network/credential/direct-call authority
```

模型外 principal 与时间另写入 grant/audit。不可变 registration 以 plugin ID、kind、digest、
requestedScopes 与批准身份定位获批 snapshot；version、publisher、capabilities 来自该 digest
覆盖的严格 manifest，并在 prepare、execution 和 runtime `current` 校验时逐项重验，不能在同一
批准下替换。

`agentd-pluginctl register` 是安装器 bootstrap 和离线恢复使用的模型外底层入口：

```bash
sudo /opt/pi-ops-agent/current/bin/agentd-pluginctl register \
  --root /var/lib/ops-agent/plugins \
  --source /var/lib/ops-agent/plugin-sources/workload.example \
  --plugin-id workload.example \
  --kind workload \
  --digest sha256:<reviewed-digest> \
  --scope control.machine.read \
  --approved-by local:<operator-id>
```

CLI 会重新 snapshot source 并核对 digest/scopes，而不是相信先前 `inspect` 的路径。成功后原子
切换 `current`。查询当前激活项：

```bash
/opt/pi-ops-agent/current/bin/agentd-pluginctl current \
  --root /var/lib/ops-agent/plugins \
  --plugin-id workload.example
```

常规运行不应让 Agent 直接调用这个 root CLI。Core 已提供 typed `plugin.register` change：Agent
必须提交 plugin ID、kind、version、publisher、精确 digest、完整排序 capabilities 和完整排序
requestedScopes。Broker 根据 plugin ID 推导唯一 source path，在 prepare 和 execution 时重新
扫描源码并逐项匹配 manifest，将全部字段写入 `ApprovalPlan`，经 reviewer 与人类两次确认后才
snapshot/activate。成功后 broker 再读取 active registration 验证；失败自动恢复先前 digest，
若恢复不确定则进入 `RECOVERY_REQUIRED`。

因此标准安装流程是：模型外把源码放入 `/var/lib/ops-agent/plugin-sources/<pluginId>` 并 inspect，
Agent 可 prepare `plugin.register`，用户只批准 broker 展示的真实 ID/kind/version/publisher、
digest、capabilities 与 requestedScopes；Adapter plan 另由 broker 派生 runtime authority 字段，
明确 action scope 仅绑定 digest review/typed IPC，而 Source 可按其专用 UID 直接使用平台 credential。
初始化所需的两个 Plugin 是例外的 bootstrap 流程，
因为在它们激活前 TUI/基础工具尚不能运行。

## 必需 Plugin bootstrap

`adapter.tui` 与 `workload.base` 缺一不可：没有前者就失去本地恢复入口，没有后者则没有基础
工具。`init` 的处理顺序是：

1. 从已验证 Release 将 bundled source 复制到可编辑的 `plugin-sources`；
2. 对真实 source 做 inspect；
3. 展示 ID、kind、version、publisher、digest、capabilities 和 requestedScopes；`adapter.tui` 还展示
   compiled Client 的 local administrator UID、宿主 filesystem/network 与 credential authority；
4. 要求用户输入精确 `APPROVE <id> <digest>`；
5. 以 `bootstrap:<admin>` 写入 grant，再启动服务。

无 TTY 自动化可使用 `--approve-required-plugins`，但调用方必须先在外部系统复核该 Release
内的精确源码与 scope。此参数不能批准其他 Plugin，也不能让更新后的 digest 复用旧 grant。

## 更新与回退

更新流程与首次安装相同：编辑 source、inspect、新批准、register。任何内容或 executable bit
变化都产生新 digest。不要直接修改 snapshot 或 `current`；registry 会在下一次读取时拒绝。
若 Target 曾为通用 `file.write`/`service.action` 配置 standing scope，还必须显式把
`authorization.baseWorkloadDigest` 更新为新批准的 `workload.base` digest；未更新期间只回落到
逐次人工审批，不能继续借用旧摘要。

Broker-mediated `plugin.register` 会保留旧 registration，并在执行失败时恢复先前 digest；显式
`/rollback` 也使用 change 中绑定的 recovery metadata。底层 CLI 尚未公开通用 rollback 子命令；
离线恢复时可重新以旧 source/digest 做一次显式注册，不能仅手工改 symlink 后称为安全回退。

更新的 in-flight 边界是明确的：若 A invocation 先取得 shared lease，register 不等待也不穿越
它，而是 fail closed 并保持 A，broker 把“尚未激活”的 rollback 视为幂等成功，管理员稍后重试；
若 register 先取得 exclusive lease，新的 A invocation 失败，B 激活后旧 Session 也必须重开。
因此更新不会让旧 digest 在 B 激活之后再发出新的 provider 请求。已经完成的 A invocation 不被
追溯撤销；已经由 broker 签名为 `PENDING_APPROVAL` 的 A change 继续保留 exact A digest、canonical
plan 与 reject/rollback 证据，但 B 成为 current 后 Client 拒绝再 approve A，必须在 B 下重新
prepare。current 仍为 A 时，Client/lease broker 在第二次 approve 持有的 A shared lease 只是前置
纵深防御；root submitter 在第一次签名 status 后还会独立解析 canonical 单一 ID/digest，直接从
固定 registry 验证 current 并持有另一把 A shared lease，覆盖 reviewer、TTY、第二次 status 与
最终 broker action。Client 或 lease broker 丢失不会释放 root lease，因此检查与提交之间的切换
也不能获得 standing authorization。候选 `plugin.register`/`plugin.install`/`workload.deploy` 与
rollback 不依赖 candidate digest 已是 current。

`adapter.tui` 更新自身时，两份正常 shared lease 会造成必然自锁，因此只有一个窄 handoff：权威
plan 必须恰好是单步、声明式 TUI authority 完整匹配的 `adapter.tui plugin.register`，且同一本地
TUI 已完成第二次 review confirmation。Client 随即停止输入、关闭 agent session、显式释放自己的
exact current digest lease，再通过 fixed FD 6 request / FD 7 response 的
`agentd.adapter-runner-control/v1` 要求外层 runner 释放同一 lease；runner 必须先等 lease broker
确认 `RELEASED` 才 ACK。root submitter 只在两次 ACK 后启动，旧 Client 无论提交成功或失败都退出。
该流程只释放当前这一个 TUI runtime 的两份 lease；另一 TUI、Adapter 或 runtime 仍会使 exclusive
register fail closed。多步计划、第一次 review、非本地 console、非 TUI plugin 和 Source Adapter
都不能请求该控制动作。

## legacy `.opspkg` 恢复证据与兼容边界

仓库仍保留旧 artifact catalog：

- `adapter.botmux` 的 `.opspkg`、digest 与历史 change 仅保留为恢复/审计证据，不再作为可执行
  runtime fallback；
- `workload.hermes` 由 `.opspkg` manifest 驱动固定 OCI executor；
- `plugin.install` / `workload.deploy` 仍是 broker 的 typed operations。

这些历史 artifact 有 digest、catalog pin 和审批，但以发布包而非可编辑源码交付，不应作为新
Plugin 的模板。BotMux 的新 Client 必须取得 active Source registration 与 exact-digest lease，
所以 `/botmux-setup` 在 Source `adapter.botmux` 缺失或无效时直接 fail closed，绝不执行 legacy
launcher。迁移方向是将业务行为移到 Source Adapter/Workload，同时保留核心 typed broker recipes；
旧安装的 artifact、change 与 rollback metadata 在恢复演练完成前必须继续可读。

仓库现在提供同 ID 的 `adapter.botmux` Source runtime；固定 launcher 只执行获批 immutable
snapshot 的 entrypoint。legacy package/launcher 可以被离线检查或用于读取历史证据，但不能被
setup wrapper 激活，也不能代替一次新的 Source digest 审批。
`workload.hermes-ops` 与 `workload.botmux-ops` 则是新的 Source 运维 profile：除只读诊断外，
业务 unit/path 规则保存在 digest-covered source schema；它们只通过通用 `target.inspect` 与
`workload.command.inspect` / `workload.service.manage` providers 工作。Command provider 只接收
semantic profileKey，由 Core 注入 actual non-base caller ID/digest，root policy 固定 root-owned
non-writable executable、argv、non-root account、timeout/output bound，并经 hardened `systemd-run`
transient service 执行；其 core receipt 绑定完整 profile/result，审计只记录 output digest/bytes。
BotMux setup 的 Source 先用自包含、64 KiB/16 层/有界节点的 strict JSON parser 拒绝 duplicate key、
trailing value、截断与超限输入，再逐字段构造 exact 输出白名单；env、cliRuntime、update、
command/path/credential、未知或 Unicode-confusable 字段与 object-map key 始终不会被复制。
Service provider 同样根据 actual caller 注入 ID/digest，并以
`workload.service.action` prepare 当前上游固定 unit 的 `reload|reset-failed|restart|start|stop`。Core 与 broker 不把
这些标准 ID/profile 作为 authority。它们与 legacy OCI `workload.hermes` 是不同 plugin ID 和生命周期；安装
Source grant 不会跳过 root-owned Target 的 account/manager/unit/action policy，也不授权 CLI、
配置正文或任意 argv；service `reload`/`reset-failed` 永不 standing。

## 开发入口

- Adapter 开发使用 [`agentd-adapter-dev`](../skills/agentd-adapter-dev/SKILL.md)；
- Workload 开发使用 [`agentd-workload-dev`](../skills/agentd-workload-dev/SKILL.md)；
- 部署与更新使用 [`agentd-init`](../skills/agentd-init/SKILL.md)。

每次修改 Plugin 契约、示例或运行时，必须同步更新对应 Skill、本文和测试。
