# `workload.pve`：Proxmox VE 安全运维

`workload.pve` 是仓库随附的标准源码 workload；它只是 PVE typed provider ABI 的一个可编辑
参考实现，不因第一方身份或这个 ID 获得额外信任。任意获批的合法 `workload.*` source 都可在
请求相同 provider scopes、通过 Target exact pin 时实现自己的 PVE 工具 schema/composition。它用于让 Agent 通过部署在 PVE 节点上的
`agentd-server` 和 `agentd-root-broker` 检查集群，并执行获得本次人工 grant 或显式 standing
authorization 的有限 root 操作。
它不是通用 PVE shell：协议中不存在任意 API path、`pvesh`/`qm`/`pct` argv、脚本或
callback。

本实现按 Proxmox VE 9 的官方文档和 API 结构设计。Proxmox 把管理操作统一暴露为
API；本机的 `pvedaemon` 仅监听 `127.0.0.1:85` 且以 root 执行，而 `pvesh` 是同一 API
的 shell interface。任务历史和异步操作以 UPID 标识。参考：

- [Proxmox VE Administration Guide](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf)
- [`pvedaemon(8)`](https://pve.proxmox.com/pve-docs/pvedaemon.8.html)
- [Proxmox VE API Viewer](https://pve.proxmox.com/pve-docs/api-viewer/)

## 信任与部署边界

推荐在 PVE 系统内直接部署一组 server-side 进程：

```text
client host                              PVE host

agentd (untrusted model)
  -> ops_pve_* typed tool
  -> HTTPS + mTLS ----------------------> agentd-server (dedicated non-root user)
                                           -> root-owned Unix sockets + SO_PEERCRED
                                           -> core broker (typed Linux + manual capsule)
                                           -> PVE broker (typed PVE only, separate domain/key)
                                                -> /usr/bin/pvesh fixed API calls
                                                -> local pvedaemon / PVE cluster
```

`init` 以本机固定绝对入口 `/usr/bin/pvesh` 作为 PVE 条件：只有该入口可执行时才安装并 enable
`ops-pve-root-helper.service`、创建专用 state/audit tmpfiles，并把
`/run/ops-agent/helper/pve-root-helper.sock` 纳入启动与 healthcheck。非 PVE `init` 不安装该 unit，
也不会因缺少 PVE socket 而报健康故障；升级清理残留 unit 时不删除旧 PVE state/audit。

`join` 还要求 enrollment 在 controller 上以 `issue-enrollment --pve` 显式签发。Bundle 的 PVE
receipt 与目标机可执行的 `/usr/bin/pvesh` 必须双向一致；PVE host 缺少已签名 PVE enrollment，
或普通 host 收到 PVE enrollment，都会在写 unit 前失败并回滚，绝不在 endpoint 生成 controller
未固定的替代 key。Endpoint 还必须从与 bearer bundle 独立的已认证渠道取得并显式传入
`controller-ca-sha256`，先匹配 controller CA 指纹，再使用 bundle CA 验证签名。

PVE endpoint 的 `join` 拓扑只包含 `agentd-server`、core broker 与独立 PVE broker；不在 PVE host
安装 agentd、reviewer、Adapter、模型配置、Source Plugin 工作树或审批 sudoers。Controller 上
获批且被 Target policy 精确 pin 的 PVE source workload 通过 HTTPS/mTLS 调用该 endpoint，两个 broker 使用不同 socket、state、
audit、receipt domain 和 key。

本机 `pvesh` mutation handler 会写入 pmxcfs 挂载点，因此 `ops-pve-root-helper.service` 保持
`ProtectSystem=full`，只额外声明精确的 `ReadWritePaths=/etc/pve`。该例外不会扩大到 `/etc`，也
不会复制给 core broker、`agentd-server`、Agent 或 Source Plugin runtime；core broker 的正常
mount namespace 还明确把 `/etc/pve` 标为 inaccessible，其他非特权进程也不能访问或挂载 PVE
配置树。这个 mount-namespace 例外只让 PVE broker 完成已经通过 tagged union、Target
policy 和审批状态机约束的本机 API 操作，不把文件路径或 pmxcfs 变成新的协议能力。

- `agentd` 不持有 PVE credential、SSH key 或 root socket，也不能构造审批。
- `agentd-server` 只负责 mTLS 身份、请求 schema 和 server/target scope；它不能运行
  `pvesh`。
- 两个 `agentd-root-broker` domain 是唯一 root 执行者。PVE broker 只接受版本化 PVE tagged
  union，并从已验证字段构造固定的 `/usr/bin/pvesh` 调用；它不接受 raw script。无法预先
  类型化的 manual root capsule 只能走 endpoint 的 core broker，并仍须本地逐次人工审批。
- 不通过公网或 LAN 暴露 `pvedaemon` 的本地 root API。跨机器入口仍是
  `agentd-server` 的 HTTPS+mTLS 接口。
- PVE 的 `/etc/pve/priv` 包含 API token、集群 CA 等敏感材料；Agent、源码 plugin 和
  `agentd-server` 均不得读取或挂载这些目录。PVE broker 也不得把 `/etc/pve/priv` 的路径、文件
  内容或派生 secret 放入模型输出、broker response、receipt 或 audit；现有 typed methods 不提供
  配置文件读取或任意 API traversal。

以后如果增加独立的只读采集进程，可以使用 PVE ACL 和 `-privsep 1` 的 API token；token
权限永远是所属用户权限的子集。但当前标准 workload 的 broker 路径不需要创建、分发或向
Agent 暴露 API token。

## Plugin grant、Target policy 与 standing scope

启用 PVE 能力需要两项独立且一致的授权：

1. client 侧按 [`docs/plugins.md`](../plugins.md) 检查并注册
   `plugins/workload-pve`。`plugin.register` 计划绑定 ID/kind/version/publisher、整个源码 tree
   的 SHA-256、完整 capabilities 与完整排序 requestedScopes；模型外本地 principal 对每次安装
   或更新逐次审批并写入 registration grant 与审计。源码变化产生的新 digest 不能复用旧批准。
2. PVE host 上 root-owned target policy 的 `pve.pluginId` 与 `pve.pluginDigest` 必须绑定同一
   registration，并进一步
   列出可访问的 node、storage、guest、migration target 和 operation。这个资源 policy 允许
   prepare，但不会自动成为 standing authorization。

只有 source descriptor capabilities 与其 active registration 精确一致，manifest
`requestedScopes` 覆盖所声明 PVE provider policy 的全部 scopes 时，harness 才向模型提供该
source 定义的工具；标准源码当前定义 `ops_pve_*`。模型参数中没有 `pluginId` 或
`pluginDigest`；typed provider 从 actual caller 注入二者并拒绝 `workload.base`。root broker 在
准备和执行前再次要求 target policy 中的 ID/digest 完全相同。Core 不维护 `workload.pve` 标准
ID 或完整标准工具 profile。

源码发生任何变化后 digest 都会改变，因此必须重新审批注册，并显式更新 PVE target
policy。只更新其中一侧会 fail closed。

若管理员希望一部分普通 PVE operation 无需每次人工审批，必须另在同一 Target 的
`authorization.standingScopes` 中列出精确 operation scope。当前仅
`pve.guest.start`、`pve.guest.shutdown`、`pve.snapshot.create` 和 `pve.guest.backup` 可表示为
standing scope。legacy policy、字段缺失或空数组全部逐次人工审批；standing scope 也只能在上述
plugin digest/capability/scope grant 与 PVE 资源 allowlist 的交集内生效。Guest stop/reboot、
snapshot delete/rollback、restore、migrate 被 broker 定义为 critical 且永不 standing；PVE manual
root capsule、plugin registration、package/artifact 安装和 rollback 同样永不 standing。

## 当前能力

### 只读检查

| 类型化 method | 固定 PVE API path | target policy 约束 |
|---|---|---|
| `pve.cluster.status` | `/cluster/status` | target 必须启用 PVE |
| `pve.node.status` | `/nodes/{node}/status` | `node` 必须列入 `nodes` |
| `pve.storage.status` | `/nodes/{node}/storage/{storage}/status` | node 和 storage 均须列入 allowlist |
| `pve.task.status` | `/nodes/{node}/tasks/{upid}/status` | UPID 必须与获批 node 绑定 |
| `pve.guest.status` | `/nodes/{node}/{qemu|lxc}/{vmid}/status/current` | guest type、VMID 和 node 均须获批 |

输出有大小上限，按 JSON 解码后作为不可信数据返回。workload 不提供 task log、guest console、
guest agent command、配置文件读取或任意 API traversal。

### 写操作

| operation | 行为 | 恢复语义 |
|---|---|---|
| `pve.guest.action` | QEMU/LXC 的 `start`、`shutdown`、`stop`、`reboot` | 不自动执行反向 power action；保留前后状态与 task evidence |
| `pve.snapshot.create` | 创建命名 snapshot；QEMU 明确不保存 VM state | 不自动删除已生成 snapshot；先核对权威 task 和 snapshot 状态 |
| `pve.snapshot.delete` | 先完成一次 `vzdump` safety backup，再删除 snapshot | 不自动重建 snapshot；保留 backup task/volume 作为人工恢复证据 |
| `pve.snapshot.rollback` | 先完成一次 `vzdump` safety backup，再回到指定 snapshot | 不自动恢复到 rollback 前状态；保留 backup task/volume 作为人工恢复证据 |
| `pve.guest.backup` | 在获批 storage 上运行 snapshot-mode、zstd `vzdump` | 不自动删除 backup；保留 task/volume evidence |
| `pve.guest.restore` | 从获批的 `storage:backup/vzdump-*` volume 恢复到尚未使用的同 VMID，默认不启动 | 不自动删除部分或完整 restore 结果 |
| `pve.guest.migrate` | 在获批 source/target node 间迁移 QEMU 或 LXC | 不自动反向迁移 |

### VMID 锁与 typed recovery chain

资源 identity 固定为 cluster-global `pve/vmid/<vmid>`。VMID 在 PVE cluster 中全局唯一；把 node、
`qemu` 或 `lxc` 放进 lock key 会让 migration 或类型别名绕过未解决变更。升级会把旧
`pve/qemu/<vmid>` / `pve/lxc/<vmid>` state 迁移到新 key；若折叠后 owner 不同则 fail closed。

这里的 “cluster-global” 只描述 key 的资源命名语义。v0.3 的 durable lock 仍存放在单个 PVE
broker 的本地 state 中，不是分布式锁；当前也没有把 cluster fingerprint 绑定进 Target 或 lock。
因此每个 PVE cluster 必须只有一个可接受 mutation 的 agentd-server/PVE broker endpoint，其他
节点只能把 mutation 路由到该 endpoint，或以只读 endpoint 运行。多个节点各自启用 mutation
broker 会让相同 VMID 被并发操作，属于不受支持且不安全的部署。

普通 operation 可省略 `recoveryOfChangeId`。只有补偿一个已锁定 VMID 时，新的 typed operation
才携带该字段；它进入 canonical plan，并必须引用同 PVE domain、server/machine、Target、VMID 的
`RECOVERY_REQUIRED` parent。Recovery child 永不 standing，安装过第一方 plugin、parent 曾获批、
或 reviewer 认为低风险都不能免除本地逐次审批。

转锁之前，PVE broker 使用 parent operation 与 root-only durable records 权威 reconciliation：

- 每个 primary API 前已 fsync `pve-primary-intent.json`；destructive snapshot 另有 safety-backup
  intent/task；
- intent 有而 task record/UPID 无、UPID task 仍 running、status query 失败或返回未知状态时，
  parent 保持锁，child executor 不会被调用；
- 已知 UPID 必须从其 node-bound task status endpoint 得到 `stopped`；`OK` 和 `ERROR` 都记录为
  terminal evidence，但只有 `OK` backup 才能产生唯一 volume evidence；
- active task inventory 为空不能替代已知 UPID 的 terminal proof；legacy/unknown 且没有结构化
  proof 的空 evidence 集合也不能自动视为 no-mutation。

通过后，单次 fsync state transaction 同时把 parent 标为 `SUPERSEDED`、写入 child ID/planHash、
`NO_MUTATION_STARTED|TASKS_TERMINAL` 和 task evidence，并把 `pve/vmid/<vmid>` owner 改为 child。
不会出现 unlocked gap；restart 不会恢复 parent owner。转锁后的 child 若在 audit、只读 Prepare、
mutation barrier、Execute 或 Verify 任一步失败，child 进入 `RECOVERY_REQUIRED` 并继续持锁；只有
`COMMITTED` 释放。Parent/selected-child resolution chain 作为完整审计证据保留，TTL/quota 不会
单边裁剪造成 dangling resolution。

#### `STARTED_OR_UNKNOWN` 的 local clearance

Lost-UPID 或旧版本 no-proof parent 无法得到上面的 terminal/no-start proof，但永久锁死 VMID 也会
阻断人工恢复。为此，PVE broker 提供一个仅供 root-owned approval submitter 使用的独立
unknown-result clearance。它不是 `workload.pve` capability/provider，也不出现在 source descriptor；
Agent、reviewer、Adapter、standing authorization 和普通业务 RPC 都不能把它当 workload 能力调用。

Eligibility 故意很窄：parent 必须仍为 `RECOVERY_REQUIRED + STARTED_OR_UNKNOWN`，child 必须是同
domain/endpoint/Target/VMID 的 pending canonical recovery plan，并且不能存在任何已知 UPID。已知
UPID running 或查询失败永久拒绝；已知 terminal 也拒绝 clearance，要求回到普通 task
reconciliation。mutation protocol v1 若完全没有 intent/task artifact，则普通路径已能证明
`NO_MUTATION_STARTED`，不进入 clearance。

Broker 在 challenge、签名 confirmation 和最终转锁三个阶段重复相同的权威观察：

- 对 source node 执行固定
  `pvesh get /nodes/<node>/tasks --source active --vmid <vmid> --limit 1 --output-format json`；migration
  还查询 target node，去重后的每个结果都必须为空；
- 读取 `/cluster/status`，要求 clustered 环境 quorate 且相关 node online；standalone 必须是 local
  nodeid 0；
- 读取 `/cluster/resources --type vm` 与 guest `status/current`，要求 VMID 类型、位置仍在获批
  source/target 集合内，不重复，状态只为 running/stopped 且没有 operation lock。

Observation 的 active-task、guest、cluster 子摘要和总摘要进入 challenge。管理员先审批普通 child
plan，再由 PASSWD sudo 启动的 root submitter 在真实 `/dev/tty` 展示该 challenge，并要求第二条
exact confirmation；confirmation 同时绑定 server/machine/Target、parent/child、childPlanHash、
`pve/vmid/<vmid>` 和 challenge digest。Broker 发出的 grant 默认 90 秒，仅驻内存且一次性；expiry、
restart、reject、child/parent drift 或 observation 变化都撤销。

最终 child approval 重新观察后，在同一 durable transaction 内消费 grant、把 parent 写为
`SUPERSEDED`、记录 `basis=local-unknown-clearance` 与所有摘要，并把 lock 转给 child。Parent 的
mutation disposition 必须继续是 `STARTED_OR_UNKNOWN`：clearance 是管理员接受残余不确定性的决定，
不是 no-mutation 或 terminal proof。旧 persisted v1 resolution 只有空 basis 且 disposition 为
`NO_MUTATION_STARTED|TASKS_TERMINAL` 时向后兼容；未知 basis、字段缺失或空 basis unknown disposition
全部 fail closed。

所有 PVE operation 都返回 `RollbackAvailable=false`。上表中的 safety backup 和前置状态是恢复
证据，不授权 broker 在原 change 内自动采取补偿动作。任何删除 snapshot、反向迁移、power
action、restore 或其他补偿都必须根据当前权威状态创建新的 typed operation，重新计算
precondition 和计划，并由用户单独审批；原 operation 失败或终态不确定时进入
`RECOVERY_REQUIRED`，不得把“尝试恢复”写成已经 rollback。

当前独立 reviewer 是确定性规则实现，只看原始用户输入与 broker 的 authoritative plan；它不看
Agent 解释，不是 LLM，也不实现基于风险的自动批准。它可以把 destructive PVE plan 提升为
critical，但不能创建 standing scope、批准操作或降低 policy 风险下限。
Broker 自身也拒绝把 guest stop/reboot、snapshot delete/rollback、restore 或 migrate 写入
`standingScopes`，因此这条高风险边界不依赖 reviewer 是否可用或是否正确分类。

restore 当前故意只接受普通 `vzdump-qemu-*` / `vzdump-lxc-*` volume ID，并要求文件名中的
guest type 和 VMID 与计划一致。它不接受任意文件路径、URL、PBS namespace、`force` 或覆盖
现有 VMID。需要 PBS restore、跨 VMID restore 或参数更多的迁移时，应新增更窄的协议 arm，
而不是加入 raw argv。

## 执行前置条件与任务终态

每次写操作在获得本次真实 client 审批或命中显式 exact standing scope 后还会重新检查：

- active root policy revision 和 workload digest；
- 已加入 Corosync cluster 时必须 quorate，source node 在线；迁移时 target node 也必须在线；
  未入集群的单节点仅在 API 明确报告 `local=1, nodeid=0, online=1` 时按 standalone 接受，
  非零 nodeid 的旧集群成员不能绕过 quorum；
- guest 位于允许范围内，状态是 `running` 或 `stopped`，且没有 PVE operation lock；
- backup/restore 使用的 storage 为 allowlist 内的 `active=1, enabled=1` storage；
- restore VMID 在整个 cluster 中尚未被使用；
- migration guest 唯一位于获批 source node，target 位于 `migrationTargets`。

`Prepare` 永远只读；destructive snapshot 的 safety `vzdump` 只能在 change/audit 已跨过 durable
`EXECUTING` barrier 后运行。Safety intent 在 API 前 fsync，task UPID/唯一 volume 在 primary 前
写入 change evidence。随后 primary intent 先 fsync，再执行最后一次完整前置条件重验：普通操作
重算原审批 digest；destructive snapshot 继续绑定 `PreviousStatus`、snapshot、storage、node/
quorum 与 guest lock，并要求 backup set 恰好是审批 baseline 加本次唯一 safety volume。

所有 mutation 必须返回格式正确且与 node 绑定的 UPID。Broker 先把它以 `0600`
写入 root-only task record，并将对应 evidence 合并到 change；两份 durable evidence 都完成后，
审批请求即可收到签名 `EXECUTING`。这只表示 broker 已可恢复地接管该 UPID，不是
任务或 operation 已成功。

后续由 broker-owned per-change singleflight worker 用每次新建的有界 context 查询原 UPID。
它不依赖审批 HTTP/CLI request，请求取消也不会取消已发起的 PVE task；没有后续
HTTP 或 client 轮询时仍会收敛。`change.status` 只读取签名状态，并可幂等确保同一
change 的 worker 已调度，不是状态机驱动器。Daemon shutdown 在当前查询或验证期间只停止
observer，保留 `EXECUTING/VERIFYING` 与 VMID lock；重启时从 durable intent/task/evidence
自动续跑，不重复发起 API。只有 `status=stopped` 且 `exitstatus=OK`，并且
operation-specific postcondition 也成立时，change 才能成为 `COMMITTED`。

启动 task、落盘、新鲜轮询或验证的任何不确定失败都不得宣告成功。Intent
持久化失败或最后重验漂移发生在 API 前时可标记确定 no-mutation；API 已尝试但
UPID 丢失则必须保留 intent、VMID lock 与 `STARTED_OR_UNKNOWN`，不能从错误文本推断已停止。

PVE rollback endpoint 无条件拒绝这些 operation，即使 persisted `rollbackAvailable` 被伪造为
true。补偿只能创建新的 typed recovery child。Restore argv 固定包含 `--start 0`，Verify 还必须
看到 guest `stopped` 且 unlocked，不能只相信 restore task 的 `OK`。

`change.prepare` response 不是终态证据。Controller 在每次 prepare 后必须以新的 requestId 查询
PVE `change.status`，使用该 endpoint registration 固定的 PVE-domain Ed25519 public key 校验
receipt，并验证完整 server/machine/Target/change/plan/state/result scope。只有签名
`PENDING_APPROVAL` 才能向审批 side-channel 暴露 change reference；签名 `COMMITTED` 才能表示
standing operation 已完成。PVE key/domain 与 core broker 独立，不能交叉接受。

跨语言请求 deadline 只覆盖本次交换、API 启动与 UPID 双重 evidence 落盘，不包住整个
backup、restore 或 migration。返回签名 `EXECUTING` 后，长任务属于 broker-owned worker；
client timeout/取消不会因此把 change 标成 `RECOVERY_REQUIRED`。只有 broker 自身的新鲜查询超时/
错误、task terminal failure、journal/evidence 失败或 postcondition 失败才 fail closed 并保留 VMID
lock。运维人员可使用审计中记录的 UPID 独立核对 authoritative task status 和实际
资源，但不能盲目重放同一操作。

## Target policy 示例

下面的示例允许对两个已知 guest、两个 node 和两个 storage prepare 已列 operation，但仅把
`pve.guest.start` 作为 standing scope；其他写操作仍逐次人工审批。`pluginDigest` 必须替换为
`agentd-pluginctl inspect` 给出的实际值；不要使用通配符或占位 digest 投产。

```json
{
  "version": 1,
  "revision": "policy-pve-20260808-v1",
  "targets": [
    {
      "id": "target-pve-root",
      "account": "root",
      "displayName": "PVE cluster maintenance",
      "inspect": {
        "hostSnapshot": true,
        "processList": true,
        "units": [],
        "readPaths": []
      },
      "changes": {
        "writePaths": [],
        "units": [],
        "packages": [],
        "plugins": []
      },
      "authorization": {
        "standingScopes": ["pve.guest.start"]
      },
      "pve": {
        "pluginId": "workload.pve",
        "pluginDigest": "sha256:REPLACE_WITH_64_LOWERCASE_HEX_DIGITS",
        "nodes": ["pve1", "pve2"],
        "storages": ["local", "local-lvm"],
        "guests": [
          { "guestType": "qemu", "vmid": 100 },
          { "guestType": "lxc", "vmid": 101 }
        ],
        "migrationTargets": ["pve2"],
        "operations": [
          "pve.guest.backup",
          "pve.guest.migrate",
          "pve.guest.restore",
          "pve.guest.shutdown",
          "pve.guest.start",
          "pve.snapshot.create"
        ]
      }
    }
  ]
}
```

数组在载入时会规范化排序；重复值、未知字段、未知 operation、未列入 `nodes` 的 migration
target、非法 VMID 或非精确 SHA-256 都会拒绝整份 policy。删除 `authorization` 或使用空
`standingScopes` 会安全地回到全人工审批；它不会从 `pve.operations` 推导 standing authority。

## 上线验收

本仓库的单元测试使用 fake `pvesh` runner 验证 tagged union、固定 executable/path/argv、
digest/resource policy、safety backup 和 UPID terminal status。它不能替代真实 PVE 验收。

首次生产部署前应在 disposable PVE lab cluster 完成：

1. QEMU 与 LXC 的五类 read smoke test；
2. start/shutdown/stop/reboot 的状态、失败 evidence 与新 typed compensation 流程；
3. snapshot create/delete/rollback，并实际验证 safety backup 可恢复；
4. backup、unused-VMID restore 和 source/target migration；
5. 非 quorate、node offline、storage disabled、guest locked、UPID error、deadline timeout、
   broker/server 中断和重启恢复测试；
6. 确认审计、change record 和 PVE task history 能用同一 UPID 对账。

在这些测试完成前，PVE 真实宿主仍属于“实现已覆盖、生产路径未验证”。
