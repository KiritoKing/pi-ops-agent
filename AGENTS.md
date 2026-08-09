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

- Noble restricted-userns host policy 必须通过已验证同一 Release 的显式 `ops-agent-bootstrap host-policy inspect/install/status` 两阶段入口到达内部 helper；Raw `host-policy`/`init`/`join` 必须固定明确的同一个 `OPS_AGENT_VERSION=vX.Y.Z` 并核对 payload version，tar/deb launcher 必须绑定相邻 versioned release-root，`join` 不得触碰该策略。离线 tar 只能由 root 解入独占 staging；从用户/Agent 可写目录 sudo 执行、root path-chain/release-tree owner 或 DAC 不安全必须 fail closed。所有 native package 前置只能由模型外管理员在 Phase 1 前单独安装；release installer 不得调用包管理器，缺失命令必须 fail closed。AppArmor/bwrap 不能成为 server-only deb 的强依赖，也不能由 `init` 静默安装或批准。
- `agentd`（当前 unit：`ops-agentd.service`）必须永久非特权运行。禁止调用 `sudo`、读取宿主 credential、直接写系统目录或执行 root 命令。
- 模型和 agentd UID 只能准备或查询变更，不能批准、拒绝或回滚。真实 client peer 的 UID 必须由 Unix `SO_PEERCRED` 校验。
- 公开 `agentd.sock` 只能由 `agentd-client-gateway` 持有；group DAC 只授予可达性，不能作为 Session 身份。gateway 必须把 kernel-observed peer UID、exact active Adapter ID/digest 与外部 Session ID 绑定为独立 backend namespace，并在进程全局拒绝同 namespace 的第二个 live writer；agentd 只能监听同 UID owner-only 的 `backend.sock 0600`。SO_PEERCRED 后还必须在启动任意 per-connection goroutine 前执行固定 process-total/per-UID admission，拒绝时有界写错并关闭；unit 保留 TasksMax/LimitNOFILE/MemoryMax。不得信任调用方声明的 UID、可预测 Session ID 或 group membership，也不得宣称该同 UID gateway 能隔离已被攻陷的 agentd。
- `ops-agent` service group 与 `ops-agent-client` 必须分离。管理员和 Adapter 只能通过 client group 连接 agentd、只读已批准 CAS 并使用 status-only observer mTLS；agent role private key 必须保持 `ops-agent:ops-agent 0600`，observer 不能 prepare、approve、reject 或 rollback。
- 所有普通 root 变更必须通过 `agentd-root-broker` 的版本化 tagged union。当前实现 artifact 为 `ops-root-helper`/`internal/roothelper`；禁止增加 raw root command、任意 argv、任意脚本或 shell callback RPC。
- `agentd-guardian` 必须与 `agentd` 同 UID，只能校验固定进程身份并有界终止卡死的 agentd；旧 root `ops-systemd-helper` 已退出 release/runtime，只可在升级与卸载流程中做兼容清理，禁止重新打包、启动或扩大其主机巡检、journal、unit、`systemctl` 权限。
- `/approve`、`/reject`、`/rollback`、`/status` 必须由 client 在模型上下文之外截获。不得把自然语言中的同名文本视为授权。
- `agentd-approval-reviewer` 只能根据用户原始输入、broker 返回的权威计划和本地策略给出解释、拆分与风险下限；它不能读取 agent 的解释，不能持有审批密钥，也不能直接批准、拒绝、回滚或调用 broker。Client 必须逐次验证 reviewer response 的 exact reviewId、planHash、canonical userIntentDigest，且每个 finding.stepId 都属于请求中的 canonical plan；不能只验证 planHash。当前 reviewer 是确定性规则实现，不得宣称已实现 LLM/AST 拆分或基于模型判断的自动放行。standing execution 只能来自 root-owned Target policy 的显式精确 scope，不能来自 reviewer。
- adapter 与 workload 都是不可信源码插件，不因第一方身份获得额外信任。每次安装或更新必须重新计算内容摘要、展示所请求 scope 并由用户在模型外本地流程逐次审批；授权必须同时绑定插件 ID、kind、摘要和 scope，摘要变化后旧授权立即失效。`plugin.register`、`plugin.install` 和 `workload.deploy` 永不允许 standing authorization。可执行 Source Adapter 与 Workload runtime 必须由双层固定 bubblewrap PID namespace 收拢进程树：outer bwrap 保留其默认 PID 1 reaper，inner bwrap 才以源码入口作为 PID 1 并禁止继续嵌套 userns；outer 必须同时用专用 `--sync-fd` 暴露 reaper 生命周期、用有界 `--info-fd` 返回 outer init 的 kernel `child-pid`。runner 捕获该 PID 的进程 start identity，并且只能在 sync FD EOF、所有相关进程 `close`、该 exact `/proc` identity 已消失或明确发生 PID reuse 后释放摘要 lease；sync 失败也必须先等 identity 消失再报错，初始 stat 不可读时只能保守等该 PID 出现 ENOENT，info 在取得 authoritative PID 前失败则必须保持 invocation/lease fail-stop。不能把 outer monitor 的 initial-process exit 或 sync FD 单独关闭当成 namespace 已清空。禁止 graceful runtime 路径中的 detached/unref 后代越过摘要 lease 生命周期。outer 在 inner 启动前只能执行同一个固定 root-owned bwrap，不能把允许创建 inner userns 的窗口交给不可信源码；outer 不得使用 `--as-pid-1` 或 `--disable-userns`，inner 必须使用两者。当前 socket broker lock 不持久跨 broker crash、强制断连或 runtime SIGKILL；在固定 supervisor/pidfd 或持久 quarantine 纳入 broker unlock 条件前，文档不得把该异常窗口宣称为 crash-safe。Adapter 保留业务所需网络/宿主用户权限不等于它获得了额外信任。声明式 `adapter.tui` 不执行插件源码，compiled Client 必须自己持有 exact adapter digest lease 到退出，不能只依赖外层 runner 存活。
- `adapter.tui` 自更新只能在一个 canonical 单步声明式 `plugin.register` 已由同一本地 TUI 完成第二次确认后交接：Client 先停止输入、关闭 agent session 并等待自己的 exact-digest lease 释放，再通过 fixed runner-only control FD 请求外层 runner 释放同一 lease并等待 ACK，之后才可启动 root submitter；旧 Client 无论提交成功或失败都必须退出。不得让多步计划、第一次 review、非本地 console、其他 Adapter 或 Source code 触发 handoff，也不得释放另一 TUI/runtime 的 lease；剩余 shared lease 必须继续使 exclusive update fail closed。
- Source Adapter runner 必须为 exact active digest 持有 shared invocation lease，直到其 Adapter/TUI 子进程完全退出；register/activate/deactivate 的 exclusive lease 忙时必须在切换 `current` 前失败。plugin-bound pending plan 只能提取一个 canonical plugin ID/digest；approve 时若摘要已不再 current 必须拒绝。Client/lease-broker lease 只是前置纵深防御；root submitter 必须在第一次签名 status 后独立解析同一 canonical ID/digest，直接从固定 registry 取得并持有自己的 exact shared lease，覆盖 reviewer、TTY、第二次 status 与最终 broker action，不能只做“提交前再读一次 current”或依赖 Client 进程存活。
- adapter 只能通过稳定的会话、消息、事件和审批来源接口接入。只有能以操作系统或等价强认证证明用户身份的 adapter 才能承载远程审批，否则必须回退到本地 CLI/TUI。
- Adapter descriptor 必须使用版本化、strict、bounded 的 `agentd.adapter-inbound/v1`、`agentd.adapter-session-control/v1` 与 `agentd.adapter-outbound-action/v1` 声明实际支持的类型、control 和 action，并用固定 `runtimeAuthority` 明示 execution、宿主 filesystem/network、runtime UID 可读 credential 与 action-scope enforcement；runner 必须把行为项精确映射到获批 manifest 的动作级 capability/scope，extra/missing grant 与 capability confusion 在 descriptor/typed IPC 边界全部拒绝。该 capability/scope 只是 digest-review grant 与 typed IPC contract，不是 credential-bearing Source Adapter 的 OS action sandbox；源码仍能以其专用非 root UID 直接调用平台并使用该 UID 可读 credential，安装 ApprovalPlan/reviewer 必须展示这份完整 authority，不得声称 `send` scope 能阻止 direct `quote`。可信来源 evidence 只是待模型外独立验证的元数据，不是 ApprovalIntent。当前 TUI 只可声明 `text + bind + display`，BotMux 只可声明 `text + bind + send`；不得虚报 reply/quote/mark/handoff/compact/clear、持久 outbox 或远端审批。
- workload 只能声明、组合或暴露已注册 capability；源码仅可在固定、无网络 bubblewrap host 中运行，并经有界 IPC 调用 scope-gated typed provider。业务 tool capability 与 provider name 是两套独立命名：descriptor capability 必须与获批 manifest 精确相等，但它不能代替 manifest `requestedScopes` 授权 provider；Core 只按 provider name 查找固定 policy，并逐项校验该 policy 的 required scopes。Workload host 的 outer/inner 两层都只可创建 `user/ipc/pid/net/mnt`，`ops-agentd.service` 的 `RestrictNamespaces=` 必须精确同步该最小集合，同时保留 `ProtectHostname=yes`、`ProtectProc=invisible`、`ProcSubset=all`、inner nested-userns deny 与仅供这两层固定 bwrap 建立/封闭 user namespace 使用的 `/proc/sys/user/max_user_namespaces` 窄可写 mount；安装探针必须在唯一、root-owned、位于 `/run/systemd/system` 的短生命周期 static unit 中复制并验证等价 hardening 与同一双层结构，结束后精确清理该 unit、drop-in、driver 与 nonce，runtime 还必须验证 outer sync FD + exact init process identity completion barrier。`ProcSubset=all` 是访问该 namespaced sysctl 的必要契约；`ProtectProc=invisible` 只隐藏其他 UID 的 PID 目录，不能被描述为隐藏 same-UID 进程或只读的非 PID procfs 全局元数据。除精确 sysctl 例外外必须保留 `ProtectKernelTunables=yes`，并同时保留 `PrivateDevices=yes`。每次 invoke 必须为 exact active digest 持有 registry shared invocation lease，register/activate/deactivate 必须取得同一 plugin lock 的 exclusive lease，禁止只靠 provider 前后重复读取 `current` 处理更新竞态。`adapter.tui` 与 `workload.base` 是必需的源码插件；真实 bubblewrap/user namespace 不可用时初始化必须 fail closed 并回滚。不得通过 agentd 内 `eval`/动态 import、宿主 shell fallback 或任意子进程把插件源码变成 core/root 逃逸路径；需要 root 的能力必须仍由版本化 broker tagged union 表达。
- Ubuntu 24.04 Noble 在 `kernel.apparmor_restrict_unprivileged_userns=1` 时，只允许用独立的 `scripts/configure-noble-bwrap-apparmor.sh` 配置发行版 `bwrap-userns-restrict` 与 exact host-wide `/usr/bin/bwrap ix,`，并让 `ops-agentd.service` 以 typed ignore-missing `AppArmorProfile=-bwrap` 进入 setup profile。该 AppArmor exec rule 不绑定 argv，会扩大宿主上该 executable 的继承执行授权，所以 `install` 必须在 `init` 前由模型外本地管理员逐次确认，并以 canonical approval digest 绑定 package 名、发行版 profile exact version/source hash、local-rule bytes 与批准前完整展示的 authority-summary hash；helper 不能由 Agent、sudoers 或 `join` 调用，也不得安装 package、修改 sysctl、启用 SUID/unconfined、删除双层 bwrap 或绕过真实 static-unit proof。`inspect` 只在 `/etc/apparmor.d` 的独占锁内核对 eligibility；`status` 不修改持久 policy，但对 `managed:enforce` 必须在同一把锁内创建并清理新的短生命周期 authority smoke，只有本次成功并输出 `verified-now` 才能视为当前证据。helper 的 root-owned `NoNewPrivileges=yes` authority smoke 必须闭世界核对 exact FragmentPath/DropInPaths、唯一且无 flags 的 ExecStart、空 hooks/environment/groups/capabilities、完整 PID 1 effective vector，并验证 effective profile、outer→fixed inner、最终 Source PID 1 stack 到 `unpriv_bwrap`、五组 capability 全零，以及继续创建 userns/nested bwrap 均失败；hosted gate 未取得这份 exact smoke 前不得宣称 production 支持。这条最小兼容只覆盖直接 Node 的 `ops-agentd`/mandatory `workload.base`。BotMux guard 必须以实际 host evidence 而不是发行版标签为准：任何 host 只要读到 restricted-userns=`1` 且 AppArmor=`Y/y`，就在 wrapper/config mutation、hardener 或 restart 前拒绝；Noble 对 restriction evidence 缺失/不可读也拒绝，其他 host 只有该 sysctl 安全不存在时才可跳过。真实 main→pi wrapper 提前 attach 会先落入 `unpriv_bwrap` 并破坏后续 setup，Adapter direct probe 不能当作其生产证据；该事实优先 guard 不扩大 host-policy helper 的范围，helper 仍只支持 Noble。profile/version/hash/rule/authority-summary 漂移必须随新 Release 重新审阅。默认卸载永久保留宿主 policy；本 Release 的 helper `remove` 必须始终 fail closed，因为用户态 active-label scan 无法排除检查后新进程进入 setup profile 的竞态，任何移除只能走另行设计和审计的主机维护流程。fresh install 失败后只有 kernel 明确证明两 profile 均 absent 才能删除本轮 exact fresh files；既有 managed files + kernel absent 的 reload/smoke 失败必须保留 files 与 kernel evidence。LXC/OrbStack 无法管理宿主 policy 或无法通过真实探针时继续 fail closed。
- 上述 Noble 兼容有必须披露并由同一次本地批准接受的 residual：`AppArmorProfile=-bwrap` 使长期运行的 `ops-agentd` Node 本体处于 bwrap setup profile。`User=ops-agent`、`NoNewPrivileges=yes` 和空 `CapabilityBoundingSet` 继续阻止其取得宿主 capability，但被攻陷 Core 仍可直接尝试该 profile 允许的 userns/mount/network setup syscall；AppArmor 没有把 setup authority 限定到固定 bwrap argv。只有首次 non-bwrap Source exec 才 stack `unpriv_bwrap`。在引入独立、typed、短生命周期 spawn supervisor 前，不得把这条兼容描述为只向固定 outer→inner 命令开放的 sandbox。
- Target mutation allowlist 只决定操作能否 prepare；只有显式非空的 `authorization.standingScopes` 才能让与该 scope 精确匹配、并仍通过 plugin digest 与资源 policy 的普通 operation 在 prepare 内执行。普通 `file.write`/`service.action` 必须由实际调用的 `workload.base` 注入 ID/digest，且 standing policy 还必须以 `authorization.baseWorkloadDigest` 精确绑定同一 digest；调用方或摘要不匹配时只能逐次人工审批。`target.inspect`、`workload.service.manage` 与 PVE typed providers 是通用 ABI，不绑定仓库随附的业务 plugin ID；后两类必须拒绝 `workload.base`，根据实际非 base caller 动态注入 ID/digest，并由 Target policy 精确 pin 同一 ID/digest、资源与 operation。Hermes/BotMux unit/path 等业务正则只能存在于其 source descriptor，不得回填 Core 或 broker 的标准 ID allowlist。legacy policy、字段缺失或空数组全部逐次人工审批；package/artifact 安装、`plugin.register`、`plugin.install`、`workload.deploy`、`breakglass.script`、rollback、`workload.service.action` 的 `reload`/`reset-failed`，以及 critical PVE stop/reboot/snapshot delete/snapshot rollback/restore/migrate 永不 standing。
- `workload.command.inspect` 是通用只读业务 recipe，不是 raw command。Source 只能提交 machine/Target 与 semantic `profileKey`；Core 必须根据 actual non-base caller 注入 ID/digest，root-owned Target policy 固定 non-root account/home、root-owned 且整条解析路径 group/world 不可写的 executable、完整 argv、timeout 与输出上限。Core broker 只能通过固定 `/usr/bin/systemd-run --wait --pipe --collect --uid=...` transient service 执行，并保持 `ProtectSystem=strict`、`ProtectHome=read-only`、`PrivateNetwork=yes`、clean env 和 cgroup timeout；不得削弱 broker unit 的 `ProtectHome=yes`，不得执行用户可写 CLI，也不得接收 shell/argv/path/env。结果必须由 core broker 签名并绑定 server/machine/Target/method/plugin/digest/profile/result digest；Root/Agent audit 只存 output digest/bytes/truncated 等元数据，不存正文。标准 Source 还必须对模型可见结果做业务白名单；BotMux setup 必须在 digest-covered Source 内用有界、拒绝 duplicate key/trailing value/过深输入的 strict JSON parser，逐字段复制 exact allowlist，并丢弃全部未知、`env`、`cliRuntime`、`update`、command/path/credential 字段与 object-map key，不能信任上游 mask 或直接 `JSON.parse` 后遍历。
- `workload.json-config.edit` 是通用 semantic 单字段 JSON 写 recipe，不是 JSON patch 或任意 file write。Source 只能提交 machine/Target、profile、selector、semantic field 和严格 string/boolean/clear tagged scalar；Core 按 actual non-base caller 注入 ID/source digest，所有账号/UID/home/config path/selector key/actual JSON field/type constraint 必须来自 root-owned `jsonConfigWorkloads`。它永不 standing、必须签名 `PENDING_APPROVAL` 后由本地 TUI 逐次二次确认；review/submit 全程既保持 Client 前置 exact-digest lease，也保持 root submitter 在第一次签名 status 后直接取得的独立 shared lease。Broker 只调用固定 root-owned `/usr/lib/ops-agent/agentd-json-config-helper`，以 target UID 的 hardened transient unit 完成 strict JSON inspect/snapshot/mutate 与 `RENAME_EXCHANGE` digest CAS；before/after sealed copy 只能由 root 读取，交换结果不确定必须 `RECOVERY_REQUIRED`。绝对路径值还要绑定 openat2 directory identity proof，并明确验证后任何获得父目录写权的本地主体仍可替换 pathname 的 residual；整文档 semantic rewrite、未知字段保留但格式/order 不保留必须进入 ApprovalPlan。
- JSON config 的 `exchangeRestored` 只证明 pathname exchange 被换回，不证明换回内容等于 approved-before。Broker 必须在 helper 返回后重新执行 typed inspect：只有 exact before 可作为 no-mutation 终态，exact after 才可继续验证，第三状态或无法观察一律保留锁并进入 `RECOVERY_REQUIRED`；审计必须保留 `mutationAttempted=true` 与 `exchangeRestored=true`。
- 任意 root Target 都可 prepare `breakglass.script` manual root capsule，但它永远只能由本地 TUI 经 PASSWD sudo 和真实 `/dev/tty` 逐次人工审批，不能由 Agent、reviewer、Adapter 或 standing policy 批准；script digest、正文和 network 声明必须绑定计划，backup paths 与 verify script 可为空，但 reviewer 必须把每个 capsule 及缺少恢复或 postcondition 证据标为 critical。`network=false` 只要求 transient unit 使用 best-effort `PrivateNetwork`，full-root script 仍可逃逸或委托 PID 1，不能称为不可逃逸的断网边界；verify script 是 caller-provided privileged postcondition，不是独立 verifier。PVE broker 禁止 raw script，只能由 endpoint 的 core broker 执行 capsule。
- 写操作必须遵守 `PREPARED/PENDING_APPROVAL → APPROVED 或显式 standing authorization → EXECUTING → COMMITTED / ROLLED_BACK / RECOVERY_REQUIRED`。每次 prepare 后 controller 必须通过 `change.status` 获取并验证对应 domain 的 pinned Ed25519 broker receipt；只有签名状态为 `PENDING_APPROVAL` 才能暴露审批 side-channel，签名 `COMMITTED` 才能表示 standing execution 成功。非 root server 转发的无签名终态不能宣告成功。Core 与 PVE receipt 必须使用独立密钥和 domain。
- Core/PVE 的独立 socket、state、receipt key 与 systemd mount namespace 约束正常协议路径和意外访问，不构成已被攻陷 root broker 之间的 containment；不得声称 domain separation 能防御宿主 root 或任一 root broker compromise。
- 普通 `file.write` 的完整有界正文必须进入 canonical ApprovalPlan，不能只展示不可读摘要；它永久禁止写 agent policy、runtime、TLS、receipt、credential、可执行 payload、sudoers 和 systemd 控制面。这些位置只能使用专用 tagged operation 或另行开放的本地 break-glass。
- 不得为了让测试或部署通过而削弱 systemd hardening、bubblewrap namespace、路径 allowlist、peer UID 校验、速率限制或审计。
- 禁止提交 API key、IM credential、SSH 材料、生成的 systemd credential、运行时状态、备份或审计日志。
- `join` endpoint 只安装 `ops-agent-server`、core broker，以及 enrollment `--pve` 与本机 `/usr/bin/pvesh` 精确匹配时的 PVE broker；不得创建 agentd/reviewer/BotMux/client group、模型配置、Source Plugin 目录、审批 sudoers 或 controller health timer。
- 每个 installer-managed service 必须随 Release 携带 unit-name-specific `zzzz-ops-agent-security.conf`，安装器在 `daemon-reload` 后必须以 PID 1 的 `FragmentPath`/`DropInPaths`、identity/lifecycle、唯一且 `ExecStartEx.flags` 为空的 ExecStart、environment/resource limits、typed D-Bus `Conditions`/`Asserts`/credential vectors 及完整 security scalar/list/path/capability effective vector 为权威；healthcheck 的 `SuccessExitStatus` 必须精确，release 未声明 `ReadWritePaths` 或 `SupplementaryGroups` 时相应 effective set 必须为空。额外 loaded drop-in 只能是 exact managed policy，或完整语法落入窄 allowlist 的 root-owned host-wide compatibility reset；未知 unit-specific/drop-in authority、host-wide `service.d` 或更晚 override 造成的漂移必须拒绝，静态文件存在或逐字正确不能替代 effective 校验。`init` 验证 reviewer、gateway、guardian、lease broker、agentd、server、core broker、healthcheck，按本机 `/usr/bin/pvesh` 条件加入 PVE；`join` 只验证 server/core，且仅在 signed enrollment 与本机入口双向匹配时加入 PVE。非 PVE host 必须移除 stale managed PVE unit/drop-in，join 不得安装或保留 controller-only service/drop-in；所有相关 unit/drop-in 都必须纳入当前 mode 的事务 snapshot 与 rollback。

- outer/inner 的 procfs contract 与双层 PID namespace contract 相互独立：outer 继续创建 PID namespace 并保留默认 PID 1 reaper、sync/info completion evidence，但不使用 `--proc` 重新挂载 procfs，只继承 systemd 已应用 `ProtectProc=invisible` 的 service proc 视图来启动同一个固定 inner；inner 必须继续用 `--proc /proc` 为自身 PID namespace 建立私有 procfs，最终不可信 Source 只看见该 inner 视图。省略 outer `--proc` 不得被描述为省略或削弱 outer PID namespace、reaper 或 lease-settlement barrier。
- 当前 GitHub-hosted Noble exact `NoNewPrivileges=yes` static-unit smoke 已证明 outer 自己执行 `--proc /proc` 会在 `ProtectProc=invisible` 下以 `EPERM` 失败。只移除 outer `--proc`、保留 outer user/ipc/pid/net/mnt namespace、默认 reaper、sync/info/identity barrier，并让 inner 继续挂载私有 procfs，是待同一 hosted gate 验证的安全候选；在该验证成功前仍不得宣称 production 支持。

## 模块所有权与代码放置

| 路径 | 语言 | 职责与放置规则 |
|---|---|---|
| `src/agentd/` | TypeScript | Pi 会话、模型路由、工具编排、sandbox 和 Agent 审计。模型可见逻辑放这里，但不得拥有 root 能力 |
| `src/client/` | TypeScript | 交互、审批命令拦截、会话输出和通用完成事件。不得导入具体 IM SDK |
| `src/shared/` | TypeScript | 配置、framing、schema guard、脱敏、路由与通用 RPC。保持 transport 与厂商无关 |
| `src/reviewer/` | TypeScript | 隔离审批解释器；只消费用户输入与权威计划，不持有密钥且不产生授权 |
| `cmd/` | Go | `agentd-server`、`agentd-root-broker` 和 same-UID guardian 的薄入口；只做参数解析、依赖装配和进程启动；旧 helper 入口只保留源码兼容，不进入 release |
| `internal/` | Go | `agentd-server`、`agentd-root-broker`、guardian、peer credential、备份、验证和回滚；不对外形成通用 root API；旧 helper 实现不得被新代码复用或扩权 |
| `integrations/<bridge>/` | adapter 自选 | IM 或自动化桥接。包装 core client，消费版本化事件，并自行负责认证与投递 |
| `plugins/adapter-*/` | 源码 + manifest | adapter 源码候选；注册时按完整内容摘要封存，不以包签名或第一方身份跳过审批 |
| `plugins/workload-*/` | 源码 + manifest | workload 源码候选、capability 声明和示例；root 能力仍须落入 broker 的窄协议 |
| `skills/` | Markdown / YAML | 面向 Skills CLI 的初始化与插件开发说明；相关实现、协议或目录变化时必须同步更新 |
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

### 新增或更新源码插件

1. 使用 `agentd.plugin/v1` manifest，明确 kind、稳定 ID、capability 和最小 scope；禁止隐藏的安装脚本、任意生命周期 hook 或默认授信。
2. 安装端必须在受控源目录重新遍历内容、拒绝 symlink/设备/越界路径并计算确定性摘要；逐次本地审批必须展示完整 identity、digest、capabilities 与 scopes，授权后把同一份内容封存到不可变 CAS，再原子切换 current。
3. 更新时不得复用旧摘要的授权。回滚只能激活已有且曾获批的不可变版本；删除 current 不得删除审计证据或 CAS 快照。
4. adapter 的远程审批能力必须有可测试的强身份来源；workload 的每个 root 操作必须有 broker tagged union、策略约束、验证和恢复语义。
5. Workload tool capability 只表达业务工具所有权；调用 Core provider 必须在 descriptor 中列出 provider name，并在 manifest `requestedScopes` 中获批该 provider policy 的全部 required scopes。禁止用 capability 名称相同、第一方 ID 或硬编码标准 plugin profile 绕过 scope。
6. 同一变更更新 `docs/plugins.md`、相应 adapter/workload 文档、示例，以及 `skills/agentd-adapter-dev` 或 `skills/agentd-workload-dev`。

### 新增 PVE 管理能力

1. 只允许固定绝对路径的 Proxmox API/CLI 入口和显式参数结构；禁止暴露通用 `pvesh`、`qm`、`pct` argv 或 shell。
2. guest、node、storage、迁移目标和操作类型必须同时受 workload 摘要授权与目标策略约束；UPID 必须有界轮询并进入审计。
3. 高破坏性快照删除/回滚、恢复和迁移必须显示资源 ID、源/目标节点、存储、影响面与不可逆风险，并按策略提升审批等级。
4. 在非 PVE 环境可用 fake runner 做协议测试，但不得把它描述为真实 PVE 验证；发布前应单独记录真实 PVE 测试范围。
5. 不得把反向 PVE 动作称为自动回滚。任何补偿都必须是新的 typed change，重新观察当前状态、重新审批并保留新的审计/UPID 证据。
6. PVE resource lock 必须使用 cluster-global `pve/vmid/<vmid>`，不能包含 node 或 guest type；旧 `pve/qemu/<vmid>` 与 `pve/lxc/<vmid>` 折叠时若 owner 冲突必须 fail closed。这里的 cluster-global 只是 key 形状；v0.3 lock 是 broker-local 且没有 cluster fingerprint enforcement，同一 PVE cluster 必须只有一个 mutation endpoint，其他 endpoint 只能路由写操作到它或保持只读，禁止宣称这是分布式锁。
7. recovery change 只能通过 canonical-plan-bound `recoveryOfChangeId` 引用同 domain、同 endpoint/Target、同 cluster-global VMID 的 `RECOVERY_REQUIRED` parent；它永不 standing，必须逐次本地审批。普通转锁路径必须权威核对所有持久 intent/task：running、query failure、unsupported status、lost-UPID intent 或无结构化 no-mutation/terminal proof 都拒绝并保持 parent lock；只有 durable no-start 或全部已知 UPID terminal 才能原子写入 parent `SUPERSEDED` resolution、evidence 与 child lock。child 失败保留锁，commit 才释放，整条 resolution chain 不得被 TTL/quota 单边回收。
8. 对仅有 lost-UPID/no-proof 且 disposition 为 `STARTED_OR_UNKNOWN` 的 parent，可使用独立的 broker-internal local unknown-result clearance；它不是 workload/provider 能力。只有本地管理员经 PASSWD sudo、真实 `/dev/tty` 和第二条 exact confirmation 可签发，Agent、reviewer、Adapter、standing policy 均不可触发。任意已知 UPID（包括 running、查询失败或已 terminal）永久不能走 clearance；terminal 必须回普通 reconciliation。Broker 必须在 challenge、confirm 和最终转锁前使用固定 `/nodes/<node>/tasks --source active --vmid N --limit 1`（migration 同查 source/target）确认空结果并绑定 guest/cluster state。grant 只在内存中短时存在、一次性消费，expiry/restart/reject/state drift 均撤销；它精确绑定 parent/child/childPlanHash/resourceKey 与 observation/active-task/guest/cluster digest。最终 child approve 必须原子消费 grant、把 parent 写为带 `basis=local-unknown-clearance` 且仍为 `STARTED_OR_UNKNOWN` 的 `SUPERSEDED` resolution，并转移 VMID lock；任何持久化失败都不得产生部分转移。
9. 每个 primary PVE API 前必须先 fsync plan-bound primary intent；destructive snapshot 的 `Prepare` 必须只读，safety `vzdump` 只能在 durable `EXECUTING` barrier 与 `change_execution_started` 后运行。primary mutation 前必须完整重验获批前置条件；safety backup 后只允许该获批 backup volume 这一项精确增量。intent 持久化失败属于确定 no-mutation；API 已尝试、UPID 丢失或任务终态未知必须进入 `RECOVERY_REQUIRED`。
10. PVE API 返回的 UPID 必须同时持久化到 root-only task record 和 change evidence，然后 broker 才可返回签名 `EXECUTING`；它只表示 broker 已可恢复地接管，不是成功。后续由 broker-owned、per-change singleflight worker 使用新的有界 context 查询原 UPID 并验证，不得依赖原 HTTP/CLI request 或需要 client 持续轮询来驱动。`change.status` 只是签名观察并可幂等补调度；daemon shutdown 必须保留 `EXECUTING/VERIFYING` 与 VMID lock，重启后续跑。只有原 UPID `stopped/OK` 且 postcondition 成立才可 `COMMITTED`；丢 UPID、查询/新鲜 step timeout、task failure 或验证失败都必须保留恢复证据并 fail closed，不得重复启动 API。

## 验证要求

代码发布前至少运行：

```bash
npm run check
npm run build
go vet ./cmd/... ./internal/...
go test -race ./internal/...
git diff --check
```

涉及 systemd、bubblewrap、安装、真实模型或 bridge 的改动，还需在目标 Linux 测试机执行相关的部署冒烟和恢复测试。环境条件缺失时应明确记录未验证项，不能通过削弱安全配置制造通过结果。Release workflow 必须在 disposable Ubuntu job 以 root 和最小专用账号/组 fixture 运行真实 `test:adapter-linux-runtime`，任意非零状态（包括 `77`）都阻断发布，且 `publish` 必须显式依赖该 job；禁止修改 runner 默认用户或使用 `continue-on-error`。

## 工作区纪律

- 修改前读取现有实现、测试和相关文档，优先小范围复用，避免 unrelated refactor。
- 保护用户已有改动；不要重置、覆盖或顺手格式化无关文件。
- 依赖使用 `package-lock.json` 和 `go.mod` 中的固定版本；不要假设全局 CLI 或认证存在。
- 生成物放在既有 `dist/`、`bin/` 或临时目录，不提交秘密和主机状态。
- README 保持面向使用者且简洁；实现细节放入 `docs/`。安全、部署或恢复行为变化必须同步更新相应文档。
- 每次实现、协议、安装流程或安全边界变化，都必须同步更新相关文档和 `skills/`；未同步视为未完成。
