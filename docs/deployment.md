# 原生部署与接入

Pi Ops Agent 只支持 systemd 为 PID 1 的 Linux。Core 不提供 Docker/Compose 部署；PVE host、
VM 或 LXC 都按原生 systemd 服务安装。目标机不需要 Git、Go、Node.js 或 npm，Release 自带
编译后的 TypeScript、固定 Node runtime 和静态 Go binaries。

本文描述当前 installer 行为。它尚未经过本次变更的 OrbStack/PVE production 验证时，不得
根据文档把“应当通过”写成“已经验证”。

## 部署模式

| 模式 | 目的 | 启动的组件 |
|---|---|---|
| `init` | 第一台 controller，同时管理本机 | agentd、guardian、reviewer、TUI、本机 server、core broker、healthcheck；PVE host 另启 PVE broker |
| `join` | 增加受管 endpoint | 只 enable/start server + core broker；`--pve` bundle 与 `/usr/bin/pvesh` 匹配时另启 PVE broker，不初始化模型、Session、TUI plugin 或 reviewer |
| upgrade | 替换 immutable release | 保留 `/etc`、`/var/lib`、`/var/log`，候选 policy + 原子 `current` |

当前 `join` 使用同一个 immutable Release payload，但只创建 `ops-agent-server` service account、
endpoint config 与 server/core broker unit/tmpfiles；不创建共享 client/controller accounts。
只有当 `--pve` bundle 与固定入口 `/usr/bin/pvesh` 同时存在时才安装/启用 PVE broker。不能据此
把 join 机器当成第二个 controller；它没有模型 credential、Session registry 或 Source Plugin
bootstrap，也不会创建 `ops-agent.target` 或它的 wants dependency。PVE broker unit 默认只挂入
`multi-user.target`；controller `init` 才显式把它加入 `ops-agent.target`。

PVE 本机 `pvesh` 的 mutation handler 会写 pmxcfs。为让真实 PVE host 上的 typed mutation 工作，
`ops-pve-root-helper.service` 保持 `ProtectSystem=full`，并且只开放精确
`ReadWritePaths=/etc/pve`，不开放整个 `/etc`。core broker 明确把 `/etc/pve` 设为 inaccessible；
`agentd-server`、Agent 与 Source Plugin runtime 也不获得该路径。`/etc/pve/priv` 的路径、内容与
派生 secret 不得出现在模型输出、RPC response、receipt 或 audit。

## Managed service 的 effective systemd 边界

Release 中每个会由 installer 安装的 managed **service** 都同时带一个 unit-name-specific
`zzzz-ops-agent-security.conf`。这不是只给 `ops-agentd` 或 bubblewrap probe 使用的补丁；它是为了在
host 存在 `/run/systemd/system/service.d/*.conf`、distribution type-wide drop-in 或站点自定义
unit override 时，把每个已安装 daemon 的最小 hardening 重新固定到 unit 自己的最终 drop-in。
`ops-agent.target` 与 healthcheck timer 不是进程执行边界，不属于这组 service security drop-in。

安装模式决定唯一允许出现并必须验证的 service 集合：

- `init`：`agentd-approval-reviewer.service`、`agentd-client-gateway.service`、
  `agentd-guardian.service`、`agentd-plugin-lease-broker.service`、`ops-agentd.service`、
  `ops-agent-server.service`、`ops-root-helper.service`、`ops-agent-healthcheck.service`；仅当本机
  `/usr/bin/pvesh` 可执行时再加入 `ops-pve-root-helper.service`；
- `join`：只有 `ops-agent-server.service` 与 `ops-root-helper.service`；仅当 signed enrollment 的
  PVE bit 与本机 `/usr/bin/pvesh` 双向精确匹配时再加入 `ops-pve-root-helper.service`。`join` 不得
  安装 controller-only unit 或它们的 drop-in，非 PVE endpoint 也不得残留 managed PVE unit/drop-in。

复制 unit/drop-in 并执行 `systemctl daemon-reload` 后，installer 以 PID 1 的
`systemctl show` 与 typed D-Bus property 结果作为权威证据，而不信文件名或文件内容本身。对上述每个 mode-applicable
service，它要求 unit 与 security drop-in 都是 `root:root 0644`、non-symlink、单硬链接并逐字匹配
当前 immutable Release；PID 1 的 `FragmentPath` 必须指向该 unit，`DropInPaths` 必须包含该最终
security drop-in；agentd 的最终 encrypted-credential drop-in 也必须是 exact root-owned file 并被
PID 1 加载。它还逐项核对 `User`、`Group`、`Type`、`UMask`、`Restart`/timeout、
`KillMode=control-group`、唯一的 release `ExecStart`/argv 及无 `+`/`!` 等前缀的空
`ExecStartEx.flags`、完整 environment/EnvironmentFile 和声明的 resource limits，拒绝
额外 `ExecCondition`、start pre/post、reload、stop 或 stop-post command，并精确核对 healthcheck 的
`SuccessExitStatus`。`systemctl show` 无法可靠打印的 `Conditions`、`Asserts` 与 Load/Set/Import
credential vectors 通过 PID 1 D-Bus typed arrays 与 exact release unit 比较。最终 security drop-in 的
每个 scalar property 必须与 effective value 精确相等；namespace/address-family/path/group 等
list property 必须按集合精确相等；capability bounding set 必须没有重新获得被 drop-in 排除的
capability；release 未声明 `ReadWritePaths` 或 `SupplementaryGroups` 的 service 也必须得到空
effective set。除 exact managed policy 外，loaded drop-in 只能来自固定 host-wide `service.d` 位置，
且必须是 `root:root 0644` non-symlink single-link file，其完整语法只能包含版本化窄 allowlist 中的
container compatibility reset；未知 unit-specific drop-in、mount/execution view、directory/credential
grant 或其他未验证 directive 一律拒绝。语法异常、重复 security directive、PID 1 无法精确返回的
property、缺失 final drop-in 或任何 host-wide reset 造成的漂移都会在启动服务前 fail closed，并触发
当前安装事务回滚。

`--no-start` 安装中的 inactive service 可能被 PID 1 从已加载 unit cache 回收；因此 typed D-Bus
核验先调用 `org.freedesktop.systemd1.Manager.LoadUnit` 并使用其返回的 object path，再读取 unit
property，不能依赖只对当前 cache 命中的 `GetUnit`。

这项检查是安装/升级时的 PID 1 快照，不是对安装后宿主 root 或随后写入的新 drop-in 的持续防护。
OS image、LXC runtime 或站点管理员改变 type-wide/unit-specific drop-in 后，必须在维护窗口重新运行
同一 mode 的版本匹配 installer 验证，并重新检查 effective properties；只看
`systemctl cat` 或 `zzzz-ops-agent-security.conf` 存在不能证明当前 service 仍满足边界。

## Release pin 与完整性

生产环境应同时固定 Raw bootstrap 与 Release tag：

```bash
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
  | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- init
```

Bootstrap：

1. 只接受 HTTPS；
2. 下载当前架构 archive 与 `checksums.txt`；
3. 解包前验证 SHA-256；
4. 若存在 `gh`，执行 `gh attestation verify`；
5. 将控制交给同一 Release 内的 `ops-agent-bootstrap`：`host-policy` 只路由到相邻的
   AppArmor helper，`init`/`join` 只路由到相邻的 `install-release.sh`；两者不会互相隐式调用。

没有 `gh` 时只验证了 GitHub HTTPS + 同一 Release checksum，不能声称完成独立 provenance
验证。高价值环境应在管理机验证 attestation 后，将 archive 放入受控镜像，并通过
`OPS_AGENT_RELEASE_BASE` 使用该镜像。

Release installer 自身不调用 apt/dnf/yum 等包管理器。所有模式都要求 systemd、OpenSSL、diffutils
等基础命令已由管理员或 image 提供；`init` 还要求固定 `/usr/bin/bwrap`、`sudo`/`visudo` 与 util-linux。
缺失项在账号、unit 或 policy mutation 前 fail closed。Noble 的额外 AppArmor package 与精确版本见下文。

Release 使用固定的受支持 Go toolchain，以 `CGO_ENABLED=0 -trimpath` 只生成当前七个 Go
artifact；旧 `ops-systemd-helper` 即使源码仍用于迁移测试，也不会进入 release binary 集合。
amd64/arm64 job 会分别核对 ELF machine、拒绝 Go binary 的动态 interpreter，并用随包固定的
Node 22 LTS runtime 对所有 compiled JavaScript 做语法检查、实际加载 Client/Reviewer 入口。
同一 job 还会解包 `.tar.gz` 与 `.deb` 并逐字比较 versioned payload，检查 Core、Reviewer、
Guardian、Adapter/Workload runtime、PVE、Source Plugin、Skills、systemd 和文档表面齐全，且
不存在旧 helper 或未 prune 的开发依赖。archive 前会删除 AppleDouble `._*` 文件；任一检查
失败都不会进入 SBOM/attestation/publish。Publish 还要求两个架构的 tar/deb/SBOM 与两个 legacy
恢复/兼容 `.opspkg` 全部存在；tar、deb、opspkg、SBOM、release manifest 和最终 checksums 都分别纳入
provenance attestation。CI/Release 引用的远端 GitHub Action 必须固定到审核过的完整 commit SHA，并在
注释保留对应 release tag。每个 native job 完整运行 `verify-release.sh` 后，先把 tar/deb 上传为独立、
不可覆盖的 artifact，再运行第三方 SBOM Action；SBOM 只能进入另一个 artifact，不能改写已验证 payload。
Publish 下载两组 artifact 后、生成 manifest 或 attestation 前再次运行同一个 verifier；这里显式使用
`--no-payload-execution`，对两个架构做 archive/deb parity、ELF、完整表面和 host-Node JavaScript 语法
复验，但不在持有 release 写权限的 job 中执行下载来的 payload；bundled Node 与 Client/Reviewer 的实际
执行证据仍来自对应的低权限 native build job。`.deb` 只安装 payload，不会自动初始化：

```bash
sudo dpkg -i ops-agent-all_X.Y.Z_amd64.deb
sudo ops-agent-bootstrap host-policy inspect
sudo ops-agent-bootstrap host-policy install
sudo ops-agent-bootstrap host-policy status
sudo ops-agent-bootstrap init --admin-user "$USER"
```

前三条只适用于下面所述的 Noble restricted-userns 主机，并且必须在管理员已单独安装固定前置包后
执行；其他主机直接运行 `init`。Debian package 不把 AppArmor/bwrap 包列为强依赖，因为同一包也用于
不运行 Source Plugin 的 `join` endpoint，不能为 server-only 节点静默扩大宿主策略面。

发布阻断验收还包括真实 Linux Adapter runtime 探针。Release workflow 在独立 disposable
Ubuntu job 中只创建 `ops-agent-botmux` 专用系统账号及其两个专用组和工作目录，不修改 runner 默认
用户，再由 root 运行 `npm run test:adapter-linux-runtime`；`publish` 必须显式依赖该 job。目标机完成
`init`、确认 `ops-agent-botmux` primary group 与 `ops-agent-client` supplementary group 已安装后，也应
在源码构建树执行 `npm run build` 并由 root 运行同一命令；已安装 Release 可直接执行
`/opt/pi-ops-agent/current/scripts/probe-adapter-linux-runtime.sh`。它必须使用真实 `/usr/bin/bwrap`；
release verifier 还必须确认该 wrapper 依赖的 fixture、socket、client 与 runtime driver 脚本全部
包含在 installed payload 中，源码树探针通过不能替代已安装 artifact 的自包含验证。探针必须在
transient systemd service 中复现 BotMux drop-in：只允许 `user/pid/mnt` namespace，并在
`PrivateDevices=yes`、`ProtectKernelTunables=yes`、`ProtectProc=invisible` 与 `ProcSubset=all` 下
仅向 bwrap 暴露 namespaced
`/proc/sys/user/max_user_namespaces` 写入口；同时通过 group DAC 文件/socket、PID namespace descendant
cleanup 与 exact-digest lease release ordering。探针必须安装 unit-name-specific late drop-in，
先用 `systemctl show` 核对 manager 的 effective property/path vector，再运行真实 workload；不能让
host-wide `service.d` 的 list reset 使 transient unit 静默降级后假通过。`ProcSubset=all` 也意味着
未被其他 hardening 屏蔽的只读非 PID procfs 全局元数据可见，`ProtectProc=invisible` 不隐藏这部分
或 same-UID PID。退出码 `77` 只表示
Linux/root/systemd/账号/组/bwrap 前置条件缺失，是“未验证”而不是通过；失败或 skip 都
必须阻断该环境的发布签署。

探针复制最小 runtime 时必须保留 release 的相对模块拓扑：driver 位于临时 `scripts/`，compiled
runner 位于同级 `dist/runtime/`，因此 driver 的 `../dist/...` import 仍指向被只读 bind 的 exact
artifact。不得把 driver 平铺到 runtime root 后意外导入宿主源码树或一个不存在的 sibling。

## `init`

Ubuntu 24.04 Noble 且 `kernel.apparmor_restrict_unprivileged_userns=1` 时，先由管理员安装 helper 的
明确前置包，再通过固定到同一个 tag 的 Raw bootstrap 运行独立 host-policy 阶段；Agent 和
`init`/`join` 不会替用户静默执行：

```bash
sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
  apparmor apparmor-profiles bubblewrap ca-certificates diffutils libcap2-bin \
  openssl sudo util-linux
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
  | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- host-policy inspect
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
  | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- host-policy install
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
  | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- host-policy status
```

Raw bootstrap 对 `host-policy`、`init` 和 `join` 都拒绝 `latest`，并核对 archive 的 `payload/VERSION`，
避免多次调用跨 Release 漂移。离线 tar 不能从用户或 Agent 可写的 checkout/解包目录通过 `sudo` 直接
执行；先把已独立验证的 archive 由 root 解到独占 staging，再运行同一 release-root wrapper：

```bash
release_stage="$(sudo mktemp -d /var/tmp/ops-agent-release.XXXXXX)"
sudo install -d -o root -g root -m 0700 "${release_stage}/root"
sudo tar -xzf /path/to/verified/ops-agent-linux-amd64.tar.gz -C "${release_stage}/root"
sudo "${release_stage}/root/ops-agent-bootstrap" host-policy inspect
sudo "${release_stage}/root/ops-agent-bootstrap" host-policy install
sudo "${release_stage}/root/ops-agent-bootstrap" host-policy status
```

wrapper 在 root 执行时会拒绝 symlink、自身整棵 release tree 的非 root owner 或 group/world write，
并拒绝不具 sticky 保护的可写祖先；因此普通用户目录下的 tar extraction 会 fail closed。`.deb` 使用
`sudo ops-agent-bootstrap host-policy ...`。三种入口最终都执行 archive/deb versioned release-root 中的
同一 wrapper 和逐字相同 helper，release verifier 会检查 exact mode、wrapper 审计 hash、tar/deb parity、
Debian control/postinst bytes 及固定 launcher 路由。完成 `status` 的 `verified-now` 证据后，再用同一个
`vX.Y.Z` 单独运行 `init`。

`inspect` 只在 `/etc/apparmor.d` 的同一独占目录锁内核对 eligibility，不创建 probe。`status` 不修改
持久 AppArmor policy，但在 `managed:enforce` 时会持有同一把锁，创建并清理一个新的短生命周期
`/run/systemd/system` static authority smoke；只有这次实时探针通过才返回 `0` 并输出
`apparmor-managed-state=verified-now`。`3` 表示安全地不存在，`1` 表示 drift、partial、实时探针失败
或证据不可访问。当前 Release 只接受
`apparmor-profiles` 版本 `4.0.1really4.0.1-0ubuntu0.24.04.7` 中 SHA-256
`11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9` 的发行版 profile，并管理：

```text
/etc/apparmor.d/bwrap-userns-restrict
/etc/apparmor.d/local/bwrap-userns-restrict  # exact: /usr/bin/bwrap ix,
```

source SHA 只是一项输入，不是 approval digest。canonical v1 approval digest 同时绑定
`package=apparmor-profiles`、exact version、上述 source SHA、exact local-rule bytes，以及批准前完整
展示的 authority summary；该 summary 的 SHA-256 是
`c745e2eb341efc1a26b017e63cc03b284f63f51298036ce58e9e6661d7f7015c`，当前 approval digest 为
`sha256:d2b2928681d31e9430a9a2a1949ead607580311cba35b776e6a651e1d67254ef`。helper 必须先展示
host-wide argv-blind `ix`、长期 Core setup-profile authority、BotMux 不支持和不自动移除这四项
residual，再由 root 从真实 `/dev/tty` 读取 exact
`INSTALL NOBLE BWRAP APPARMOR sha256:d2b2928681d31e9430a9a2a1949ead607580311cba35b776e6a651e1d67254ef`。
CI/外部变更系统已经完成等价模型外审批时才可传同一 `--approve-digest`；这不是 Agent 自批。
helper 不 apt/install package、不改 sysctl、不启用 SUID/unconfined，也拒绝 disable/force-complain、
partial、symlink 或既有内容 drift。AppArmor exact exec rule 只绑定 `/usr/bin/bwrap` path，不绑定本项目
argv，因此属于 host-wide authority 扩张；发行版 version/hash 变化必须由新 Release 重新 pin、重新
批准，不能现场放宽。

fresh `install` 在可能已经 load kernel profile 后失败时绝不调用 `apparmor_parser --remove`，否则会
让 active task 失去 confinement。只有权威 kernel evidence 明确证明 `bwrap` 与 `unpriv_bwrap`
两者均 absent，helper 才删除本轮新建的 exact managed files；loaded、partial 或 unreadable evidence
一律保留 files 与 kernel state、报告 `INCOMPLETE`，交由单独主机恢复流程处理。
若 managed files 已经 exact、kernel profiles 为 absent，重新 load 或后续 smoke 失败也必须保留这些
既有 files 与任何 kernel evidence；这不是 fresh mutation，不能为了恢复 `absent` 外观而删除证据。

批准界面还必须说明 `AppArmorProfile=-bwrap` 的长期 residual：`ops-agentd` Node 本体会一直处于
bwrap setup profile。非 root UID、`NoNewPrivileges=yes` 与空 `CapabilityBoundingSet` 继续阻止它
取得宿主 capability，但被攻陷 Core 可直接尝试该 profile 允许的 userns/mount/network setup
syscall；AppArmor 不把这份 authority 限定到固定 runner argv。首次 non-bwrap Source exec 才 stack
`unpriv_bwrap`。接受 canonical digest 即同时接受这份扩大面；将来需要独立 typed spawn supervisor
才能把 setup authority 收窄到短生命周期。

`ops-agentd.service` 使用 typed ignore-missing `AppArmorProfile=-bwrap`。helper 的 root-owned
`NoNewPrivileges=yes` static-unit smoke 必须闭世界核对 exact FragmentPath/DropInPaths、唯一且无
flags 的 `ExecStart`、空 hooks/environment/groups/capabilities，以及完整 PID 1 effective
security/lifecycle vector；它还必须证明 effective profile、outer→fixed inner、最终
Source PID 1 label 包含 `unpriv_bwrap`、五组 capability 全零，并且后续 `unshare --user` 与 nested
bwrap 均失败。GitHub-hosted exact static unit 已证明 outer `--proc /proc` 在
`ProtectProc=invisible` 下返回 `EPERM`；outer 继承 service proc、inner 保留私有 proc 的修正形状
仍待 hosted gate 复验，完成前不能发布或宣称 production 支持。这条兼容只
覆盖直接 Node 的 `ops-agentd`/mandatory `workload.base`，且 host-policy helper 仍只支持 Noble。
BotMux guard 以实际状态而非发行版标签为准：任何 host 只要读到 restricted-userns=`1` 且
AppArmor=`Y/y`，都在 wrapper/config mutation、hardener 或 restart 前拒绝；Noble 上 restriction
evidence 缺失/不可读也拒绝，其他 host 只有该 sysctl 安全不存在时才可跳过。BotMux main→pi wrapper
若 attach 会先落入 `unpriv_bwrap`、阻断后续 sandbox setup；Adapter direct-Node probe 不能当作
BotMux production 证据。无法管理宿主 policy 的 LXC/OrbStack 没有降级路径。`join` 不承载 Source
runtime，永远不安装、更新或删除该宿主 policy。

交互式安装：

```bash
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
  | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- init
```

通过 `sudo` 时 `SUDO_USER` 是本地管理员；root 直接运行必须指定一个现有的非 root 用户：

```bash
sudo ops-agent-bootstrap init --admin-user alice
```

该管理员必须有可由真实 TTY/PAM 输入的本地密码，而且不能让 cloud-init、OrbStack image 或其他
sudoers 条目在最终匹配顺序中以 `NOPASSWD`（例如后加载的 `NOPASSWD: ALL`）覆盖两个固定 helper
的 `PASSWD` 规则。安装器会在
`sudo -k` 后以 `sudo -n` 做负向探针；只要任一匹配规则能免密运行就回滚。Disposable Ubuntu
E2E 应创建专用、带密码且无 broad sudo rule 的 `opsadmin`；生产机应先保留独立恢复入口再审查
既有 sudo policy，不能为了通过安装把审批 helper 改成免密。

安装器会：

- 创建 `ops-agent`、`ops-agent-server`、`ops-agent-reviewer`、`ops-agent-botmux`、
  `ops-agent-lease` system accounts/groups 和不对应登录账号的 `ops-agent-client` group；`ops-agent`
  与 BotMux 账号仅追加 client group，server/reviewer/lease 静态账号无 supplementary group，本地
  管理员仅追加 client/reviewer group；lease broker unit 只在运行时附加 client group 读取 registration；
- 生成本地 CA、server/agent/observer identity，以及 root:root `0600` 的 approver
  mTLS/Ed25519 identity；agent private key 仅 agentd UID 可读，observer private key 只供
  client group 发起 status-only HTTPS；
- 为本机 core/PVE broker 生成相互独立的 root-only receipt private key，并把对应公钥固定到
  `servers.json`；
- 将 server registry 实际引用的所有旧 approver identity 迁到
  `/etc/ops-agent/approver/root` 的 root-only 路径，原旧管理员目录也收权；
- 安装 `/etc/sudoers.d/zzzz-ops-agent-approval`，唯一允许固定 `agentd-approval-submit` binary，
  以及无参数的 `/usr/libexec/pi-ops-agent/setup-botmux`，均使用 `PASSWD` 与 command-specific
  `timestamp_timeout=0`，不授予通用 root command；完整 sudo policy 必须通过 `sudo -k` 后的
  non-interactive 负向探针，且 root 视角的 `sudo -U ops-agent-botmux -l` 必须证明专用账号没有
  任何 sudo rule，否则安装失败。sudo 1.9 在“无规则”时也可能返回 status 0，所以安装器不信退出码，
  只接受 C locale 下唯一一行 canonical `is not allowed to run sudo` 结果；warning、Defaults、command
  listing 或其他附加输出一律 fail closed；
- 安装 unit、tmpfiles、immutable release 目录和 `/opt/pi-ops-agent/current`；PVE broker unit、
  state/audit 目录与 socket 只在检测到 `/usr/bin/pvesh` 的 PVE host 启用；
- 初始化 root-owned Target policy 与本机 Machine registration；
- 复制、检查并请求批准 `adapter.tui`、`workload.base`；
- 在唯一、root-owned、位于 `/run/systemd/system` 且执行后精确清理的短生命周期 static unit 中，
  复制并核验与 `ops-agentd.service` 等价的 systemd hardening，再以 `ops-agent` 身份探测
  bubblewrap 的最小 `user/ipc/pid/net/mnt` namespace 集合、nested-userns deny、`PrivateDevices=yes`、
  `ProtectKernelTunables=yes`、`ProtectProc=invisible`、`ProcSubset=all` 与精确 kernel-tunable mount
  例外；任一边界不可用时必需的 `workload.base` 无法加载，因此 `init`
  fail closed 并回滚整轮安装事务；
- 通过 `/dev/tty` 读取模型 key 并生成 systemd encrypted credential；
- 启动服务并运行当前 healthcheck。

Release 还包含独立 `agentd-json-config-helper`。安装器会在停止 ingress、确认 broker store idle 后，
事务化快照并以 `root:root 0755` regular file 安装到固定
`/usr/lib/ops-agent/agentd-json-config-helper`，再逐字节对比 current release binary；不使用 PATH 或
Source Plugin 目录。失败会恢复原文件和目录 metadata。Controller 与 endpoint healthcheck 都检查
该 fixed copy 的 DAC 和版本一致性；卸载只删除这一精确文件，非空 `/usr/lib/ops-agent` 不会被递归
清理。

模型 credential 尚未准备好时使用 `--no-start`。它仍会安装文件和生成配置，但不会将“未启动”
称为成功运行。

安装器先记录 unit 状态并停 `agentd`/server ingress，再检查 core/PVE broker store。存在
`PREPARING`、`EXECUTING`、`VERIFYING` 或 `ROLLING_BACK` 会立即拒绝；broker 仍 active 时也会
恢复 ingress 并拒绝在线升级，管理员须在所有 change terminal 后先停 target 与两个 broker。
只有离线后才建立 root-only 内容快照，覆盖本轮会修改的 supplementary groups、
runtime/server/TLS/approver 配置、unit/drop-in、tmpfiles、`current`、CLI/libexec wrapper、Source
工作树、plugin registry、sudoers，以及原 unit 的 enabled/active 状态。Adapter state/secret、
broker state/backup/audit 从不做整树回卷。提交前失败会逆序恢复；回滚失败时保留 root-only
evidence。服务只在事务提交后启动，所以启动/health 失败会留下已提交但 inactive/degraded 的
版本供排障，不会用旧快照覆盖可能已经恢复的外部请求。

### 必需 Source Plugin

安装器会分别展示 `adapter.tui` 和 `workload.base` 的 manifest、digest 与 scopes；对 Adapter 还会
展示 runtime identity、execution、宿主 filesystem/network、runtime UID 可读 credential 和 direct
platform authority，明确 action scope 不是源码进程的 OS sandbox。随后要求输入：

```text
APPROVE adapter.tui sha256:<digest>
APPROVE workload.base sha256:<digest>
```

自动化环境必须在外部变更系统中完成同等审核，然后显式传 `--approve-required-plugins`：

```bash
sudo ops-agent-bootstrap init \
  --admin-user alice \
  --approve-required-plugins
```

这不是 Agent 自批，也不批准任何其他 Plugin。Source 被复制到
`/var/lib/ops-agent/plugin-sources`，运行时使用 `/var/lib/ops-agent/plugins` 内的不可变 snapshot。
安装器不会从该 registration 自动生成 root standing grant。管理员若另行允许通用
`file.write`/`service.action` standing，Target 必须用 `authorization.baseWorkloadDigest` 精确绑定
当前批准摘要；插件更新后需重新审阅并单独更新 policy，不匹配期间安全回落到逐次审批。

### 旧 artifact policy

`--enable-artifact` 只影响 legacy `.opspkg` catalog。例如迁移旧 Hermes/BotMux policy 或保留其
恢复证据时可以显式启用：

```bash
sudo ops-agent-bootstrap init \
  --admin-user alice \
  --enable-artifact adapter.botmux \
  --enable-artifact workload.hermes
```

参数只能使用 Release catalog 内的完整 identity/digest，且只允许 fresh policy。它不安装
Source Plugin，也不会让第一方 artifact 自动可信。已有 `targets.json` 时 installer 拒绝通过
此参数扩权，管理员必须单独审阅 policy 变化。`workload.hermes` 仍有受限 OCI 兼容 executor；
legacy `adapter.botmux` 只保留 artifact/change/rollback 证据，不能启动新版 Client，也不能满足
`/botmux-setup` 对 active Source `adapter.botmux` 的要求。

## `join`

在 controller 上模型外生成短期 enrollment bundle：

```bash
sudo /opt/pi-ops-agent/current/bin/ops-agent-server issue-enrollment \
  --controller https://controller.example:7443 \
  --endpoint https://endpoint.example:7443 \
  --machine-id machine-example-01 \
  --machine-name endpoint-example \
  --output /root/endpoint.opstoken
```

命令成功后还会输出 `controller-ca-sha256=sha256:<64 个小写十六进制字符>`。通过与
bundle 传输路径独立的已认证渠道（例如已核验的管理员 SSH 会话或现场控制台）把该指纹交给
endpoint 管理员；不能从 bundle 自身或同一未认证中转消息中提取并信任它。

目标是 PVE host 时必须额外传 `--pve`；普通 host 禁止传。Endpoint 安装会把 bundle 内容与
本机固定入口 `/usr/bin/pvesh` 做精确匹配，任一方向不一致都要求重新签发而不是本地补 key。

将 bundle 作为非 symlink、owner-only 普通文件传到 endpoint：

```bash
controller_ca_sha256='sha256:<从独立渠道核验的 64 位小写十六进制指纹>'
chmod 600 ./endpoint.opstoken
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
  | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- join \
      --controller https://controller.example:7443 \
      --controller-ca-sha256 "${controller_ca_sha256}" \
      --token-file ./endpoint.opstoken
```

上式只用于 fresh endpoint。首次 enrollment 会原子写入
`/etc/ops-agent/endpoint-enrollment.json`，把 controller origin、endpoint origin、外部核验的 CA
指纹、server/machine identity 和 PVE 模式记录为 root-owned trust binding；它不冻结后续可审计修改
的 `targets.json` 内容。

已有完整 endpoint 升级 Release 时仍使用 `join`，但必须省略 `--token-file`：

```bash
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
  | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- join \
      --controller https://controller.example:7443 \
      --controller-ca-sha256 "${controller_ca_sha256}" \
      --no-start
```

新 Release 中的 `ops-agent-server validate-enrollment` 会只读验证 metadata/controller/CA pin、
server identity、当前 target policy schema、CA/client-CA、server certificate/private key、approval
public key、文件 DAC，以及 core/PVE domain-separated receipt keypair；全部通过后才复用 enrollment。
任何已有 endpoint surface 与新 `--token-file` 同时出现都会拒绝，缺文件、未知字段、证书或 key
不匹配、权限变宽、PVE 模式变化也会在 config 阶段触发整轮安装事务回滚。升级不会用新 bundle
静默覆盖 identity、policy、TLS 或 receipt key；确需重新 enrollment 时必须先显式退役旧 endpoint、
轮换 controller registration，并按 fresh join 重新签发。

Enrollment bundle v2 绑定 controller origin、endpoint identity、证书、初始 fail-closed policy、core receipt
key，以及可选的 PVE receipt key 和期限。Controller 只保存每个 remote server 的公钥到
`broker-receipts/remotes/<serverId>/` 并写入 registration；私钥仅存在于短期 bundle 和 endpoint。
Endpoint 在采用 bundle 内 CA 验证签名之前，必须先让该 CA 证书的 SHA-256 指纹与显式传入的
外部 pin 精确匹配；缺失、非规范或不匹配均 fail closed。Controller URL 不是信任锚。
当前没有在线
消费记录，因此有效期内复制件可重放，不能称作真正的一次性 token。成功后立即删除 controller、
中转机和 endpoint 上所有副本；失败或疑似泄漏时禁用 pending registration、等待过期并轮换
相关 identity 后重新签发。

`join` 只创建 `ops-agent-server` identity、server/core broker unit 与最小 tmpfiles；PVE 精确匹配时
再增加 PVE broker。它不创建 agentd/reviewer/BotMux/client group、模型/guardian 配置、插件目录、
审批 sudoers、`ops-agent` CLI symlink、controller health timer 或 `ops-agent.target.wants`。旧版
PVE endpoint 遗留的唯一精确 PVE target symlink 会在升级事务中清理；其他 target-wants 内容一律
视为 controller surface 并拒绝覆盖。检查使用
`scripts/healthcheck.sh --endpoint`。若发现这些 controller-only surface，join 拒绝覆盖。

远端 server 模式的 root broker（带 `--target-policy`）还必须同时配置
`--approval-key-id`、`--approval-public-key` 和 domain-specific receipt signing key；缺任一项时
broker 在启动阶段拒绝运行，不会进入可接收远端 change action 的状态。

启用 Hermes/BotMux fixed command profiles 前，管理员必须把对应 CLI 安装到 root-owned、
group/world 不可写的稳定绝对路径，并确认路径上每一级目录满足同一属性；业务账号自己的
`~/.local/bin`、npm/pnpm bin、checkout 或 symlink 链不能使用。Target policy 的每个
`commandWorkloads` 项必须绑定 exact plugin ID/digest、Target account、non-root run-as account/home、
semantic profileKey、完整 executable/argv、1–120 秒 timeout 与 1–65536 byte output bound。
无需也不得把 core broker unit 的 `ProtectHome=yes` 改成 read-only：broker 通过 system manager
创建独立 `ProtectHome=read-only`、`ProtectSystem=strict`、`PrivateNetwork=yes` transient service。
安装/升级后用 agent role 的专用 `/v1/workload-command-inspections` route 做 smoke test，并验证
返回 core receipt；不要用旧 `/v1/inspect` 或临时放开 raw argv。

启用 BotMux config edit 时，另行审核
[`jsonConfigWorkloads` 示例](../plugins/workload-botmux-ops/target-policy.example.json)并替换实际
plugin digest、numeric UID、home、selectors 与 absolute path roots。同一物理 config 只允许一个
profile。先用一个无副作用值变化演练 prepare/reject，再演练批准、verify 与 rollback；确认计划显示
config digest/identity、before/after、whole-document rewrite 和 post-verification pathname replacement
residual，且远端 Adapter、
standing policy 与旧 digest 都不能批准。不要把 service restart 合并进这次配置审批。

## 账号与网络

目标进程身份：

```text
ops-agent             agentd + same-UID guardian + local session gateway
ops-agent-reviewer    approval reviewer only
ops-agent-lease       exact-digest Source Plugin lease broker only
ops-agent-server      HTTPS server only
root                  core/PVE agentd-root-broker only
root (short-lived)    agentd-approval-submit after interactive PASSWD sudo
```

`ops-agent-server` 不属于 `ops-agent` 或 `ops-agent-client` supplementary group；升级安装会删除
历史 membership。本地管理员和 BotMux 也会从 `ops-agent` service group 移除，只保留明确需要的
`ops-agent-client`（管理员另有 reviewer group）。`ops-agent-lease` 静态账号不加入 client group；
systemd unit 的 runtime-only `SupplementaryGroups=ops-agent-client` 只用于读取 immutable registration，
请求授权仍取决于 socket peer UID。
当前关键权限按文件/Socket 分开，而不是靠共享大组：

| 对象 | owner/group/mode | 可用 principal |
|---|---|---|
| `/run/ops-agent/helper` | `root:root 0755` | 仅作为中性路径；权限落在具体 socket |
| `root-helper.sock` | `root:ops-agent-server 0660` | server 与 root |
| `/run/ops-agent/agentd` | `ops-agent:ops-agent-client 2750` | agentd owner 可创建；client 只能 traverse/read，不能替换目录项 |
| `agentd.sock` | `ops-agent:ops-agent-client 0660` | local session gateway 的公开入口；group 只允许连接，实际身份取 `SO_PEERCRED` + exact Adapter digest |
| `backend.sock` | `ops-agent:ops-agent-client 0600` | 仅同 UID 的 agentd 与 local session gateway；client group 没有读写位 |
| `/var/lib/ops-agent/plugin-sources` | `ADMIN_USER:primary-group 0750`（init） | 管理员可编辑不可信源码；client group 不读取，root broker 注册前重算摘要 |
| `/var/lib/ops-agent/plugins` | `root:ops-agent-client 2750` | root 写；agentd/TUI/BotMux 只读获批 CAS |
| `/run/ops-agent/plugin-lease` | `ops-agent-lease:ops-agent-client 2750` | client principal 只能连接固定 socket，不能据此获得任意 plugin lease |
| `plugin-lease/lease.sock` | `ops-agent-lease:ops-agent-client 0660` | lease broker 用 `SO_PEERCRED` 对 runtime UID 与 plugin class 再授权 |
| `/var/lib/ops-agent/plugins/invocation-leases` | `root:ops-agent-lease 0750` | 仅 root registry mutation 与 lease broker 可 traverse；client 不可读 |
| `invocation-leases/<pluginId>.lock` | `root:ops-agent-lease 0640` | broker shared `flock`；root registry exclusive `flock` |
| `ca.crt`、`agent.crt` | `root:ops-agent-client 0640` | client principals 可读取公有证书 |
| `agent.key` | `ops-agent:ops-agent 0600` | 仅 agentd service UID；管理员与 Adapter 不可读 |
| `observer.crt`、`observer.key` | `root:ops-agent-client 0640` | client principals；server 强制 observer 仅 status |
| `servers.json` | `root:ops-agent-client 0640` | agentd/TUI/Adapter 读取 endpoint 与 observer 路径 |
| 本机 receipt private key | `root:root 0600` | 对应 core/PVE broker only |
| controller remote receipt 公钥 | `root:ops-agent-client 0640` | Client/submitter 验证指定 server 的 broker response |
| endpoint receipt 公钥 | `root:ops-agent-server 0640` | endpoint 留存的公开配对证据；不创建 client group |
| `endpoint-enrollment.json` | `root:ops-agent-server 0640` | endpoint 升级时只读核验 controller/CA/identity/PVE 绑定 |
| `client-ca.crt`、`server.crt`、`server.key` | `root:ops-agent-server 0640` | server，不给 agent/admin |
| `/etc/ops-agent/approver/root/*` | `root:root 0600` | approval submitter only |

创建 `invocation-leases` 时，Linux 会从其 `2750` registry parent 暂时继承 setgid。Installer 必须在
校验前用显式 special-bit-zero numeric mode（`00750`，而不是会保留目录 setgid 的 `0750`）清除
该位，并证明最终值精确为 `root:ops-agent-lease 0750`；不能接受继承得到的 `2750`，否则会把
client-readable registry 的目录语义误带入 broker-only lock boundary。

`/etc/ops-agent` 与 `tls/` 本身是 root:root `0755` 中性目录；看到文件名不代表能读取 credential。
不得把 client principals 加回 `ops-agent` service group、让 observer role 准备/提交变更，或给
server 补任何 client/service supplementary membership。

`agentd-server` 默认监听 `0.0.0.0:7443`，必须由网络 ACL 限制到 controller；TLS 仍要求客户端
证书。Root broker 只监听 `/run/ops-agent/helper/root-helper.sock`，PrivateNetwork，且 socket group
只给专用 server 账号；安装器会移除管理员遗留的 server-group membership。Plugin lease broker
也只有本地 AF_UNIX socket、PrivateNetwork 和空 capability set；该 socket 不是 root broker API。
禁止把任一 socket 转发到 TCP、SSH remote forward 或容器 mount。

普通管理员、Agent 与 Adapter 都不得读取 approver 私钥。TUI 第二次确认后只能以固定六组
flag/value argv（action、server、machine、Target、change 与 bounded user intent）调用
root-owned submitter；其 parser 不接受 URL、credential path 或 noninteractive
flag。Submitter 重新展示 ASCII-only canonical plan、要求本地密码，并要求精确输入
对应的 `APPROVE|REJECT|ROLLBACK SERVER_ID MACHINE_ID TARGET_ID CHANGE_ID PLAN_HASH`。不能把
sudoers 改成 `NOPASSWD`、恢复可复用 timestamp，或给该用户通用 helper/socket 权限，否则
会破坏审批边界。

每个 root Target 默认可以准备 per-change manual root capsule；这只是可准备性，不是持久授权。
旧 `--allow-breakglass` flag 仅为 CLI 兼容 no-op，不再是安全开关，也不需要 `full-root` policy。
Capsule 永不 standing，只能由本地 TUI 的独立 reviewer、PASSWD sudo submitter 和真实 `/dev/tty`
精确确认逐次批准；外部 Adapter、非 root Target 和 PVE broker 都不能使用。`backupPaths` 可显式为空，
`verifyScript` 可省略；它只是 caller-provided privileged postcondition，不是独立 verifier。
Reviewer 对所有 capsule 固定 critical，并把缺少恢复/postcondition 证据展示给用户。`network=false`
只启用 best-effort `PrivateNetwork`，不是 full-root script 无法逃逸的断网保证。完整恢复语义见
[运维手册](operations.md#manual-root-capsule-与恢复)。

Join 到 PVE 时，server/broker 直接安装在 PVE host；controller 不持有 PVE root token，也不
通过 SSH 调通用 root shell。Target policy 先 pin 所选 PVE source workload 的 exact ID/digest、node、storage、guest、
operation 与 migration target。具体部署前置和 smoke 见[PVE Workload](workloads/pve.md)。

v0.3 的 `pve/vmid/<vmid>` 虽使用 cluster-global 资源 key 形状，durable lock 仍是 broker-local，
且尚无 cluster fingerprint enforcement。每个 PVE cluster 必须只部署一个可接受 mutation 的
endpoint；其他节点把写操作路由到它，或只提供只读 endpoint。不要在同一 cluster 的多个节点
分别启用 mutation broker，也不要把该锁描述为分布式锁。

## bubblewrap 与 PVE LXC

`ops_bash` 和所有 Source Workload host 都要求 non-privileged user namespace。`workload.base` 是
`init` 的必需插件，因此若 LXC 禁止该能力，安装器必须 fail closed 并回滚整轮事务；不得只关闭
`ops_bash` 后启动一个无法加载必需 Workload 的 agentd。也不得关闭 systemd hardening、改为 sudo
shell、进程内 loader，或给容器额外 host 权限作为降级路径。

Debian merged-/usr 上 `/bin`、`/sbin`、`/lib*` 可能是 symlink。部署 smoke 必须同时覆盖 merged
和非 merged layout，保证 bubblewrap 的只读 bind 不把 symlink target 遮蔽或制造不存在路径。
安装器的 preflight 在唯一、root-owned、位于 `/run/systemd/system` 的短生命周期 static unit 中
复制最终 security drop-in、核验 PID 1 的 effective 配置，并运行真实双层 bwrap；结束后必须精确清理
unit、drop-in、driver 与 nonce。outer 仍创建 PID namespace 并保留默认 PID 1 reaper，只启动固定
inner bwrap；它不使用 `--proc` 重挂 procfs，而继承该 static unit 已受 `ProtectProc=invisible`
保护的 service proc 视图。inner 才使用 `--proc /proc` 建立私有 procfs、以 `/bin/sh` 为 PID 1 并
禁止继续嵌套 userns；最终 Source 只会看到 inner 视图。省略 outer proc remount 不会删除 outer
PID namespace/reaper，也不能缩短 runtime completion barrier；runtime 另以 outer
PID 1 独占的 `--sync-fd` EOF 和 bounded `--info-fd` 绑定的 exact init identity 消失作为完整
进程树 completion barrier。preflight 能捕获
`RestrictNamespaces`、`ProtectHostname`、`ProtectKernelTunables`、nested userns 或 bwrap 参数漂移；它仍不替代
对真实 Source Workload/provider/lease 的部署验证。
若真实 probe 进入失败终态，安装器会在删除临时 unit 前输出有界 journal 和
`kernel.apparmor_restrict_unprivileged_userns` 状态；应以其中的实际 bwrap errno/AppArmor 拒绝为准，
不能把通用的“user namespace 不可用”摘要当作根因，也不能通过关闭 host-wide 限制制造通过。
尤其不能把普通 shell 下成功的 direct bwrap smoke 当作这个 unit-bound proof。GitHub-hosted Noble
exact NNP static unit 已证明 outer 的 `--proc /proc` 在 `ProtectProc=invisible` 下返回 `EPERM`；
上述仅移除 outer proc remount、保留 outer PID containment 与 inner 私有 procfs 的形状仍待 hosted
复验，当前不能称为成功。Noble helper 必须
先在自己的 root-owned `NoNewPrivileges=yes` static unit 中核对 typed `AppArmorProfile=-bwrap`
effective attachment，再证明最终 `unpriv_bwrap`/zero-cap/nested-userns deny；installer 随后仍运行
自己的完整 preflight。该证据边界只覆盖直接 Node 的 `ops-agentd`/base Workload，不覆盖未 attach
的真实 BotMux main→pi wrapper chain。

## 安装其他 Source Plugin

当前标准流程通过 broker 的 typed `plugin.register` change：

1. 将可编辑源码放到 `/var/lib/ops-agent/plugin-sources/<name>`；
2. 用 `agentd-pluginctl inspect` 获取真实 digest；
3. Agent 使用检查结果中的 ID、kind、version、publisher、digest、完整 capabilities 和完整排序
   requestedScopes prepare `plugin.register`，不能省略或自行改写任一字段；broker 对 Adapter 另行
   派生 runtime UID/filesystem/network/credential/direct-call authority 并绑定到 canonical plan；
4. 用户在 TUI 审核 broker 的权威 plan；第一次只 review，第二次进入 submitter 的
   PASSWD + exact TTY confirmation；
5. broker 重新 hash、snapshot、原子激活并验证，随后重启/重连相关 runtime；
6. 确认 active registration 与获批 digest 一致，失败时核对 rollback/recovery evidence。

激活还必须通过 `/var/lib/ops-agent/plugins/invocation-leases/<pluginId>.lock` 的 exclusive
`flock` 与在途 Workload 串行化。该目录是 `root:ops-agent-lease 0750`，lock 是 `0640`；agentd、
Client 与 Adapter 都不能打开它。Runtime 只能以真实 UID 连接固定
`/run/ops-agent/plugin-lease/lease.sock`，由 peer-authenticated `agentd-plugin-lease-broker` 为 exact
active digest 持 shared lease。Release 升级会以 registry owner 身份为旧 registration 补齐 lock。
若仍有旧 digest invocation，注册会在切换 `current` 前 fail closed 并保留旧版本，调用结束后需重试，
不得通过停止隔离、手改 symlink、放宽目录 DAC 或删除 lock file 强行更新。

命令和安全限制见[Source Plugin](plugins.md)。`agentd-pluginctl register` 仅用于必需 Plugin
bootstrap 或离线恢复；常规安装/更新不能绕过 change audit。每次更新都要重新批准，不能只根据
plugin ID 覆盖 `current`。

`adapter.tui` 是固定启动特例：`/usr/local/bin/ops-agent` 只进入固定 Adapter runner；runner 每次
重验其 active runtime digest、精确 capability/scope/descriptor 与 CAS 路径，并在启动前复查
current 未漂移，再通过固定 lease broker socket 为 exact digest 持有 shared lease 直到子进程退出。TUI
snapshot 只能包含不可执行 `manifest.json`/`profile.json`；runner 解析固定 local-TTY profile 后
以当前非 root 本地用户在宿主 TTY 直接启动 release compiled Client，而不执行 snapshot；Client
自己通过同一 broker 持有 exact digest lease 到退出，保留 host sudo/PAM 且不依赖 runner 单点存活。可执行
Source Adapter 才进入保留网络/宿主用户权限的双层 bubblewrap PID namespace：inner 让 Source 成为
PID 1 并禁用后续 userns，outer 默认 reaper 通过 lifecycle FD + exact init identity 证明全部后代已消失。旧
Adapter/TUI 仍在
运行时，更新的 exclusive lease 必须在激活前失败而不是撤销其审批边界。
唯一的 TUI 自更新例外不绕过该锁：一个单步 canonical `adapter.tui plugin.register` 经过同一本地
TUI 第二次确认后，Client 先关闭 agent session、释放自己的 lease，再经固定 runner control FD
要求外层 runner 释放 lease 并等待 ACK；只有两份都释放后才启动 submitter。旧 TUI 随后退出，用户
从新 digest 重新启动。另一 TUI 或任何 runtime 仍持 shared lease 时，exclusive register 仍会在
切换 `current` 前失败；多步计划和 Source Adapter 不得触发这条 handoff。
正式 Source runtime 不再自行启动 Client：runner 启动 Source/compiled Client sibling，以 FD 4
转发 strict typed bind/text、FD 3 返回 completion，并只向 Client 的 FD 5 写入已捕获 descriptor、
plugin ID 与 active digest。Client 必须在读取任何 Source input 前重验该 context、active
registration 与 exact digest lease；外部 initial prompt 与后续消息都必须从 Source 的 bounded
bracketed-paste stdin 进入，runner/Source/Client 均不得把 positional argv 或 `@file` 变成模型输入。
该 Client 能看到本地终端和该 UID 的数据；bootstrap/更新批准的是精确 profile 与本地审批 scope，
不能因此允许 TUI 插件夹带源码。

## BotMux Source Adapter

BotMux setup 先读取 host evidence，而不是仅按 Ubuntu Noble 标签判断。任何发行版只要实际读取到
restricted-userns=`1` 且 AppArmor=`Y/y`，wrapper 就必须在 config mutation、digest-approved hardener
或 restart 前拒绝；Noble 缺少或无法读取 restriction evidence 也拒绝，其他 host 只有该 sysctl 安全
不存在时才可继续。managed BotMux 的 `NoNewPrivileges=yes` main→pi wrapper 链不能安全取得后续
bwrap setup profile；不要复制 `ops-agentd` 的 `AppArmorProfile=-bwrap`，否则 wrapper 会过早落入
`unpriv_bwrap`。Noble helper 仍只解锁 direct Node core/base；direct Adapter CI probe 不能作为
BotMux production 证据。runtime 也必须保持 fail closed，等待单独经过真实 main→wrapper→sandbox
链验证的 profile 设计。

BotMux 本体是外部依赖，`init` 不安装。先审批并注册 Source `adapter.botmux`，再在本地 TUI
输入精确 `/botmux-setup`。Client 只执行固定 argv
`sudo -k -- /usr/libexec/pi-ops-agent/setup-botmux`；sudo/PAM 要求管理员密码，root-owned wrapper
不接受参数，并以 `ops-agent-botmux` UID 启动固定 setup runner。Runner 通过固定 lease broker
socket 为 `adapter.botmux` exact digest 持有 shared lease，完整覆盖 BotMux 官方 `setup`、获批
snapshot 中的 hardener 和 `restart`；hardener 是 inner bubblewrap PID namespace 的 PID 1，outer
默认 reaper 的 lifecycle FD + init identity barrier 必须等 detached 后代完全消失，不能让它们越过 lease。Lease 丢失会终止当前命令并禁止后续步骤，并发更新只能在
`current` 切换前失败。Wrapper 使用 `agentd-pluginctl current --runtime` 重新验证 registration、
snapshot digest 与 entrypoint，绝不执行可编辑 `plugin-sources`。current 不存在或任一 Source
校验失败时都直接中止并要求管理员审阅、注册 Source 插件；legacy `.opspkg` 只保留为恢复证据，
不会被 setup wrapper 执行。BotMux UID 本身没有 sudo。

部署必须额外检查：

- `node-pty` native addon 实际可加载；使用 `npm --ignore-scripts` 后要显式 build/verify；
- shell 是 `/bin/bash`；PATH 以 `/opt/pi-ops-agent/botmux-bin` 开头；
- 该目录中存在名为 `pi` 的 wrapper，BotMux resume 不只依赖 `cliPathOverride`；
- `bots.json` 与备份均为 `0600`，只有一个 owner，无群聊/grants/listeners；
- home 为 `/var/lib/ops-agent/adapters/botmux`、`0700 ops-agent-botmux:ops-agent-botmux`，其唯一
  supplementary group 是 `ops-agent-client`；
- 外部 Adapter 的 approve/reject/rollback 被 Client 拒绝，且普通 UID 不持有 approver key 或
  broker socket；审批回到 TUI 的 PASSWD + 精确 TTY 确认。

更多 envelope/sender/completion 规则见[Adapter 文档](adapters.md)。

## 部署验收

当前 init host 的显式状态检查：

```bash
systemctl status \
  ops-agent.target \
  ops-agentd.service \
  agentd-guardian.service \
  agentd-approval-reviewer.service \
  ops-agent-server.service \
  ops-root-helper.service \
  --no-pager

sudo /opt/pi-ops-agent/current/scripts/healthcheck.sh
```

Controller healthcheck 会检查 guardian/reviewer unit 与 socket、guardian heartbeat freshness 和必要
Source Plugin registration；显式 `systemctl status` 仍用于补充查看 unit 失败原因。至少人工验证：

1. `current` 指向预期 immutable release，config/state 不在版本目录；
2. 每个 daemon 使用预期 UID，只有 core/PVE broker 是 root；submitter 只在审批时短暂存在；
3. reviewer 看不到 config、state、broker socket 或网络；
4. approver files 为 `/etc/ops-agent/approver/root` 下 root:root `0600`，registry 不再引用旧
   admin path；sudoers 为 root:root `0440`、完整 policy 通过 `visudo -cf`，且两个固定 helper
   在 `sudo -k` 后的 `sudo -n` 都因需要密码而失败；管理员和 server 没有遗留越权 group；
5. TUI/base registration digest 与用户批准一致；
6. agent role 不能批准，外部 Adapter/管理员 UID 都不能读取 approver key 或连接 broker；
7. 第一次 `/approve` 只返回 `REVIEW_REQUIRED`；第二次同计划仍必须通过 PASSWD sudo，并在
   submitter 展示 canonical plan 后输入完整 action/server/machine/Target/change/planHash；
8. agentd disconnect 后 CLI 退出，新的 PTY/Client 可重新连接；
9. 无 user namespace 时 `init` fail closed 并回滚，不留下无法加载 `workload.base` 的半可用 controller；
10. 重复 request/status 不重放 mutation，只有通过 pinned receipt 验证的 broker `COMMITTED` 才算成功；
11. join host 未运行第二份 agentd/model/session controller，不存在 `ops-agent.target.wants`，且
    `--endpoint` healthcheck 不要求 controller unit、socket、credential 或 plugin surface；
12. PID 1 已对当前 mode 的完整 managed service 集合加载 exact release unit 与 unit-specific final
    security drop-in，并通过 lifecycle/security effective-vector 核验；`init` 与 `join` 的集合不能
    取并集，非 PVE host 不应残留 managed PVE unit/drop-in。
13. 若 Noble restricted-userns 开启，helper 的 exact managed state、typed ops-agentd profile、
    `NoNewPrivileges=yes` authority smoke 与 installer preflight 必须全部通过；direct smoke 不能
    替代它。BotMux 则按实际 evidence 判断：任何 host 的 restricted-userns=`1` + AppArmor enabled
    都必须在 setup mutation 前报告 unsupported/fail closed；Noble evidence 缺失也拒绝。`join` 不应
    出现任何项目管理的 AppArmor profile/local rule surface。

使用仓库 Skill 执行这套流程：[`agentd-init`](../skills/agentd-init/SKILL.md)。
