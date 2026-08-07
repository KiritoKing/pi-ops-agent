# 原生部署与接入

Pi Ops Agent 只支持以 systemd 为 PID 1 的 Linux。Ops Agent 自身不提供 Compose 或非
systemd 部署；PVE LXC 直接使用原生安装。摘要绑定的 `managed-workload` 插件可以通过固定
OCI 安全模板部署，但这不形成通用容器管理接口。

目标机不需要 Git、Go、Node.js 或 npm，也不会运行源码构建和 npm lifecycle。
GitHub Release 已包含编译后的 TypeScript、production dependencies、固定 Node runtime
和当前架构的静态 Go 命令。

## 第一台机器：`init`

GitHub Raw 上的脚本只是下载和校验 bootstrap。真正的主机修改由 Release 包内、
与版本绑定的 `install-release.sh` 完成：

```bash
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/main/scripts/install.sh \
  | sudo sh -s -- init
```

这个默认命令创建 core-only policy：不会授权任何业务 artifact、Docker package/unit 或
文件读取路径。需要扩展时，fresh init 由管理员在模型外按 catalog ID 精确选择，可重复传入：

```bash
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/main/scripts/install.sh \
  | sudo sh -s -- init \
      --enable-artifact adapter.botmux \
      --enable-artifact workload.hermes
```

ID 必须在该 Release 的受信 catalog 中唯一存在；版本、publisher、digest 取自 catalog，
不能通过参数替换。只有显式选中的 `managed-workload` 才会带来 Docker 前置权限。已有
`targets.json` 时安装器拒绝该参数，避免把升级伪装成授权操作；管理员须独立审阅并修改现有
root-owned policy。

通过 `sudo` 运行时，`SUDO_USER` 成为首个本地管理员；root 直接执行时必须显式指定：

```bash
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/main/scripts/install.sh \
  | sudo sh -s -- init --admin-user alice
```

安装器通过 `/dev/tty` 无回显读取模型 credential，生成 systemd encrypted
credential，启动服务并运行健康检查。需要先落盘、稍后再配置 credential 时可使用
`--no-start`。

`init` 的边界是：

- 安装中央 `agentd`、同机 `agentd-guard`、本机 `agentd-server`、
  `agentd-root-broker`、健康托管和 TUI；
- 创建 `ops-agent` 非特权账户、运行目录、配置和 systemd unit；
- 初始化空的机器与 Session 注册表；
- 安装并启动核心服务，执行只读冒烟；
- 默认仅授权主机快照、进程和核心 unit/journal；文件 `readPaths` 与业务 artifact 为空；
- **不安装、不初始化、不配置 BotMux 或任何外部 Adapter**；
- **不读取 Lark/BotMux credential，也不创建 BotMux 服务账户**。

后续 `join` 机器只部署 `agentd-server + agentd-root-broker`，不会再运行一份模型、
Session 或 `agentd-guard`。规范组件名与当前 unit/binary 兼容映射见
[架构文档](architecture.md#artifact-兼容映射)。

完成后重新登录，使 `ops-agent` supplementary group 生效，然后进入保底入口：

```bash
ops-agent tui
```

## Release 选择与完整性

默认安装 GitHub `latest` Release。生产安装应同时把 Raw 脚本和 Release 固定到同一 Tag：

```bash
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/v0.2.0/scripts/install.sh \
  | sudo OPS_AGENT_VERSION=v0.2.0 sh -s -- init
```

Bootstrap 只接受 HTTPS，下载 `checksums.txt` 和与本机架构对应的 archive，并在解包
前校验 SHA-256。Release workflow 还为 `.tar.gz`、`.deb`、`.opspkg`、SBOM 和
manifest 生成 GitHub artifact attestation。

如果目标机安装了 GitHub CLI，bootstrap 会额外执行：

```bash
gh attestation verify <archive> --repo KiritoKing/pi-ops-agent
```

没有 `gh` 时安装器会明确提示：此时验证边界只有 GitHub HTTPS 加同一 Release 中的
checksum，不能声称已经验证了独立签名。高价值主机可先在管理机执行 attestation
验证，再把已验证 archive 放入受控镜像，并通过 `OPS_AGENT_RELEASE_BASE` 指向镜像。

Release 包含：

```text
ops-agent-linux-amd64.tar.gz
ops-agent-linux-arm64.tar.gz
ops-agent-all_<version>_amd64.deb
ops-agent-all_<version>_arm64.deb
ops-agent-linux-amd64.spdx.json
ops-agent-linux-arm64.spdx.json
adapter-botmux_<version>.opspkg
workload-hermes_<version>.opspkg
manifest.json
checksums.txt
```

`.deb` 只安装已验证的 Release payload，不自动初始化服务。手工安装后执行：

```bash
sudo dpkg -i ops-agent-all_0.2.0_amd64.deb
sudo ops-agent-bootstrap init --admin-user "$USER"
```

## 后续机器：`join`

管理员在 `agentd` controller 上运行 `ops-agent endpoint-token`（或当前 artifact
`ops-agent-server issue-enrollment`），在模型外生成一个短期签名 enrollment bundle。
Bundle 内只包含指定 controller origin、endpoint 身份、证书和初始 policy；把它保存为
仅 owner 可读的文件后，在新机器执行：

```bash
chmod 600 ./ops-agent-enrollment.opstoken
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/main/scripts/install.sh \
  | sudo sh -s -- join \
      --controller https://controller.example:7443 \
      --token-file ./ops-agent-enrollment.opstoken
```

Bundle 内容不接受裸 argv 或环境变量。安装器只接受普通、非符号链接且无 group/world 权限
的文件，复制到 root-only 临时文件后调用：

```text
ops-agent-server enroll --controller <url> --token-file <root-only-file>
```

只有签名、期限、controller origin、证书、identity/policy 落盘和只读 smoke 全部成功，
才启用 `agentd-server`（当前 unit 为 `ops-agent-server.service`）。它是离线 bearer bundle：MVP 没有在线“消费一次”状态，所以在
有效期内复制件仍可重放。成功后必须立即安全删除 controller 和 endpoint 上的 bundle；
怀疑泄露时等待其过期并轮换对应 endpoint credential。Issuer 会在发放时先写 controller
注册表，endpoint 安装失败时管理员必须禁用或删除该待接入记录。

## PVE LXC 与 bubblewrap

安装器始终要求 systemd。`ops_bash` 还要求非特权 user namespace 和 bubblewrap：

```bash
bwrap --unshare-all --die-with-parent \
  --ro-bind /usr /usr --ro-bind /bin /bin \
  --proc /proc --dev /dev /bin/true
```

如果 LXC 禁止 user namespace，不得关闭 sandbox 或扩大 systemd 权限。核心、TUI、
注册表和远端类型化工具仍可运行，但 Harness 不注册 `ops_bash`；健康检查应把这一状态
报告为受限能力而不是静默降级。

## 通过 Agent 部署 managed-workload

仅当 fresh init 显式传入 `--enable-artifact ID` 时，安装器才把该 Release artifact 的完整
identity/digest 写入本机 Target policy；它仍不会解包插件、安装 Docker、下载业务镜像或
创建业务 credential。模型先查询该 Target 已授权的 artifact catalog，
准备 `plugin.install` 并等待模型外审批。安装后的业务专用 `prepare-credentials.mjs` 只在
管理员上下文中读取显式 FD，输出通用 bundle；root 侧统一脚本再校验 manifest slot、绑定
bundle digest 与 policy revision，并重启读取 policy 的 endpoint 服务：

```text
prepare-credentials.mjs --input-fd N
  -> configure-plugin-credentials.sh --plugin-id workload.NAME \
       --target-id target-local-system --credential-fd N
```

随后模型只能准备绑定同一 artifact 的 `workload.deploy`，仍须独立审批。broker 从插件声明
生成固定安全模板，不接受模型提供镜像、端口、mount、宿主路径或 Docker argv。只有全部
声明式进程身份检查和容器内 digest-bound checks 通过且 broker 返回 `COMMITTED` 才算成功。
需要容器内 root 初始化的镜像还必须精确声明允许的 supervisor 进程及非 root 稳态进程；
这是通用插件契约，不是业务镜像特例。Hermes 的具体输入、
WebUI/TUI/CLI 与重启验收见[第一方 Hermes 工作负载指南](workloads/hermes.md)。

上述显式授权只适用于首次生成 policy。升级已有安装时，安装器只把 v0.1 的字符串插件项
收窄成 catalog 中同 ID 的完整 identity；不会改写管理员的读取范围，也不会因为新 Release
增加了 artifact、managed workload、`docker.io` 或 `docker.service` 就扩大已有 allowlist。
文件 metadata 可以在授权目录下查询，但 `file.read` 必须精确列出目标文件且 Linux broker
通过 `openat2` 禁止 symlink/magic-link 和目录逃逸。新增授权必须由管理员显式修改并复核 policy。

## 通过 Agent 安装 Adapter

TUI 不实现独立的“插件管理业务页面”。用户直接与 Agent 对话：

```text
帮我安装 BotMux adapter
```

Agent 通过固定插件工具完成 catalog 查询、manifest/兼容性检查、安装计划准备和状态
查询，并向用户解释 publisher、版本、digest 和 root 文件变更。插件包不包含 BotMux
本体，也不会让 `agentd-root-broker` 执行 npm 或联网脚本；先按
[BotMux 官方安装说明](https://deepcoldy.github.io/botmux/)为当前管理员安装 `botmux`。
该 Target 还必须已在 fresh init 中通过 `--enable-artifact adapter.botmux` 获得授权，或由
管理员在现有 root-owned policy 中独立加入并复核精确 artifact identity。

Adapter 文件安装是一项高权限 change：Agent 只能 prepare，真实管理员必须在 TUI 中
执行 `/approve <changeRef>`。`agentd-root-broker` 只验证、解包固定 digest，并原子维护插件
`current` 与固定 launcher；不会执行 manifest 中的 installer、callback 或任意命令。

提交成功后，在交互式 TUI 输入 `/botmux-setup`。这个精确 client 命令不发送给模型；它
临时退出 raw input，依次运行固定 argv 的 `botmux setup`、插件 hardener 和
`botmux restart`。Hardener 要求首个 bot 恰好一个 `allowedUsers`、禁止群聊，设置
`cliId=pi`、固定 `cliPathOverride`、`p2pOpen=false`、`disableCliBypass=true` 和
`sandbox=false`。最后一个设置不是关闭 ops-agent sandbox，而是避免 BotMux 再包一层
未知文件沙箱；真正的 Harness 仍由 systemd + bubblewrap 隔离。

Lark App Secret 由 BotMux 官方交互直接读取，ops-agent 不读取、不代理也不记录。按
BotMux 当前设计，它以明文保存在当前管理员的 `~/.botmux/bots.json`；hardener 把文件和
带时间戳备份都设为 `0600`，输出只含非秘密摘要。该边界不同于 systemd encrypted
credential，部署者必须接受并保护该账户。

插件不能携带 root shell installer。ops-agent 的 BotMux Adapter 是独立
`adapter-botmux_<version>.opspkg`，不在 `init` 中解包、配置或启用。其他 IM Adapter
复用相同的 Agent 驱动流程。

## 部署验收

```bash
systemctl status \
  ops-agent.target \
  ops-agentd.service \
  ops-systemd-helper.service \
  ops-agent-server.service \
  ops-root-helper.service \
  --no-pager
sudo /opt/pi-ops-agent/current/scripts/healthcheck.sh
ops-agent tui
```

以上是当前真实 unit 名称：依次对应规范的 `agentd`、兼容
`agentd-guard`、`agentd-server` 和 `agentd-root-broker`。不要在代码完成迁移前把命令
机械改成尚不存在的 unit。

至少验证：

1. `/opt/pi-ops-agent/current` 指向期望版本，配置和状态不在版本目录内；
2. 目标机未安装 Node/Go/npm 仍可运行；
3. TUI 可创建 Session 且 Session workspace 互相隔离；
4. agent credential 无法批准写操作；
5. BotMux 尚未安装时核心与 TUI 仍健康；
6. LXC 无 user namespace 时只禁用 `ops_bash`，类型化工具继续工作；
7. 重复 request/change 查询不会重放 mutation。
8. 安装 Adapter 后，`/botmux-setup` 不进入 transcript，BotMux 配置为 `0600` 且输出不含 secret。
9. managed-workload 仅监听 loopback，image/artifact/credential digest 与 policy 一致，容器无 privileged/device/socket mount。
10. `ops-agent` UID 不能连接 Docker socket或读取 workload credential，受管工作负载在重启后恢复。
