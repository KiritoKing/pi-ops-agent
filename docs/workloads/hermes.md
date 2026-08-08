# 第一方 Hermes managed-workload

`workload.hermes` 是通用运维能力的端到端用例，不是核心协议特例。业务事实全部位于
`plugins/workload-hermes/` 的 schema v2 manifest 与静态资源；core 只认识
`plugin.install`、`workload.deploy` 和固定 OCI 安全模板。

## 安装与凭据

fresh 主机应在模型外显式授权这个用例；裸 `init` 保持 core-only：

```bash
curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/main/scripts/install.sh \
  | sudo sh -s -- init --enable-artifact workload.hermes
```

已有 policy 不会被安装器扩权；管理员需要从当前 Release catalog 复制并复核完整
`id/kind/version/publisher/digest`，以及 managed-workload 所需的 Docker package/unit 后再
独立修改 root-owned policy。

先在 TUI 要求安装 `workload.hermes`，并以精确 `/approve <changeRef>` 完成插件安装。
随后准备一个 root-only 输入文件，内容只有以下三个字段：

```json
{"deepseekApiKey":"REDACTED","dashboardUsername":"admin","dashboardPassword":"REDACTED"}
```

使用插件自己的非特权准备工具生成通用 credential bundle，再交给通用 root 配置器。两个
文件都不得进入仓库、argv、模型上下文或 transcript：

```bash
sudo sh -c 'umask 077; \
  /opt/pi-ops-agent/current/runtime/node \
  /opt/pi-ops-agent/plugins/workload.hermes/current/prepare-credentials.mjs \
  --input-fd 3 3</root/hermes-input.json >/root/hermes-bundle.json'
sudo /opt/pi-ops-agent/current/scripts/configure-plugin-credentials.sh \
  --plugin-id workload.hermes \
  --target-id target-local-system \
  --credential-fd 3 3</root/hermes-bundle.json
sudo rm -f -- /root/hermes-input.json /root/hermes-bundle.json
```

准备工具生成 scrypt WebUI verifier 与随机 session secret。通用配置器校验 slot、已安装包的
publisher/version/digest 和 Target policy，写入 root-only bundle，并更新 policy revision。
它不会执行插件代码。该 legacy compatibility configurer 目前只支持首次部署；部署后禁止
credential replacement。这里描述的是仍需保留的旧 `.opspkg` 恢复边界，不代表当前 Source
Workload 或 Release 版本。

## 部署与交互

回到 TUI，要求安装 Docker（尚未安装时）并部署 `workload.hermes`。每个 change 都需要独立
审批。manifest 固定官方 multi-arch image digest、`gateway run`、`127.0.0.1:9119`、
4 GiB/2 CPU/512 PID、持久数据、最小 capability 和容器内健康检查。健康检查要求：

固定上游镜像的 s6 `/init` 需要容器内 root 完成 UID/GID 与 volume 初始化；manifest 因而
使用通用的 root-init/runtime-user 契约，精确允许一组 s6 supervisor 命令，并要求 `hermes`
服务最终以 `10000:10000` 运行。broker 会从宿主读取进程表逐项验证，未声明的 root/non-root
进程或身份漂移都会使部署回滚。容器没有 Docker socket、host namespace、设备或额外 mount。

业务健康检查另外要求：

- WebUI 启用 basic auth；
- gateway 为 running；
- platform connector 数量严格为 0。

WebUI 只监听 loopback。远程访问使用 SSH tunnel：

```bash
ssh -L 9119:127.0.0.1:9119 <admin>@<host>
```

验收应覆盖容器内 `hermes` CLI、`hermes --tui`、WebUI 登录与 Chat，以及主机重启后
`hermes --tui --continue` 的 Session 持久化。`ops-agent` UID 必须无法读取 workload
credential、连接 Docker socket或修改 root-helper 受管数据。
