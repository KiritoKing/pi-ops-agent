# 运维、升级、审计与恢复

## 日常入口

TUI 是始终安装、与任何外部 IM 无关的保底入口：

```bash
ops-agent tui
```

服务与健康检查：

```bash
sudo /opt/pi-ops-agent/current/scripts/healthcheck.sh
systemctl status \
  ops-agent.target \
  ops-agentd.service \
  ops-systemd-helper.service \
  ops-agent-server.service \
  ops-root-helper.service \
  --no-pager
journalctl \
  -u ops-agentd.service \
  -u ops-systemd-helper.service \
  -u ops-agent-server.service \
  -u ops-root-helper.service \
  -f
```

这些是 `v0.1.x` artifact 名称，分别对应 `agentd`、兼容 `agentd-guard`、
`agentd-server` 和 `agentd-root-broker`。规范名称与迁移状态见[架构文档](architecture.md)。

计划维护时停止整个 target，避免 systemd/`agentd-guard` 重新拉起 `agentd`：

```bash
sudo systemctl stop ops-agent.target
# 完成维护
sudo systemctl start ops-agent.target
```

## 程序升级与回退

程序安装在不可变版本目录，`current` 是唯一激活指针：

```text
/opt/pi-ops-agent/
├── current -> releases/0.1.0
└── releases/
    ├── 0.1.0/
    └── 0.2.0/
```

配置、credential、Session、MachineContext、备份和审计都位于 `/etc`、`/var/lib`、
`/var/log`，不随程序目录切换。升级前必须先校验 Release checksum/attestation、协议
兼容性和配置迁移计划，再安装新版本并原子切换 `current`。

若启动或冒烟失败，停止 target，将 `current` 原子指回旧版本，执行
`systemctl daemon-reload` 后重新启动。程序回退不能自动回退数据 schema；存在不可逆迁移
时，Release 必须在安装前拒绝并要求显式迁移计划。

已有配置不会被覆盖；新默认写到相邻 `.dist`：

```bash
diff -u /etc/ops-agent/agentd.json /etc/ops-agent/agentd.json.dist
diff -u /etc/ops-agent/models.json /etc/ops-agent/models.json.dist
```

## Credential 与证书

模型 credential 轮换：

```bash
sudo /opt/pi-ops-agent/current/scripts/encrypt-credential.sh --force
sudo systemctl restart ops-agentd.service
```

模型、Adapter、agent-role、approver-role 和 admin-role credential 必须分开。轮换远端
`agentd-server` 证书时先建立新证书的重叠有效期，验证 identity/policy digest 后再吊销旧证书；
不能因 endpoint IP 不变而接受 identity 漂移。

Enrollment bundle 是短期离线 bootstrap bearer，不是长期 credential。它绑定 controller
origin、endpoint identity、证书、policy 和期限，但 MVP 没有在线消费记录，不能保证
“用过即失效”。成功接入后立即删除所有复制件；失败重试生成新 bundle，并禁用 issuer
预先写入但未完成 smoke 的待接入注册项。

## Machine、Target 与策略漂移

机器以稳定 `machineId/serverId` 标识，地址只是 locator。每次 `agentd-server` 重连刷新 observed endpoint、
capability digest、policy revision 和证书期限，但不能让 `agentd-server` 覆盖本地 trust pin 或 alias。

以下变化必须 fail-closed 并要求管理员检查：

- `agentd-server` identity、machineId 或证书 pin 变化；
- Target 对应 UID/GID/账号变化；
- capability 新增写/root 能力；
- policy revision 在 prepare 与 approve 之间变化；
- 已审批计划的 precondition、backup 或 verification digest 变化。

机器下线时先禁用新 Session 和 prepare，等待在途 change 到达权威终态，然后吊销证书并
归档审计。删除注册表记录不能删除远端备份或 `agentd-root-broker` 状态。

## Adapter 生命周期

统一状态为：

```text
AVAILABLE -> INSTALLED -> CONFIGURED -> VERIFIED -> ENABLED
                                             \-> DEGRADED / DISABLED
```

插件安装、升级和删除都必须由 Agent 准备类型化 change，管理员在模型外审批。Adapter
失败不能影响 TUI 和核心服务。升级后重新验证 sender identity、私聊语义、防重放、入站、
出站及 approval intent；任一失败都不能保留审批能力。

BotMux 本体不由 `init` 或 Adapter 插件安装。`/botmux-setup` 只在交互式 TUI 中运行，并
依次调用 BotMux 官方 setup、固定 hardener 和 restart；配置变化前保存 `0600` 备份。
BotMux 配置内的明文 Lark secret 由该管理员账户负责保护。回退 Adapter 不会删除 BotMux
配置或 secret；永久清理必须由管理员在模型外按 BotMux 自身流程执行。

卸载 Adapter 默认保留 encrypted credential 和最小 outbox/state 以便恢复。永久清理
秘密是另一项显式、不可恢复操作。

## 变更状态与恢复

权威状态位于目标机器 `agentd-root-broker`，不位于对话 Session：

```text
PREPARED -> APPROVED -> EXECUTING -> COMMITTED
     |          |           |
     v          v           +-> ROLLED_BACK
 REJECTED    EXPIRED             |
                                  +-> RECOVERY_REQUIRED
```

连接中断、controller 重启或 Session 损坏后，只能用原
`serverId + changeId + requestId` 查询状态，不能重新提交 mutation。

恢复步骤：

1. 冻结目标资源的新 mutation；必要时停止目标 endpoint；
2. 读取 `agentd-root-broker` 的 root-only change state 和审计，不相信模型总结；
3. `COMMITTED`：独立检查 verification；
4. `ROLLED_BACK`：核对资源摘要和服务状态；
5. `RECOVERY_REQUIRED`：按审计定位备份，由真实管理员显式 rollback 或人工恢复；
6. 恢复后先做只读 smoke，再解除资源锁。

文件原子替换可以提供强回滚；service action 和 package install 只有有限或 best-effort
回滚语义，不能把 `rollbackAvailable=true` 描述成完整事务保证。

## 审计

至少关联：

```text
adapter ingress/message ID
principal ID
agentSessionId / turnId
serverId / machineId / targetId
requestId / changeId / planHash
policy and capability revisions
approver identity / approval nonce
backup / verification / rollback evidence
```

`agentd`、`agentd-server` 和 `agentd-root-broker` 分别写业务/安全审计；
`agentd-guard` 只写心跳过期、身份校验和有界终止等可用性审计。root 审计不能由
`ops-agent` 改写。Hash chain
只能发现本地篡改，不能抵御已获得 root 的攻击者整体替换程序与日志；生产部署应把摘要
只追加传送到独立系统。

## 卸载

默认卸载程序和 unit，但保留配置、credential、Session、MachineContext、备份与审计：

```bash
sudo /opt/pi-ops-agent/current/scripts/uninstall.sh
```

确认数据已经导出后才执行永久清理：

```bash
sudo /opt/pi-ops-agent/current/scripts/uninstall.sh --purge-state --yes --remove-user
```

`--purge-state` 不可恢复。它不能被模型自行准备为低风险操作，也不能由 IM 群聊审批。
