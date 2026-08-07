# 安全模型

## 保护目标

1. Prompt、模型、日志、远端 `agentd-server` 或 Adapter 被控制后，不能自行获得或批准 root。
2. 一个 machine/session 被控制后，不能静默扩展到未注册机器、Target 或其他 workspace。
3. 每个高权限变更可证明目标、计划、审批、备份、验证、终态和恢复证据。
4. 断线、重试、进程崩溃和重复 webhook 不会重复业务 mutation。
5. 模型、IM、transport、enrollment 与审批 credential 相互隔离。

同一 LAN 不是信任边界。Prompt、工具参数、capability manifest、日志、文件、软件源、
网络响应和历史记忆均是不可信输入。

## 分层边界

| 层 | 强制控制 |
|---|---|
| Harness | 禁用 Pi 原生工具/skill/extension；固定类型化工具；不可信 capability 只能取交集 |
| Session | 独占 workspace 和 writer lease；机器/Target 由 Harness 绑定 |
| Sandbox | bubblewrap 无网络、系统只读、只挂当前 workspace；独立非 root UID |
| Guard | `agentd-guard` 与 `agentd` 同 UID，只做固定心跳/进程身份检查和有界终止；不是权限边界 |
| Registry | 稳定 serverId、证书 pin、管理员注册；IP 不是身份 |
| Transport | HTTPS/mTLS、角色分离、严格 schema、deadline、限流、幂等、防重放 |
| Server | `agentd-server` 是非 root 网络前端；root policy 和 credential 只读 |
| Root broker | `agentd-root-broker` Unix-only、peer identity、tagged union、资源 allowlist、无 raw root API |
| Approval | 模型外 principal；绑定不可变 plan 和短期 nonce；执行前重新校验 |
| Recovery | 写前备份、fsync、验证、自动回滚或 `RECOVERY_REQUIRED` |

黑名单和 System Prompt 只减少误触，不是权限证明。

## Target 与路径权限

Root-owned policy 把 `targetId` 映射为 UID/GID、允许的路径、unit 和 recipe。模型不能提交
用户名、UID 或 `runAs`。路径授权必须在 canonical/fd 层阻止 symlink/rename 逃逸；Linux
实现优先使用 `openat2` 的 `RESOLVE_BENEATH/NO_SYMLINKS` 或等价机制。Unit 使用精确
allowlist，输出、deadline、并发和资源大小有硬上限。

策略结果为 `deny/read/prepare/human-approve/local-console-only`。MVP 中有副作用的
文件、服务、包、root 及插件安装全部需要人工审批；远端任意脚本和 breakglass 不发布为
capability。

## 审批与状态机

```text
PREPARED -> APPROVED -> EXECUTING -> COMMITTED
     |          |           |
     v          v           +-> ROLLED_BACK
 REJECTED    EXPIRED             |
                                  +-> RECOVERY_REQUIRED
```

ApprovalGrant 至少绑定：

```text
serverId, machineId, targetId, changeId,
planHash, policyRevision, capabilityRevision,
preconditions, issuedAt, expiresAt, nonce, approver identity
```

Agent credential 不能生成 ApprovalGrant。`agentd-server` 与 `agentd-root-broker` 都必须
重新校验，任何 identity、plan、policy、capability 或 precondition 变化都会使旧审批
失效。只有 `agentd-root-broker` 返回 `COMMITTED` 才能宣告成功。

## 插件与秘密

插件包必须有严格 manifest、固定 publisher/version/digest、SBOM 和受信 catalog 记录。
GitHub Release artifact attestation 是发布来源证明；没有执行 attestation 验证时只能声称
验证了 HTTPS + checksum，不能声称独立签名已验证。

插件不得携带 root shell installer。Agent 只能准备由 `agentd-root-broker` 认识的类型化安装操作。
MVP 没有通用 secret broker，也不让模型发起 secret 请求。BotMux Adapter 文件提交后，
只有交互式 TUI 的精确 `/botmux-setup` 能在模型外把终端交给 `botmux setup`；ops-agent
不读取 secret，transcript、argv 和审计正文均不包含 secret。BotMux 当前把 Lark secret
明文保存在管理员账户的 `~/.botmux/bots.json`；hardener 强制配置和备份为 `0600`。这是
明确的第三方存储边界，不能描述成 systemd encrypted credential 或 ops-agent broker。

Adapter 只有在能验证 sender、区分私聊/群聊/转发/机器人、持久去重并签名绑定
principal + ingress ID + changeRef 时，才可声明 approval capability；否则只能聊天/只读，
审批回到 TUI。

## Release 与供应链

目标机不运行 npm/Go 构建。Release workflow 固定依赖、编译 amd64/arm64、下载并校验
固定 Node runtime，生成 tar、Debian package、SPDX SBOM、manifest、checksums 和 GitHub
artifact attestation。安装器在任何解包/主机写入前校验 archive checksum；版本目录与
配置/状态分离，激活使用原子 `current` 切换。

Checksum 与 artifact 位于同一 GitHub Release，只能检测传输损坏或资产不一致，不能
替代独立签名/attestation。高价值环境必须执行 `gh attestation verify` 或从已验证的内部
镜像部署。

## 已知边界

MVP 不抵御内核漏洞、`agentd-root-broker` 自身漏洞、被控制的软件源、已获得 root 的攻击者或
systemd credential 主密钥泄漏。Controller HA、多方审批、外部审计锚定、自动低风险写入、
远端任意脚本和记忆插件均不在 MVP。

后续“结构化/AI 辅助审核”不能按文本行拆 shell，必须按 Shell AST 和源跨度展示命令、
管道、重定向、变量及风险；findings 以结构化节点返回。任何局部修改都要重新
prepare/hash/审批。审核模型只能提高风险或提示遗漏，不能降低确定性策略或授权，并须
披露额外 Token。

后续记忆插件也不能修改工具、权限或系统 Prompt。记忆区分 machine、machine-target 和
global scope，带适用条件；上线前必须用真实历史 Session replay 披露平均/P95 在线、后台
及总体 Token 增量和比例，未经成本确认不能启用。

Enrollment bundle 由 controller 离线签名并绑定 origin、endpoint identity、证书、policy
和期限。MVP 不维护在线 nonce 消费表，因此不能声称单次使用；有效期内的复制件可重放。
文件权限、短期限、成功后删除和 credential 轮换是当前补偿控制。
