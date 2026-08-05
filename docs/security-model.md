# 安全模型

## 保护目标

1. 模型或 agentd 被 prompt injection 控制后，不能自行获得 root，也不能批准自己准备的变更。
2. 每个高权限变更都能回答“谁批准、执行了什么、备份在哪里、验证结果如何”。
3. 执行失败时优先自动回滚；无法安全回滚时进入 `RECOVERY_REQUIRED`，禁止谎报成功。
4. 密钥不进入 Git、普通配置、环境变量、进程参数、prompt 或审计正文。

## 不信任输入

飞书消息、模型回复、工具参数、日志、journal、文件内容、软件包元数据和网络响应全部是不可信数据。系统提示只能改善行为，不能提供权限保证。

## 分层控制

| 层 | 控制 | 被绕过后的下一层 |
|---|---|---|
| harness | 固定系统提示、禁用 Pi 内置工具/skill/extension、只注册四个 ops 工具 | agentd 独立 UID |
| 命令预检 | 拒绝 `sudo`、mount、块设备、容器 socket、fork bomb 等明显危险命令 | bubblewrap |
| 沙箱 | user/mount/network 等 namespace、只读系统目录、无网络、唯一 workspace bind | 非特权 `ops-agent` UID |
| RPC | 最大帧、schema、deadline、固定 tagged union、无 raw root command | peer UID + 审批状态机 |
| 审批 | `SO_PEERCRED` 校验配置的真实审批 UID；摘要绑定不可变计划 | root-helper 执行器 |
| 恢复 | 写前备份、原子替换、验证、失败回滚 | root-only 备份与审计 |
| 宿主 | systemd hardening、独立目录、能力裁剪、restart 限流 | 人工恢复流程 |

### 为什么保留 Bash

运维需要组合现有诊断工具，完全取消 Bash 会把大量日常只读工作重新实现成专用 RPC。这里保留的是两类能力：

- `ops_bash`：适合解析文本、生成配置草案和离线脚本测试；运行于离线 bubblewrap，不能看宿主 credential、systemd socket、Docker socket或 workspace 之外的可写目录。
- `breakglass.script`：面向类型化操作覆盖不到的罕见 root 任务，默认关闭。开启后必须显式列出备份路径、验证脚本和网络需求，计划摘要不可变，仍需真实用户批准。

黑名单只减少误触和低成本攻击。真正的边界是 namespace、文件映射、独立 UID 和 root-helper 协议；不应通过不断扩充正则表达式来宣称 shell “安全”。

agentd unit 保留 `ProtectProc=invisible`，但不能启用 `ProcSubset=pid`：bubblewrap 创建 user namespace 时需要只读访问 `/proc/sys/kernel/overflowuid` 与 `overflowgid`。它还需要 `AF_NETLINK` 在新网络 namespace 内初始化隔离 loopback；agentd 没有 `CAP_NET_ADMIN`，sandbox command 仍无宿主网络。内核参数仍由 `ProtectKernelTunables=yes` 禁止写入。

## 高权限状态机

```text
PREPARED -> APPROVED -> EXECUTING -> COMMITTED
     |          |           |
     v          v           +-> ROLLED_BACK
 REJECTED    EXPIRED             |
                                  +-> RECOVERY_REQUIRED
```

- `PREPARED` 必须包含规范化操作、摘要、备份计划和验证计划。
- 审批绑定 `changeId` 和内容摘要；prepare 后不能修改内容。
- 只有 root-helper 返回 `COMMITTED` 才能向用户声称成功。
- `RECOVERY_REQUIRED` 需要人类从 root-only 备份恢复，不得继续自动尝试。

## 密钥模型

DeepSeek key 通过 `systemd-creds encrypt` 生成 `/etc/ops-agent/credentials/deepseek_api_key.cred`。unit 使用 `LoadCredentialEncrypted=`，systemd 在服务私有 credential 目录解密为只读文件；agentd 通过 `CREDENTIALS_DIRECTORY` 读取后放入 Pi 的内存 credential store。

禁止把 key 放进 `models.json` 的 `apiKey`、`Environment=`、`.env`、命令行或消息 prompt。消息桥自身的 IM 凭据也应使用独立的 encrypted credential；两组 credential 不共享。core 的完成事件协议只使用继承的 FD，不读取消息桥环境变量；任何 adapter 都必须在启动 core 前剥离厂商 credential。

## 默认拒绝与可扩展性

- `file.write` 默认只允许 `/etc`、`/opt`；新增根目录需要 root-owned systemd override 和安全评审。
- package install 是类型化包名/版本，不接受拼接参数。
- service action 只接受合法 `.service` unit 和固定 action。
- 原始磁盘、内核模块、主机生命周期、firewall、容器/VM 控制默认拒绝。
- 消息桥应只把 allowlist 用户的私聊映射到可写会话；群聊默认只读或完全禁用审批命令。

## 尚未覆盖

MVP 不抵御内核漏洞、root-helper 自身内存安全漏洞、被替换的软件源/包签名根、已获得 root 的攻击者或 systemd credential 主密钥泄露。公网发布前应增加 fuzz、协议兼容测试、包管理器隔离测试和外部安全审计。

### Pi 0.83.0 上游依赖告警

截至 2026-08-05，官方 npm 上最新的 `@earendil-works/pi-coding-agent` 仍是 0.83.0，发布包自带 shrinkwrap，固定 `undici@8.5.0` 和 `minimatch@10.2.5`/`brace-expansion@5.0.7`。`npm audit` 因此报告 2 个 high、1 个 moderate；根项目 `overrides` 会被该 shrinkwrap 阻断，不能用伪造 lockfile 宣称已修复。

本 harness 禁用了 Pi 内置工具、skill、extension、prompt template 和 context file；模型不能提供 model glob，HTTP cache/retry/cookie/blob API 也未暴露为 agent tool。因此当前已知利用路径不直接由消息输入触发，但这不是漏洞修复。部署应保持单审批者、固定模型 endpoint 和 systemd 重启/限流；上游发布包含 `undici >= 8.9.0`、`brace-expansion >= 5.0.9` 的版本后，应优先升级并重新执行完整冒烟。若威胁模型包含恶意模型 endpoint、共享 HTTP cache 或不可信本地配置写入者，应在上游修复前停止部署。
