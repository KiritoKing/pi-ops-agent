# MVP 重构技术方案与路线

本文是 MVP 范围与后续路线的审核基线。架构、安全、部署和恢复细节分别由同目录专门
文档约束；实现与本文冲突时必须在同一变更中更新文档和测试。

## MVP 交付范围

1. 中央非 root `agentd`：Pi Harness、固定工具、多 Machine/Target、多 Session、每
   Session 独占 workspace。
2. 每机器一个非 root `agentd-server`：HTTPS + JSON + mTLS、能力发现、Target、严格
   schema、限流、幂等和异步 change。
3. 每机器一个 Unix-only root helper：类型化权限、备份、执行、验证、回滚和权威状态。
4. 模型外审批：agent/approver/admin role credential 分离，授权绑定完整计划摘要。
5. TUI 保底入口与 Adapter Plugin 抽象；BotMux 作为首个独立 `.opspkg`，由用户通过
   TUI 对话要求 Agent 准备安装，不属于 `init`。
6. 原生 systemd 部署：GitHub Raw 最小 bootstrap、amd64/arm64 预构建 Release、`.deb`、
   SBOM、manifest、checksums、artifact attestation、版本目录切换与回退。

## 明确排除

- Docker/OCI/Compose、非 systemd Linux 和 macOS；
- 远端任意脚本、raw root command、模型自行审批；
- 自动低风险写入、多人审批、controller HA；
- 记忆、自进化、对话前召回和后台沉淀 daemon；
- AI 审核模型和 Shell 脚本逐节点审核。

## 实施顺序

1. 领域与严格协议：Machine、Target、Session、ChangeRef、Principal、Capability、Policy。
2. Session 隔离与本地 client gateway；保留旧 Unix helper adapter 作为迁移层。
3. Go server、mTLS role、root helper Target policy、异步 change 和幂等恢复。
4. 注册、enrollment、机器池、capability/policy drift 与跨机器审批路由。
5. TUI 事件、模型外审批、插件 catalog/prepare/status、BotMux Adapter Plugin 与模型外
   `/botmux-setup`。
6. Release/原生安装、升级回退、干净 PVE LXC 冒烟和 GitHub 首个 Release。

## MVP 验收

- 干净 amd64/arm64 systemd Linux 无开发工具时，一条 Raw 命令完成 `init`；
- `init` 后 BotMux 未安装但 `ops-agent tui` 可用；
- Agent 可准备 BotMux Adapter 安装，Agent 无法批准；BotMux secret 只进入其官方交互，
  不进入模型、ops-agent transcript 或 argv；
- 后续机器通过短期签名 bundle enrollment，失败不启用 endpoint；离线 bundle 在有效期
  内不具备中心化单次消费保证；
- 两台机器、多个 Target 和多个 Session 不串 identity/workspace/change；
- 恶意 capability 不能创建未知工具或扩权；
- agent-role 不能 approve，旧审批不能跨 server/Target/policy revision 复用；
- 断线/重复 request 不重复 mutation；
- 文件写前有备份、fsync、验证和可核对终态；
- PVE LXC 无 user namespace 时只禁用 `ops_bash`，不降低其他边界；
- CI、Go race/vet、协议和安装测试全绿，GitHub Release 资产、SBOM、checksum、manifest、
  attestation 均可读取并完成一次干净机安装。

## MVP 后续

### 自进化与记忆插件

独立第一方插件在对话前判断是否需要召回，并由后台 daemon 按 cursor 增量查阅已结束
对话，生成候选经验。Scope 必须是 `machine`、`machine-target` 或带适用条件的 `global`；
实时检查永远高于记忆。插件不能修改代码、系统 Prompt、工具、policy 或审批。

上线依次经过 shadow、candidate-only、历史 replay 和小流量 canary。成本报告必须披露
每轮平均/P50/P95、在线召回、后台沉淀、总体 Token 增量和相对不开启插件的比例；未经
成本报告与明确确认不能启用。

### 结构化与 AI 辅助审批

Shell 必须解析 AST 与源跨度，而不是按换行拆分；展示 command、pipeline、redirect、
variable 和风险，审核意见使用结构化 node/span findings。任何局部修改都会生成新计划、
新 hash 和新审批。AI reviewer 只辅助发现风险，不能降低确定性策略、批准或授权；同样
必须披露额外 Token。

### 其他增强

- Lark Direct、Slack 等 Adapter，共用 envelope、secret 和安装计划；
- 多人审批与更细粒度资源锁；
- 经证明幂等、账号级、可逆 recipe 的低风险自动执行；
- Controller HA、证书自动轮换、外部审计锚定和分阶段插件更新。
