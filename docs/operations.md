# 运维、审计与恢复

## 日常命令

```bash
sudo /opt/pi-ops-agent/scripts/healthcheck.sh
systemctl status ops-agent.target ops-agentd ops-systemd-helper ops-root-helper --no-pager
journalctl -u ops-agentd -u ops-systemd-helper -u ops-root-helper -f
```

计划维护时停止整个 target，避免 watchdog 重新拉起 agentd：

```bash
sudo systemctl stop ops-agent.target
# 完成维护
sudo systemctl start ops-agent.target
```

不要单独长时间停止 agentd；systemd-helper 会把它视为故障。

## credential 轮换

```bash
sudo /opt/pi-ops-agent/scripts/encrypt-credential.sh --force
sudo systemctl restart ops-agentd.service
```

脚本从无回显 stdin 读取 key，经管道直接交给 `systemd-creds encrypt`，不创建明文临时文件。轮换后检查 agentd journal 和一次只读模型请求；旧 encrypted credential 被原子替换。

## 配置升级

重复执行 installer 时保留 `/etc/ops-agent/agentd.json` 和 `models.json`，新默认值写入相邻 `.dist`。人工比较后再合并：

```bash
diff -u /etc/ops-agent/agentd.json /etc/ops-agent/agentd.json.dist
diff -u /etc/ops-agent/models.json /etc/ops-agent/models.json.dist
```

改配置后先运行构建测试和 `systemd-analyze verify`，再重启 target。不要在生产机上把供应商 model ID 改成未经验证的自动 fallback。

## 审计

| 日志 | 内容 | 写权限 |
|---|---|---|
| `/var/log/ops-agent/agentd/audit.jsonl` | prompt 路由、工具调用、模型事件 | `ops-agent` |
| `/var/log/ops-agent/root-helper/audit.jsonl` | prepare、审批者 UID、执行、验证、回滚 | root |
| `/var/log/ops-agent/systemd-helper/audit.jsonl` | heartbeat、只读检查、watchdog restart | root |

日志是 hash chain；应由日志采集器只追加上传到另一台机器。链能发现事后改写，但不能阻止已获得 root 的攻击者同时替换日志和程序。审计中仍应通过 BotMux message ID/session ID 与 helper `requestId/changeId/auditId` 做关联。

## 失败恢复

1. 先停止 `ops-agent.target`，冻结自动重试。
2. 读取 root-helper audit，确认最终状态和备份路径；不要相信模型总结。
3. 若状态是 `ROLLED_BACK`，独立验证文件摘要、包版本和 unit 状态。
4. 若状态是 `RECOVERY_REQUIRED` 且 `/status <changeId>` 显示 `rollbackAvailable=true`，由真实审批者先执行 `/rollback <changeId>`，再独立验证 `ROLLED_BACK`。若 root-helper 报告回滚不可用或回滚失败，再从 `/var/lib/ops-agent/root-helper` 下的 root-only 备份按审计记录人工恢复。
5. 恢复后做只读健康检查，再启动 target；不要重复提交同一个业务变更来“试试看”。

agentd session 损坏只影响对话上下文，不应影响 root-helper 的权威变更状态。可先备份再移走单个 session JSONL，让同一 BotMux chat 创建新会话；禁止清空整个 state 目录来修一个会话。

## 卸载

默认卸载保留 credential、会话、备份和审计：

```bash
sudo /opt/pi-ops-agent/scripts/uninstall.sh
```

确认已导出审计和备份后，才永久清理：

```bash
sudo /opt/pi-ops-agent/scripts/uninstall.sh --purge-state --yes --remove-user
```

`--purge-state` 不可恢复，会删除 systemd encrypted credential。默认路径更适合升级、回滚程序版本或暂时停用。
