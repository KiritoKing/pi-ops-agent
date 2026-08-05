export type ThinkingRoute = "low" | "medium" | "high";

export interface ModelRoute {
  provider: string;
  model: string;
  thinking: ThinkingRoute;
  risk: "R0" | "R1" | "R2";
  reason: string;
}

const CHANGE_PATTERN =
  /(?:安装|卸载|升级|更新|部署|重启|停止|启动|修改|配置|新增|删除|回滚|install|remove|upgrade|deploy|restart|stop|start|configure|write|delete|rollback)/i;
const DIAGNOSE_PATTERN =
  /(?:故障|异常|原因|诊断|日志|journal|debug|diagnos|root cause|为什么|排查)/i;
const SIMPLE_PATTERN =
  /(?:状态|健康|负载|磁盘|内存|版本|uptime|status|health|load|disk|memory|version)/i;

export function routePrompt(
  text: string,
  provider = "deepseek",
  model = "deepseek-v4-flash",
): ModelRoute {
  if (CHANGE_PATTERN.test(text)) {
    return {
      provider,
      model,
      thinking: "high",
      risk: "R2",
      reason: "potential host mutation",
    };
  }
  if (DIAGNOSE_PATTERN.test(text)) {
    return {
      provider,
      model,
      thinking: "high",
      risk: "R1",
      reason: "diagnostic reasoning",
    };
  }
  if (SIMPLE_PATTERN.test(text)) {
    return {
      provider,
      model,
      thinking: "low",
      risk: "R0",
      reason: "bounded read-only inspection",
    };
  }
  return {
    provider,
    model,
    thinking: "medium",
    risk: "R1",
    reason: "general operations request",
  };
}
