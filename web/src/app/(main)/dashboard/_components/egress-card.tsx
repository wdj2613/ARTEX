"use client";

import * as React from "react";

import { Globe2Icon, Loader2Icon, NetworkIcon, RadioTowerIcon, RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { EgressCheck, EgressReport } from "@/lib/types";
import { cn } from "@/lib/utils";

// 仪表盘出口卡片：进页面自动探一次，可手动刷新。
// 复用后端 POST /api/settings/proxy/test —— 它返回两条链路：
//   direct（真实出口，不经过任何代理）、global（经已保存的全局代理出网）。
// 没有全局代理时 global 是 skipped，此时卡片只报真实出口并说明当前直连。

type ProbeState = {
  report: EgressReport | null;
  isLoading: boolean;
  error: string | null;
};

// 失败原因取第一个出错地址：refused=代理没开，timeout=出不了网。
function firstError(check: EgressCheck | undefined): string {
  return check?.result.probes?.find((p) => p.error)?.error ?? check?.result.error ?? "探测失败";
}

function EgressCell({
  icon: Icon,
  title,
  hint,
  check,
  isLoading,
}: {
  icon: React.ElementType;
  title: string;
  hint: string;
  check: EgressCheck | undefined;
  isLoading: boolean;
}) {
  const skipped = !!check?.skipped;
  const ok = !!check && !skipped && check.result.ok;
  const failed = !!check && !skipped && !check.result.ok;

  return (
    <div className="min-w-0 rounded-md border px-3 py-2">
      <div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[10px] text-muted-foreground">
        <Icon className="size-3 shrink-0" aria-hidden="true" />
        <span className="font-medium text-foreground">{title}</span>
        {ok && !isLoading && (
          <span className="ml-auto flex shrink-0 items-center gap-1 text-emerald-500">
            <span className="size-1.5 rounded-full bg-emerald-500" aria-hidden="true" />
            连通
          </span>
        )}
        {failed && !isLoading && (
          <span className="ml-auto flex shrink-0 items-center gap-1 text-destructive">
            <span className="size-1.5 rounded-full bg-destructive" aria-hidden="true" />
            不通
          </span>
        )}
      </div>
      <div className="mt-1 min-w-0 text-sm">
        {isLoading ? (
          <span className="inline-flex items-center gap-1 text-muted-foreground text-xs">
            <Loader2Icon className="size-3 animate-spin" aria-hidden="true" /> 探测中…
          </span>
        ) : ok ? (
          <span className="flex min-w-0 flex-wrap items-baseline gap-x-1.5">
            {/* IPv6 很长，窄屏必须允许在任意位置换行，否则撑破卡片 */}
            <span className="min-w-0 font-mono break-all [overflow-wrap:anywhere]">
              {check.result.exit_ip || "已连通"}
            </span>
            <span className="shrink-0 text-[10px] text-muted-foreground">{check.result.latency_ms}ms</span>
          </span>
        ) : failed ? (
          <span className="break-words text-destructive text-xs [overflow-wrap:anywhere]">{firstError(check)}</span>
        ) : (
          <span className="text-muted-foreground text-xs">{hint}</span>
        )}
      </div>
    </div>
  );
}

export function EgressCard() {
  const [state, setState] = React.useState<ProbeState>({ report: null, isLoading: true, error: null });
  // 请求序号：连点刷新或重复挂载时，只认最后一次的结果。
  const seq = React.useRef(0);

  const probe = React.useCallback(async () => {
    const mine = ++seq.current;
    setState((prev) => ({ ...prev, isLoading: true, error: null }));
    try {
      // 用已保存的 global_proxy 探测（不是输入框里的值），否则显示的出口和 agent 实际出口不一致。
      const settings = await api.settings();
      if (mine !== seq.current) return;
      const report = await api.testEgressProxy({ global_proxy: settings.global_proxy ?? "" });
      if (mine !== seq.current) return;
      setState({ report, isLoading: false, error: null });
    } catch (cause) {
      if (mine !== seq.current) return;
      setState({ report: null, isLoading: false, error: cause instanceof Error ? cause.message : "未知错误" });
    }
  }, []);

  // 只在挂载时探一次：轮询会重复发真实出网请求，所以刷新是手动的。
  React.useEffect(() => {
    void probe();
  }, [probe]);

  const direct = state.report?.checks.find((c) => c.key === "direct");
  const global = state.report?.checks.find((c) => c.key === "global");
  // configured 已在后端脱敏（user:pass → ***），可以直接显示。
  const proxyLabel = state.report?.configured ?? "";

  return (
    <Card className="p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs font-semibold">
          <Globe2Icon className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
          出口 IP
          <span className="min-w-0 font-normal text-[10px] text-muted-foreground break-all [overflow-wrap:anywhere]">
            {state.isLoading ? "正在探测…" : proxyLabel ? `全局代理 · ${proxyLabel}` : "未配置全局代理"}
          </span>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          onClick={() => void probe()}
          disabled={state.isLoading}
          aria-label="重新探测出口 IP"
        >
          <RefreshCwIcon className={cn("size-3.5", state.isLoading && "animate-spin")} aria-hidden="true" />
        </Button>
      </div>

      {state.error ? (
        <p className="break-words text-destructive text-xs [overflow-wrap:anywhere]">探测失败：{state.error}</p>
      ) : (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <EgressCell icon={NetworkIcon} title="真实出口" hint="尚未探测" check={direct} isLoading={state.isLoading} />
          <EgressCell
            icon={RadioTowerIcon}
            title="代理出口"
            hint="未配置全局代理 · 直连出网"
            check={global}
            isLoading={state.isLoading}
          />
        </div>
      )}
    </Card>
  );
}
