package agent

import (
	"strings"
	"testing"
)

// 等待规范是代码-owned 的段 [D]：即使有人把 DB 里的 worker 提示词整段改掉，这段也必须
// 还在——它是"长跑任务别用 sleep 阻塞意图预算"这条规则的唯一常驻说明。
func TestWorkerSystemAlwaysCarriesWaitSpec(t *testing.T) {
	old := PromptOverride
	t.Cleanup(func() { PromptOverride = old })
	// 模拟用户把 worker 提示词改成一句毫无约束力的话。
	PromptOverride = func(k string) (string, bool) {
		if k != "worker" {
			return "", false
		}
		return "随便干点什么", true
	}
	got := workerSystem("", "", "/data", "/data/tasks/7/i42")
	for _, want := range []string{"等待类任务的执行方式", "run_in_background", "TaskOutput", "30 秒", "/data/tasks/7/i42", "进度留痕", "report_progress"} {
		if !strings.Contains(got, want) {
			t.Fatalf("worker 提示词缺少 %q（用户改 DB 提示词后不该丢）: %q", want, got)
		}
	}
	// 顺序固定：正文 → 流量段（可选）→ 产物规约 → 等待规范，便于排查实际下发的提示词。
	if i, j := strings.Index(got, "中间产物输出规约"), strings.Index(got, "等待类任务的执行方式"); i < 0 || j < i {
		t.Fatalf("等待规范应排在产物规约之后: artifact=%d wait=%d", i, j)
	}
	if i, j := strings.Index(got, "等待类任务的执行方式"), strings.Index(got, "进度留痕"); i < 0 || j < i {
		t.Fatalf("进度留痕应排在等待规范之后: wait=%d progress=%d", i, j)
	}
}
