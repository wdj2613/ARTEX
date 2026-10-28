package agent

import (
	"strings"
	"testing"
)

func TestRenderSystemOverrideAndFallback(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })

	// no override → built-in default
	PromptOverride = nil
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "g"}); got != "DEFAULT" {
		t.Fatalf("no override should give default, got %q", got)
	}

	// override → rendered with vars
	PromptOverride = func(k string) (string, bool) {
		if k == "planner" {
			return "目标:{{.Goal}} 范围:{{.Scope}}", true
		}
		return "", false
	}
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "拿下X", Scope: "*.x.com"}); got != "目标:拿下X 范围:*.x.com" {
		t.Fatalf("override render: %q", got)
	}

	// override referencing a non-catalog var → execution error → fallback to default
	PromptOverride = func(k string) (string, bool) { return "{{.NotInCatalog}}", true }
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "x"}); got != "DEFAULT" {
		t.Fatalf("bad var should fall back to default, got %q", got)
	}

	// full plannerSystem path: DB body [A] is honored, then the code-owned tail
	// [C] (中间产物输出规约) is ALWAYS appended — editing the body can't drop it.
	PromptOverride = func(k string) (string, bool) { return "PLANNER {{.Goal}}", true }
	got := plannerSystem("拿下X", "/data", "/data")
	if !strings.HasPrefix(got, "PLANNER 拿下X") {
		t.Fatalf("plannerSystem body not honored: %q", got)
	}
	if !strings.Contains(got, "中间产物输出规约") || !strings.Contains(got, "/data") {
		t.Fatalf("plannerSystem missing code-owned artifact tail: %q", got)
	}

	// worker dual-text via {{if .ProxyAddr}} in a user template, plus the code tail:
	// [B] trafficTool present only when RECORDING (caCert set — the MITM is on, so
	// the traffic_* tools exist), [C] artifact spec always present. The trafficTool
	// block is gated on the CA (arg 2), NOT on ProxyAddr — a global egress proxy
	// with capture off routes traffic but records nothing.
	PromptOverride = func(k string) (string, bool) {
		return "{{if .ProxyAddr}}走代理 {{.ProxyAddr}}{{else}}手动{{end}}", true
	}
	recording := workerSystem("127.0.0.1:8080", "/ca.pem", "/data", "/data")
	if !strings.HasPrefix(recording, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker proxy branch body: %q", recording)
	}
	if !strings.Contains(recording, "traffic_search") {
		t.Fatalf("worker while recording should inject trafficTool: %q", recording)
	}
	if strings.Contains(recording, "traffic_refs") {
		t.Fatalf("worker bypassed shared optional evidence policy: %q", recording)
	}
	if !strings.Contains(recording, "中间产物输出规约") {
		t.Fatalf("worker missing artifact tail: %q", recording)
	}
	// Egress proxy set but capture OFF (no CA): the ProxyAddr template branch still
	// renders, but the trafficTool block must NOT — those tools are not registered.
	egressOnly := workerSystem("127.0.0.1:8080", "", "/data", "/data")
	if !strings.HasPrefix(egressOnly, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker egress-only branch body: %q", egressOnly)
	}
	if strings.Contains(egressOnly, "traffic_search") {
		t.Fatalf("worker without recording must NOT inject trafficTool: %q", egressOnly)
	}
	noProxy := workerSystem("", "", "/data", "/data")
	if !strings.HasPrefix(noProxy, "手动") {
		t.Fatalf("worker no-proxy branch body: %q", noProxy)
	}
	if strings.Contains(noProxy, "traffic_search") {
		t.Fatalf("worker without proxy must NOT inject trafficTool: %q", noProxy)
	}
}

// TestToolboxSpecSurvivesOverride 锁定工具箱规约段 [F] 的位置：它是代码-owned 尾巴，
// 用户改 DB 提示词也不能把它冲掉——否则换个提示词，模型就会忘掉"先用手边工具"。
func TestToolboxSpecSurvivesOverride(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = func(k string) (string, bool) { return "CUSTOM BODY", true }

	got := workerSystem("", "", "/data", "/data")
	if !strings.Contains(got, "工具箱使用规约") {
		t.Fatalf("worker 提示词被 DB 覆盖后丢了工具箱段: %q", got)
	}
	for _, want := range []string{"ffuf", "gobuster", "dirb", "whatweb", "nuclei", "wapiti", "sqlmap", "hydra", "subfinder", "masscan", "/opt/artex/wordlists/", "create_custom_tool", "/app/data/tools/"} {
		if !strings.Contains(got, want) {
			t.Fatalf("工具箱段缺少 %q（提示词：%q）", want, got)
		}
	}
	for _, absent := range []string{"httpx", "dnsx", "katana"} {
		if strings.Contains(got, absent) {
			t.Fatalf("提示词提到了镜像里没装的工具 %q，会让 agent 撞空", absent)
		}
	}
	if strings.Index(got, "中间产物输出规约") > strings.Index(got, "工具箱使用规约") {
		t.Fatalf("工具箱段应在等待规约之后、进度留痕之前，顺序错了: %q", got)
	}

	main := mainAgentSystem("目标", "/data", "/data")
	if !strings.Contains(main, "工具箱使用规约") {
		t.Fatalf("main agent 提示词也应带工具箱段: %q", main)
	}
}
