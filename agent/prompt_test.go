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
	for _, want := range []string{"ffuf", "gobuster", "dirb", "whatweb", "nuclei", "wapiti", "sqlmap", "hydra", "subfinder", "masscan", "httpx", "dnsx", "katana", "/opt/artex/wordlists/", "create_custom_tool", "/app/data/tools/"} {
		if !strings.Contains(got, want) {
			t.Fatalf("工具箱段缺少 %q（提示词：%q）", want, got)
		}
	}
	// 反向断言：这两个镜像里确实没装，提示词不得提及（否则 agent 照着试必然撞空）。
	// 以后往镜像里加工具时，同步把这里和上面的正向列表一起改。
	for _, absent := range []string{"nikto", "hashcat"} {
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

// CVE 验证链段是代码拥有的：DB 覆盖提示词正文也不能把它丢掉，否则 agent 又会回到
// "command -v nuclei 然后手搓 curl"（线上 39602 次 Bash 调用里 nuclei 真实执行 0 次）。
func TestCVESpecSurvivesOverride(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = func(k string) (string, bool) { return "CUSTOM BODY", true }

	got := workerSystem("", "", "/data", "/data")
	if !strings.Contains(got, "已知漏洞（CVE）验证链") {
		t.Fatalf("worker 提示词被覆盖后丢了 CVE 段: %q", got)
	}
	for _, want := range []string{
		"cve_lookup",             // 触发条件指向工具
		"-jsonl",                 // 证据必须落盘
		"report_finding",         // 命中后走的上报路径
		"批量",                     // 多个候选写进同一条意图（避免被判重）
		"/root/nuclei-templates", // 模板目录口径与 Dockerfile 一致
		"在线情报",                   // 本地无模板时走在线补充
		"KEV",                    // 在线结果里最有价值的优先级信号
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("CVE 段缺少 %q（提示词：%q）", want, got)
		}
	}
	// 关键纪律必须在：CVE 匹配不等于漏洞已存在。
	if !strings.Contains(got, "不等于漏洞已存在") {
		t.Fatalf("CVE 段丢了「匹配不等于已存在」的边界: %q", got)
	}
	// 顺序：工具箱段 → CVE 段 → 进度留痕段。
	if i, j, k := strings.Index(got, "工具箱使用规约"), strings.Index(got, "已知漏洞（CVE）验证链"), strings.Index(got, "进度留痕"); !(i < j && j < k) {
		t.Fatalf("CVE 段位置不对（应在工具箱之后、进度留痕之前）: %d %d %d", i, j, k)
	}
	// main agent 不做 CVE 验证（主控不动手，nuclei 在其禁止名单里）。
	if main := mainAgentSystem("目标", "/data", "/data"); strings.Contains(main, "已知漏洞（CVE）验证链") {
		t.Fatal("main agent 不该带 CVE 验证段（它不直接对目标动手）")
	}
}

// OPSEC 准则段来自上游 RuoJi6/ARTEX，由 renderSystem 统一追加到所有角色的
// 提示词尾部（开 opsec_enabled 才注入）。它与我们自己的「工具箱使用规约」在
// “别手搓 curl”这一点上主题重叠，所以这里锁住两件事：
//  1. 段只出现一次、且位置在代码拥有的各尾段之前（不能让重复注入把提示词撑大）；
//  2. 工具箱段只讲“选哪个工具”，行为约束一律引用 OPSEC（一个真源，不许复述）。
//
// 违反任一条，两条相似但不同的约束会同时出现在一次 run 里，模型只会挑一条执行。
func TestOpsecBlockInjectedOnceAndNotDuplicated(t *testing.T) {
	t.Cleanup(func() { OpsecEnabled = nil; PromptOverride = nil })

	// 关：一个字都不该出现。
	OpsecEnabled = func() bool { return false }
	if got := workerSystem("", "", "/data", "/data"); strings.Contains(got, "【OPSEC 准则") {
		t.Fatalf("opsec 关闭时不应注入整段，got len=%d", len(got))
	}

	// 开：恰好一次，且在工具箱段之前。
	OpsecEnabled = func() bool { return true }
	got := workerSystem("", "", "/data", "/data")
	if n := strings.Count(got, "【OPSEC 准则"); n != 1 {
		t.Fatalf("OPSEC 段应恰好出现 1 次，实际 %d 次", n)
	}
	if i, j := strings.Index(got, "【OPSEC 准则"), strings.Index(got, "工具箱使用规约"); !(i >= 0 && j >= 0 && i < j) {
		t.Fatalf("OPSEC 段应在工具箱规约之前: %d %d", i, j)
	}
	// 行为约束只在 OPSEC 里出现一次，工具箱段必须引用而不是复述。
	if n := strings.Count(got, "随机轮换 User-Agent"); n != 1 {
		t.Fatalf("“随机轮换 User-Agent”应只由 OPSEC 段出现一次，实际 %d 次", n)
	}
	if !strings.Contains(got, "按 **OPSEC 准则**执行") {
		t.Fatal("工具箱段应显式引用 OPSEC 准则，而不是自己再写一套约束")
	}
	if strings.Contains(got, "不得使用 -k、--ignore-https-errors") && strings.Count(got, "证书校验") > 2 {
		t.Fatal("证书校验约束被重复表述")
	}

	// 规划者同样只注入一次（OPSEC 是全局尾段，不是 worker 专属）。
	if n := strings.Count(plannerSystem("目标", "/data", "/data"), "【OPSEC 准则"); n != 1 {
		t.Fatalf("planner OPSEC 段应恰好 1 次，实际 %d 次", n)
	}
}
