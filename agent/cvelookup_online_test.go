package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/cveonline"
)

// onlineSection 取一次出参里的 online 段（没有就返回 nil）。
func onlineSection(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	v, ok := out["online"]
	if !ok {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("online 段不是对象: %T", v)
	}
	return m
}

// ① 总开关关闭 + 本地零命中 → online 段 enabled:false，且**一次网络请求都不发**。
// 这里给一个必然连不上的代理，如果真发了请求，测试会明显变慢甚至报别的错。
func TestCVEOnlineDisabledWhenSwitchOff(t *testing.T) {
	cveFixture(t) // 只有两条模板；查一个库里没有的 CVE
	ts := NewToolSet(nil, "")
	// 不调用 SetCVEOnline → 零值 Opts，Enabled=false

	out := callCVE(t, ts, map[string]any{"cve": "CVE-2026-00001"})
	if n := out["count"].(float64); n != 0 {
		t.Fatalf("本地应零命中，得到 %v", n)
	}
	online := onlineSection(t, out)
	if online == nil {
		t.Fatal("本地零命中时必须给出 online 段（哪怕只是 enabled:false）")
	}
	if online["enabled"] != false {
		t.Fatalf("关闭状态下 enabled 应为 false: %v", online)
	}
	if online["items"] != nil {
		t.Fatal("关闭状态下不该有任何在线结果")
	}
	if s, _ := online["hint"].(string); !strings.Contains(s, "设置") {
		t.Fatalf("关闭时应告诉模型去哪里打开: %q", s)
	}
}

// ② 开关打开但本次显式 online=off → 不发请求，且说明是本次调用指定的。
func TestCVEOnlineRespectsPerCallOff(t *testing.T) {
	cveFixture(t)
	ts := NewToolSet(nil, "")
	ts.SetCVEOnline(cveonline.Opts{Enabled: true, Sources: []string{cveonline.SourceNVD}})

	out := callCVE(t, ts, map[string]any{"cve": "CVE-2026-00001", "online": "off"})
	online := onlineSection(t, out)
	if online == nil {
		t.Fatal("应给出 online 段")
	}
	if online["enabled"] != true {
		t.Fatalf("总开关是开的，enabled 应为 true: %v", online)
	}
	if s, _ := online["skipped"].(string); !strings.Contains(s, "online=off") {
		t.Fatalf("应说明是本次调用指定的 off: %v", online)
	}
}

// ③ 开关打开 + 上游不可达 → 工具本身不报错，online 段如实标 ok:false。
// 用已取消的 ctx 模拟"网络这一层完全不通"，不依赖真实网络。
func TestCVEOnlineFailureDoesNotBreakTool(t *testing.T) {
	cveFixture(t)
	ts := NewToolSet(nil, "")
	ts.SetCVEOnline(cveonline.Opts{Enabled: true, Sources: []string{cveonline.SourceNVD}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	in := []byte(`{"cve":"CVE-2026-00001"}`)
	res, err := ts.cveLookup().Call(ctx, in, nil)
	if err != nil {
		t.Fatalf("在线失败不该让工具返回 error: %v", err)
	}
	body := res.Flatten()
	if !strings.Contains(body, `"online"`) {
		t.Fatalf("出参缺 online 段: %s", body)
	}
	// 本地零命中 + 在线失败 → 仍要有 hint 告诉模型下一步怎么办。
	if !strings.Contains(body, "hint") {
		t.Fatalf("本地零命中且在线失败时仍应给 hint: %s", body)
	}
}

// ④ 本地命中时默认不查在线（省额度、降延迟）：出参里不该出现 online 段。
func TestCVEOnlineNotQueriedWhenLocalHits(t *testing.T) {
	cveFixture(t)
	ts := NewToolSet(nil, "")
	ts.SetCVEOnline(cveonline.Opts{Enabled: true, Sources: []string{cveonline.SourceNVD}})

	out := callCVE(t, ts, map[string]any{"cve": "CVE-2021-41773"})
	if n := out["count"].(float64); n != 1 {
		t.Fatalf("本地应命中 1 条，得到 %v", n)
	}
	if onlineSection(t, out) != nil {
		t.Fatal("本地命中时默认不该查在线（online=auto 的语义）")
	}
}
