package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/cveidx"
)

// cveFixture 造一个只含两条模板的临时库，避免测试依赖镜像里的 1.4 万个模板。
func cveFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cves := filepath.Join(dir, "http", "cves", "2021")
	if err := os.MkdirAll(cves, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	files := map[string]string{
		"CVE-2021-41773.yaml": `
id: CVE-2021-41773
info:
  name: Apache 2.4.49 - Path Traversal
  severity: high
  classification:
    cve-id:
      - CVE-2021-41773
    cvss-score: 7.5
    cpe: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
  metadata:
    verified: true
    vendor: apache
    product: http_server
`,
		"CVE-2024-4577.yaml": `
id: CVE-2024-4577
info:
  name: PHP - CGI Argument Injection
  severity: critical
  classification:
    cve-id:
      - CVE-2024-4577
    cvss-score: 9.8
  metadata:
    verified: true
    vendor: php
    product: php
`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(cves, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	t.Setenv("ARTEX_NUCLEI_TEMPLATES_DIR", dir)
	cveidx.Invalidate()
	t.Cleanup(cveidx.Invalidate)
	return dir
}

// callCVE 走一遍工具的真实调用路径并解出 JSON 出参。
func callCVE(t *testing.T, ts *ToolSet, args map[string]any) map[string]any {
	t.Helper()
	in, _ := json.Marshal(args)
	tool := ts.cveLookup()
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("出参不是 JSON: %v / %s", err, res.Flatten())
	}
	return out
}

func TestCVELookupByCVE(t *testing.T) {
	cveFixture(t)
	ts := NewToolSet(nil, "")

	out := callCVE(t, ts, map[string]any{"cve": "cve-2021-41773"})
	if out["available"] != true {
		t.Fatalf("应可用: %v", out)
	}
	if got := out["count"].(float64); got != 1 {
		t.Fatalf("应命中 1 条，得到 %v", got)
	}
	items := out["items"].([]any)
	item := items[0].(map[string]any)

	next, _ := item["next"].(string)
	// 两条硬约束：必须用 -t 绝对路径（-id 单独用会报 no templates provided），
	// 必须 -jsonl 落盘（否则结果进不了证据链）。
	if !strings.Contains(next, "nuclei -t '") {
		t.Fatalf("next 必须用 -t 加引号的绝对路径: %q", next)
	}
	if !strings.Contains(next, "-jsonl") || !strings.Contains(next, "-o cve-CVE-2021-41773.jsonl") {
		t.Fatalf("next 必须带 -jsonl 落盘: %q", next)
	}
	if !strings.Contains(next, "/http/cves/2021/CVE-2021-41773.yaml") {
		t.Fatalf("next 应带模板绝对路径: %q", next)
	}
	if _, ok := out["evidence_rule"]; !ok {
		t.Fatal("有结果时必须给出证据规则（jsonl 的 request/response 才是证据）")
	}
	if item["cve"] != "CVE-2021-41773" || item["severity"] != "high" {
		t.Fatalf("条目字段不对: %v", item)
	}
}

func TestCVELookupProductVersionlessIsCapped(t *testing.T) {
	cveFixture(t)
	ts := NewToolSet(nil, "")

	// 无版本号的组件名查询：即使传大 limit 也要被压到 10 以内，并标注版本未知。
	out := callCVE(t, ts, map[string]any{"product": "apache", "limit": 99})
	if out["version_unknown"] != true {
		t.Fatalf("无版本号时必须标注 version_unknown: %v", out)
	}
	if hint, _ := out["hint"].(string); !strings.Contains(hint, "版本") {
		t.Fatalf("应提示先确认版本: %q", hint)
	}

	// 带版本号的查询不触发这条限制。
	out2 := callCVE(t, ts, map[string]any{"product": "apache 2.4.49"})
	if out2["version_unknown"] == true {
		t.Fatal("带版本号时不该标注 version_unknown")
	}
}

func TestCVELookupNotFoundGivesFallbackHint(t *testing.T) {
	cveFixture(t)
	ts := NewToolSet(nil, "")

	out := callCVE(t, ts, map[string]any{"cve": "CVE-1999-0001"})
	if got := out["count"].(float64); got != 0 {
		t.Fatalf("不该命中: %v", out)
	}
	hint, _ := out["hint"].(string)
	if !strings.Contains(hint, "web_search") {
		t.Fatalf("无结果时应指向 web_search 兜底: %q", hint)
	}
}

func TestCVELookupDegradesWhenTemplatesMissing(t *testing.T) {
	t.Setenv("ARTEX_NUCLEI_TEMPLATES_DIR", filepath.Join(t.TempDir(), "missing"))
	cveidx.Invalidate()
	t.Cleanup(cveidx.Invalidate)

	ts := NewToolSet(nil, "")
	out := callCVE(t, ts, map[string]any{"cve": "CVE-2021-41773"})
	if out["available"] != false {
		t.Fatalf("模板目录缺失时应降级为 available:false，而不是报错: %v", out)
	}
	if _, ok := out["reason"]; !ok {
		t.Fatal("降级时应给出 reason")
	}
}

func TestCVELookupRequiresOneArg(t *testing.T) {
	cveFixture(t)
	ts := NewToolSet(nil, "")
	in, _ := json.Marshal(map[string]any{})
	res, err := ts.cveLookup().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("不该返回 error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("空入参应报错: %s", res.Flatten())
	}
}

func TestHasVersionToken(t *testing.T) {
	cases := map[string]bool{
		"nginx 1.24.0":   true,
		"PHP 8.1.29":     true,
		"apache":         false,
		"Next.js App":    false,
		"nginx 1.24.0-1": true,
		"v2.4.49":        true,
	}
	for in, want := range cases {
		if got := hasVersionToken(in); got != want {
			t.Fatalf("hasVersionToken(%q)=%v，应为 %v", in, got, want)
		}
	}
}
