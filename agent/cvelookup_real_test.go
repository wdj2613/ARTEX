package agent

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/cveidx"
)

// TestCVELookupRealLibrary 用镜像里那套真实模板库（1.4 万条）走一遍工具的真实调用路径，
// 把出参原样打出来。默认 skip——测试不能依赖镜像。
//
//	ARTEX_CVEIDX_REAL=/path/to/nuclei-templates go test ./agent/ -run TestCVELookupRealLibrary -v
func TestCVELookupRealLibrary(t *testing.T) {
	dir := os.Getenv("ARTEX_CVEIDX_REAL")
	if dir == "" {
		t.Skip("设置 ARTEX_CVEIDX_REAL 指向真实模板库才会跑")
	}
	t.Setenv("ARTEX_NUCLEI_TEMPLATES_DIR", dir)
	cveidx.Invalidate()
	t.Cleanup(cveidx.Invalidate)

	ts := NewToolSet(nil, "")

	// ① 按 CVE 精确查：零噪声，必须恰好命中一条，且 next 指向真实存在的模板文件。
	out := callCVE(t, ts, map[string]any{"cve": "CVE-2021-41773"})
	if out["available"] != true {
		t.Fatalf("索引应可用: %v", out)
	}
	if n := out["count"].(float64); n != 1 {
		t.Fatalf("按 CVE 精确查应命中 1 条，得到 %v", n)
	}
	item := out["items"].([]any)[0].(map[string]any)
	next := item["next"].(string)
	if !strings.Contains(next, "nuclei -t '") || !strings.Contains(next, "-jsonl") {
		t.Fatalf("next 不合规: %q", next)
	}
	path := strings.SplitN(strings.SplitN(next, "'", 3)[1], "'", 2)[0]
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		t.Fatalf("next 里的模板路径不可用: %q err=%v", path, err)
	}
	pretty, _ := json.MarshalIndent(out, "", "  ")
	t.Logf("① 按 CVE 查 CVE-2021-41773（模板总数 %v / 带 CVE %v）:\n%s",
		out["template_count"], out["cve_template_count"], pretty)

	// ② 无版本号的组件名查：必须收窄条数并打 version_unknown 标记，
	//    防止把「Apache」这条产品线一百多个历史 CVE 倒进 worker 上下文。
	out2 := callCVE(t, ts, map[string]any{"product": "apache"})
	if out2["version_unknown"] != true {
		t.Fatalf("无版本号查询必须打 version_unknown: %v", out2["version_unknown"])
	}
	if n := out2["count"].(float64); n > 3 {
		t.Fatalf("无版本号默认应只给 3 条，得到 %v", n)
	}
	seen := map[string]bool{}
	for _, it := range out2["items"].([]any) {
		cve := it.(map[string]any)["cve"].(string)
		if seen[cve] {
			t.Fatalf("同一 CVE 重复出现: %s", cve)
		}
		seen[cve] = true
	}
	t.Logf("② 无版本 product=apache → %v 条: %v", out2["count"], seen)

	// ③ 查不到的组件必须优雅降级（给 hint，不是错误）。
	out3 := callCVE(t, ts, map[string]any{"product": "kingsoft-wps-nonexistent"})
	if out3["available"] != true {
		t.Fatalf("查不到不该让索引不可用: %v", out3)
	}
	if out3["count"].(float64) != 0 || out3["hint"] == nil {
		t.Fatalf("零命中应带 hint: %v", out3)
	}
	t.Logf("③ 无覆盖组件降级 normal：count=%v hint=有", out3["count"])
}
