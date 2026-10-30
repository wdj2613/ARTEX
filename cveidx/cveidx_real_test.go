package cveidx

import (
	"os"
	"testing"
	"time"
)

// TestLoadRealLibrary 用真实模板库跑一遍解析与查询。默认 skip：不把镜像里的
// 1.4 万个模板变成测试依赖。想验就指一个真实目录：
//
//	CVEIDX_REAL_DIR=/path/to/nuclei-templates go test ./cveidx/ -run TestLoadRealLibrary -v
func TestLoadRealLibrary(t *testing.T) {
	dir := os.Getenv("CVEIDX_REAL_DIR")
	if dir == "" {
		t.Skip("设置 CVEIDX_REAL_DIR 指向真实模板库才会跑")
	}
	start := time.Now()
	idx, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	elapsed := time.Since(start)
	t.Logf("模板=%d 带CVE=%d 耗时=%s", idx.TemplateNum, idx.WithCVENum, elapsed.Round(time.Millisecond))

	if idx.TemplateNum < 1000 {
		t.Fatalf("真实库模板数应远超 1000，得到 %d（目录指错了？）", idx.TemplateNum)
	}
	if idx.WithCVENum < 1000 {
		t.Fatalf("真实库带 CVE 的模板应远超 1000，得到 %d", idx.WithCVENum)
	}

	// 抽查一条已知 CVE：字段必须解析出来，路径必须是绝对路径且文件真实存在。
	e, ok := idx.LookupCVE("CVE-2021-41773")
	if !ok {
		t.Fatal("真实库里查不到 CVE-2021-41773（解析器可能漏了 http/cves 这类子目录）")
	}
	t.Logf("CVE-2021-41773: sev=%s cvss=%.1f verified=%v vendor=%s product=%s path=%s",
		e.Severity, e.CVSS, e.Verified, e.Vendor, e.Product, e.Path)
	if e.CVSS == 0 || e.Severity == "" {
		t.Fatalf("CVE-2021-41773 的关键字段没解析出来: %+v", e)
	}
	if st, err := os.Stat(e.Path); err != nil || st.IsDir() {
		t.Fatalf("模板路径不可用（next 命令会失败）: %q err=%v", e.Path, err)
	}

	// 按组件名查（模拟指纹出 "Apache"）：必须给出候选，且 verified 排在前面。
	hits := idx.Search(SearchOpts{Product: "apache", Limit: 5})
	if len(hits) == 0 {
		t.Fatal("按组件名 apache 查不到候选")
	}
	if !hits[0].Verified {
		t.Fatalf("首条候选应是 verified:true，得到 %+v", hits[0])
	}
	t.Logf("product=apache 前 %d 条: %s / %s / %s", len(hits), hits[0].CVE, hits[1].CVE, hits[2].CVE)

	// CPE 前缀查询。
	if cpeHits := idx.Search(SearchOpts{CPE: "cpe:2.3:a:apache:http_server", Limit: 5}); len(cpeHits) == 0 {
		t.Fatal("CPE 前缀查询没命中")
	}

	if elapsed > 30*time.Second {
		t.Fatalf("索引构建太慢（%s），首次调用会把 worker 卡住", elapsed)
	}
}
