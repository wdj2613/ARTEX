package cveonline

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestLookupRealSources 打真实情报源跑一遍。默认 skip——CI 不该依赖外网。
//
//	CVEONLINE_REAL=1 go test ./cveonline/ -run TestLookupRealSources -v
//
// 可选环境变量：NVD_KEY / GH_TOKEN / CVEONLINE_PROXY（隔离网用代理出口）。
func TestLookupRealSources(t *testing.T) {
	if os.Getenv("CVEONLINE_REAL") == "" {
		t.Skip("设置 CVEONLINE_REAL=1 才会打真实情报源")
	}
	opts := Opts{
		Enabled:     true,
		Sources:     append([]string{}, DefaultSources...),
		NVDKey:      os.Getenv("NVD_KEY"),
		GitHubToken: os.Getenv("GH_TOKEN"),
		Proxy:       os.Getenv("CVEONLINE_PROXY"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	start := time.Now()
	res, err := Lookup(ctx, opts, Query{CVE: "CVE-2021-41773"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	t.Logf("耗时 %s / 命中 %d 条 / 源状态 %+v / 降级 %v",
		time.Since(start).Round(time.Millisecond), len(res.Hits), res.Sources, res.Degraded)

	if len(res.Hits) == 0 {
		t.Fatalf("真实源应能查到 CVE-2021-41773: %+v", res.Sources)
	}
	h := res.Hits[0]
	pretty, _ := json.MarshalIndent(h, "", "  ")
	t.Logf("合并结果:\n%s", pretty)

	if h.CVSS < 7 {
		t.Errorf("CVE-2021-41773 的 CVSS 应 >= 7，得到 %v（NVD 解析可能坏了）", h.CVSS)
	}
	if !h.KEV {
		t.Error("CVE-2021-41773 在 CISA KEV 里，应被标 kev:true")
	}
	if h.EPSS <= 0 {
		t.Error("EPSS 应取到值")
	}
	if len(h.Affected) == 0 {
		t.Error("受影响版本区间应解析出来")
	}
	if h.PocCount == 0 {
		t.Error("GitHub PoC 搜索应命中（该 CVE 有上百个仓库）")
	}
	if len(h.Refs) == 0 {
		t.Error("参考链接应解析出来")
	}

	// 按组件名（真实 NVD keywordSearch）+ 缓存命中。
	res2, err := Lookup(ctx, opts, Query{Product: "apache http server", Limit: 3})
	if err != nil {
		t.Fatalf("组件名检索: %v", err)
	}
	t.Logf("组件名检索命中 %d 条: %v", len(res2.Hits), func() []string {
		out := make([]string, 0, len(res2.Hits))
		for _, x := range res2.Hits {
			out = append(out, x.CVE)
		}
		return out
	}())
	if len(res2.Hits) == 0 {
		t.Error("组件名检索应至少命中一条")
	}
}
