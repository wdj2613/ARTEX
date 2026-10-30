package cveidx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTpl 在 dir 下写一个模板文件。
func writeTpl(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// fixtureDir 造一个最小模板库：一条 cve-id 数组、一条 cve-id 标量、一条无 CVE 的
// 暴露面模板、一条畸形 yaml（验证不会让整份索引失败）。
func fixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTpl(t, filepath.Join(dir, "http", "cves", "2021"), "CVE-2021-41773.yaml", `
id: CVE-2021-41773
info:
  name: Apache 2.4.49 - Path Traversal and Remote Code Execution
  severity: high
  tags: cve,cve2021,lfi,apache
  classification:
    cve-id:
      - CVE-2021-41773
    cvss-score: 7.5
    epss-score: 0.99992
    cpe: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
  metadata:
    verified: true
    vendor: apache
    product: http_server
`)
	// cve-id 写成标量（真实模板库里确实存在这种写法），且 cvss 写成字符串。
	writeTpl(t, filepath.Join(dir, "http", "cves", "2024"), "CVE-2024-4577.yaml", `
id: CVE-2024-4577
info:
  name: PHP < 8.1.29 - CGI Argument Injection
  severity: critical
  classification:
    cve-id: CVE-2024-4577
    cvss-score: "9.8"
    cpe: cpe:2.3:a:php:php:*:*:*:*:*:*:*:*
  metadata:
    verified: true
    vendor: php
    product: php
`)
	// 没有 CVE 号的暴露面模板：按产品名检索时仍应有价值。
	writeTpl(t, filepath.Join(dir, "http", "exposures"), "nginx-status.yaml", `
id: nginx-status
info:
  name: Nginx Status Page Exposure
  severity: low
  metadata:
    vendor: nginx
    product: nginx
`)
	// 畸形模板：必须被跳过而不是让整份索引失败。
	writeTpl(t, filepath.Join(dir, "http"), "broken.yaml", "id: [unclosed\n  info: {{{\n")
	return dir
}

func TestLoadAndLookupCVE(t *testing.T) {
	idx, err := Load(fixtureDir(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if idx.TemplateNum != 4 {
		t.Fatalf("模板数应为 4，得到 %d", idx.TemplateNum)
	}
	if idx.WithCVENum != 2 {
		t.Fatalf("带 CVE 的应为 2 条，得到 %d", idx.WithCVENum)
	}

	e, ok := idx.LookupCVE("cve-2021-41773") // 大小写不敏感
	if !ok {
		t.Fatal("按小写 CVE 号没查到")
	}
	if e.Severity != "high" || e.CVSS != 7.5 || !e.Verified {
		t.Fatalf("字段解析错误: %+v", e)
	}
	if e.Vendor != "apache" || e.Product != "http_server" {
		t.Fatalf("vendor/product 解析错误: %+v", e)
	}
	if e.Path == "" || !filepath.IsAbs(e.Path) {
		t.Fatalf("模板路径必须是绝对路径（next 命令依赖它）: %q", e.Path)
	}
	if e.Year != 2021 {
		t.Fatalf("年份解析错误: %d", e.Year)
	}

	// 标量 cve-id + 字符串 cvss 也要能解析。
	e2, ok := idx.LookupCVE("CVE-2024-4577")
	if !ok {
		t.Fatal("标量写法的 cve-id 没解析出来")
	}
	if e2.CVSS != 9.8 {
		t.Fatalf("字符串形式的 cvss-score 没解析: %v", e2.CVSS)
	}
}

func TestSearchByProductAndVerified(t *testing.T) {
	idx, err := Load(fixtureDir(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// 按 product 名命中（"http_server" 归一化后也能被 "http server" 命中）。
	if got := idx.Search(SearchOpts{Product: "apache", Limit: 10}); len(got) == 0 {
		t.Fatal("按 vendor 名 apache 没查到")
	}
	if got := idx.Search(SearchOpts{Product: "http server", Limit: 10}); len(got) == 0 {
		t.Fatal("归一化后 \"http server\" 没命中 http_server")
	}

	// verified 过滤：nginx-status 没有 verified，必须被排除。
	got := idx.Search(SearchOpts{Product: "nginx", Verified: true, Limit: 10})
	if len(got) != 0 {
		t.Fatalf("verified 过滤失效，仍返回 %d 条", len(got))
	}
	if got := idx.Search(SearchOpts{Product: "nginx", Limit: 10}); len(got) != 1 {
		t.Fatalf("不过滤时应返回 1 条 nginx-status，得到 %d", len(got))
	}

	// CPE 前缀查询。
	if got := idx.Search(SearchOpts{CPE: "cpe:2.3:a:php:php", Limit: 10}); len(got) != 1 || got[0].CVE != "CVE-2024-4577" {
		t.Fatalf("CPE 前缀查询结果不对: %+v", got)
	}

	// limit 截断。
	if got := idx.Search(SearchOpts{Product: "apache", Limit: 0}); len(got) == 0 {
		t.Fatal("limit=0 应表示不限")
	}
}

func TestSearchSortsVerifiedFirst(t *testing.T) {
	idx, err := Load(fixtureDir(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := idx.Search(SearchOpts{Product: "apache", Limit: 10})
	if len(got) == 0 {
		t.Fatal("没有候选")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Verified != got[i].Verified && !got[i-1].Verified {
			t.Fatal("排序错误：verified 条目应排在前面")
		}
	}
}

// 一个 CVE 在真实库里有多个模板（Log4Shell 三条），必须只出一条，且保留最好的那条。
func TestDedupeByCVEKeepsBest(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "network", "cves", "2021")
	writeTpl(t, base, "log4shell-a.yaml", `
id: CVE-2021-44228
info:
  name: Log4Shell (network variant)
  severity: critical
  classification:
    cve-id:
      - CVE-2021-44228
    cvss-score: 10
  metadata:
    vendor: apache
    product: log4j
`)
	// 同名 CVE 的 http 变体：verified + 同分，应优先选它（jsonl 里 request/response 都全）。
	writeTpl(t, filepath.Join(dir, "http", "cves", "2021"), "log4shell-b.yaml", `
id: CVE-2021-44228
info:
  name: Log4Shell (http variant)
  severity: critical
  classification:
    cve-id:
      - CVE-2021-44228
    cvss-score: 10
  metadata:
    verified: true
    vendor: apache
    product: log4j
`)
	idx, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if idx.WithCVENum != 1 {
		t.Fatalf("同一 CVE 的两个模板应合成 1 条，得到 %d", idx.WithCVENum)
	}
	e, ok := idx.LookupCVE("CVE-2021-44228")
	if !ok {
		t.Fatal("查不到 CVE-2021-44228")
	}
	if !e.Verified || !strings.Contains(e.Path, "/http/") {
		t.Fatalf("应保留 verified 且 http 变体，实际: %+v", e)
	}
	got := idx.Search(SearchOpts{Product: "log4j", Limit: 10})
	if len(got) != 1 {
		t.Fatalf("按产品名检索也应去重成 1 条，得到 %d", len(got))
	}
}

func TestLoadMissingDirDegrades(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Fatal("空目录应返回错误（调用方据此降级为 available:false）")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("不存在的目录应返回错误")
	}
}

func TestResolveDirHonorsEnv(t *testing.T) {
	dir := fixtureDir(t)
	t.Setenv("ARTEX_NUCLEI_TEMPLATES_DIR", dir)
	if got := ResolveDir(); got != dir {
		t.Fatalf("环境变量未生效: %q != %q", got, dir)
	}
}

func TestGetCachesAndInvalidate(t *testing.T) {
	dir := fixtureDir(t)
	t.Setenv("ARTEX_NUCLEI_TEMPLATES_DIR", dir)
	Invalidate()
	t.Cleanup(Invalidate)

	a, err := Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	b, _ := Get()
	if a != b {
		t.Fatal("第二次 Get 应命中缓存（同一指针）")
	}

	// 新增一个模板后，不 Invalidate 看不到；Invalidate 之后能看到。
	writeTpl(t, filepath.Join(dir, "http", "cves", "2025"), "CVE-2025-0001.yaml", `
id: CVE-2025-0001
info:
  name: Demo Product 1.0 - RCE
  severity: high
  classification:
    cve-id:
      - CVE-2025-0001
  metadata:
    verified: true
    vendor: demo
    product: demo
`)
	if _, ok := b.LookupCVE("CVE-2025-0001"); ok {
		t.Fatal("未 Invalidate 前不该看到新模板")
	}
	Invalidate()
	c, err := Get()
	if err != nil {
		t.Fatalf("Invalidate 后 Get: %v", err)
	}
	if _, ok := c.LookupCVE("CVE-2025-0001"); !ok {
		t.Fatal("Invalidate 之后应能看到新模板")
	}
}
