package cveonline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSources 把所有源指向同一个 httptest 服务，按路径分派。
// 返回计数器，便于断言"某源根本没被请求"。
type calls struct {
	nvd, osv, github, epss int32
}

func (c *calls) total() int32 { return c.nvd + c.osv + c.github + c.epss }

func fakeSources(t *testing.T, h func(w http.ResponseWriter, r *http.Request, c *calls)) *calls {
	t.Helper()
	c := &calls{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/nvd"):
			atomic.AddInt32(&c.nvd, 1)
			r.URL.Path = "/nvd"
		case strings.HasPrefix(r.URL.Path, "/osv/"):
			atomic.AddInt32(&c.osv, 1)
			r.URL.Path = "/osv"
		case strings.HasPrefix(r.URL.Path, "/github"):
			atomic.AddInt32(&c.github, 1)
			r.URL.Path = "/github"
		case strings.HasPrefix(r.URL.Path, "/epss"):
			atomic.AddInt32(&c.epss, 1)
			r.URL.Path = "/epss"
		}
		h(w, r, c)
	}))
	t.Cleanup(srv.Close)

	oldNVD, oldOSV, oldGH, oldEPSS := nvdBase, osvBase, githubBase, epssBase
	oldTO, oldTTL := PerSourceTimeout, CacheTTL
	nvdBase, osvBase = srv.URL+"/nvd", srv.URL+"/osv/"
	githubBase, epssBase = srv.URL+"/github", srv.URL+"/epss"
	PerSourceTimeout = 500 * time.Millisecond
	CacheTTL = time.Minute
	Invalidate()
	t.Cleanup(func() {
		nvdBase, osvBase, githubBase, epssBase = oldNVD, oldOSV, oldGH, oldEPSS
		PerSourceTimeout, CacheTTL = oldTO, oldTTL
		Invalidate()
	})
	return c
}

const nvdOK = `{"totalResults":1,"vulnerabilities":[{"cve":{
 "id":"CVE-2021-41773","published":"2021-10-05T00:00:00.000","vulnStatus":"Analyzed",
 "cisaExploitAdd":"2021-11-03","cisaVulnerabilityName":"Apache HTTP Server Path Traversal",
 "descriptions":[{"lang":"es","value":"ignorar"},{"lang":"en","value":"Path traversal in Apache 2.4.49."}],
 "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]},
 "weaknesses":[{"description":[{"value":"CWE-22"}]}],
 "configurations":[{"nodes":[{"cpeMatch":[
   {"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
   {"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "versionStartIncluding":"2.4.0","versionEndExcluding":"2.4.51"}]}]}],
 "references":[{"url":"https://example.com/a"},{"url":"https://example.com/b"}]
}}]}`

const osvOK = `{"id":"CVE-2021-41773","summary":"","affected":[
 {"package":{"ecosystem":"Debian","name":"apache2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.4.51"}]}]}]}`

const ghOK = `{"total_count":185,"items":[
 {"full_name":"blasty/CVE-2021-41773","html_url":"https://github.com/blasty/x","stargazers_count":42},
 {"full_name":"b/x","html_url":"https://github.com/b/x","stargazers_count":0},
 {"full_name":"c/x","html_url":"https://github.com/c/x","stargazers_count":0},
 {"full_name":"d/x","html_url":"https://github.com/d/x","stargazers_count":0}]}`

const epssOK = `{"data":[{"cve":"CVE-2021-41773","epss":"0.97","percentile":"0.99"}]}`

func okHandler(w http.ResponseWriter, r *http.Request, c *calls) {
	switch r.URL.Path {
	case "/nvd":
		w.Write([]byte(nvdOK))
	case "/osv":
		w.Write([]byte(osvOK))
	case "/github":
		w.Write([]byte(ghOK))
	case "/epss":
		w.Write([]byte(epssOK))
	}
}

func onOpts() Opts {
	return Opts{Enabled: true, Sources: append([]string{}, DefaultSources...)}
}

// ① 关闭时完全不出网。
func TestLookupDisabledNeverCallsNetwork(t *testing.T) {
	c := fakeSources(t, okHandler)
	_, err := Lookup(context.Background(), Opts{Enabled: false}, Query{CVE: "CVE-2021-41773"})
	if err != ErrDisabled {
		t.Fatalf("应返回 ErrDisabled，得到 %v", err)
	}
	if c.total() != 0 {
		t.Fatalf("关闭状态下不该有任何出网请求，实际 %d 次", c.total())
	}
}

// ② 全源正常：四个源的数据要合并进一条 hit。
func TestLookupByCVEHappyPath(t *testing.T) {
	fakeSources(t, okHandler)
	res, err := Lookup(context.Background(), onOpts(), Query{CVE: "cve-2021-41773"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("应合并成 1 条，得到 %d（sources=%+v）", len(res.Hits), res.Sources)
	}
	h := res.Hits[0]
	if h.CVE != "CVE-2021-41773" {
		t.Fatalf("CVE 号应大写归一: %q", h.CVE)
	}
	if h.CVSS != 7.5 || h.Severity != "high" {
		t.Fatalf("CVSS/severity 解析错: %v %v", h.CVSS, h.Severity)
	}
	if !h.KEV || h.KEVName == "" {
		t.Fatalf("CISA KEV 没解析出来: %+v", h)
	}
	if h.Summary != "Path traversal in Apache 2.4.49." {
		t.Fatalf("应取 en 描述，得到 %q", h.Summary)
	}
	if h.EPSS != 0.97 {
		t.Fatalf("EPSS 没合并: %v", h.EPSS)
	}
	if h.PocCount != 185 || len(h.PocSamples) != 3 {
		t.Fatalf("PoC 数/样例不对: count=%d samples=%d", h.PocCount, len(h.PocSamples))
	}
	if len(h.Affected) < 2 {
		t.Fatalf("版本区间应同时有精确版本和区间两种形式: %v", h.Affected)
	}
	joined := strings.Join(h.Affected, " | ")
	if !strings.Contains(joined, "= 2.4.49") || !strings.Contains(joined, "< 2.4.51") {
		t.Fatalf("版本区间文本不对: %s", joined)
	}
	if !strings.Contains(joined, "Debian apache2") {
		t.Fatalf("OSV 的生态包名没合并进来: %s", joined)
	}
	if len(h.CWE) != 1 || h.CWE[0] != "CWE-22" {
		t.Fatalf("CWE 不对: %v", h.CWE)
	}
	for _, want := range []string{SourceNVD, SourceOSV, SourceGitHub, SourceEPSS} {
		if !containsStr(h.Sources, want) {
			t.Fatalf("sources 缺 %s: %v", want, h.Sources)
		}
	}
}

// ③ 开开关但两个 key 都没配 → 仍能查，只标 degraded。
func TestLookupNoKeysStillWorks(t *testing.T) {
	fakeSources(t, okHandler)
	res, err := Lookup(context.Background(), onOpts(), Query{CVE: "CVE-2021-41773"})
	if err != nil {
		t.Fatalf("缺 key 不该报错: %v", err)
	}
	if len(res.Hits) != 1 {
		t.Fatal("缺 key 仍应拿到结果")
	}
	deg := strings.Join(res.Degraded, " ")
	if !strings.Contains(deg, "nvd:no_key") || !strings.Contains(deg, "github:no_token") {
		t.Fatalf("degraded 应如实标注两个缺 key: %v", res.Degraded)
	}
}

// ④ 部分配置：只配 NVD key → NVD 请求带 apiKey 头，GitHub 仍走未认证并标注。
func TestLookupPartialConfigSendsNVDKey(t *testing.T) {
	var gotAPIKey, gotAuth string
	fakeSources(t, func(w http.ResponseWriter, r *http.Request, c *calls) {
		if r.URL.Path == "/nvd" {
			gotAPIKey = r.Header.Get("apiKey")
		}
		if r.URL.Path == "/github" {
			gotAuth = r.Header.Get("Authorization")
		}
		okHandler(w, r, c)
	})
	o := onOpts()
	o.NVDKey = "nvd-key-123"
	res, err := Lookup(context.Background(), o, Query{CVE: "CVE-2021-41773"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if gotAPIKey != "nvd-key-123" {
		t.Fatalf("NVD 请求应带 apiKey 头，实际 %q", gotAPIKey)
	}
	if gotAuth != "" {
		t.Fatalf("没配 GitHub token 就不该带 Authorization，实际 %q", gotAuth)
	}
	if strings.Contains(strings.Join(res.Degraded, " "), "nvd:no_key") {
		t.Fatalf("已配 NVD key 不该再标 no_key: %v", res.Degraded)
	}
	if !strings.Contains(strings.Join(res.Degraded, " "), "github:no_token") {
		t.Fatalf("GitHub 未配 token 仍应标注: %v", res.Degraded)
	}
}

// ⑤ 单源超时：该源 ok:false，其它源结果照返。
func TestLookupOneSourceTimeoutOthersSurvive(t *testing.T) {
	fakeSources(t, func(w http.ResponseWriter, r *http.Request, c *calls) {
		if r.URL.Path == "/github" {
			select {
			case <-time.After(2 * time.Second): // 远超 500ms 的单源超时
			case <-r.Context().Done():
			}
			return
		}
		okHandler(w, r, c)
	})
	res, err := Lookup(context.Background(), onOpts(), Query{CVE: "CVE-2021-41773"})
	if err != nil {
		t.Fatalf("单源超时不该升级成整体错误: %v", err)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("其它源的结果应照常返回，得到 %d 条", len(res.Hits))
	}
	if res.Hits[0].CVSS != 7.5 {
		t.Fatal("NVD 数据应仍在")
	}
	found := false
	for _, s := range res.Sources {
		if s.Name == SourceGitHub {
			found = true
			if s.OK {
				t.Fatalf("GitHub 超时应标 ok:false: %+v", s)
			}
			if s.Error == "" {
				t.Fatal("失败源必须带 error 文本")
			}
		}
	}
	if !found {
		t.Fatal("失败源也要出现在 sources 里（以便模型知道降级了）")
	}
}

// ⑥ 限流：429 要识别成"限流/拒绝"，而不是笼统 500。
func TestLookupRateLimited(t *testing.T) {
	fakeSources(t, func(w http.ResponseWriter, r *http.Request, c *calls) {
		if r.URL.Path == "/nvd" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		okHandler(w, r, c)
	})
	res, _ := Lookup(context.Background(), onOpts(), Query{CVE: "CVE-2021-41773"})
	for _, s := range res.Sources {
		if s.Name == SourceNVD {
			if s.OK || !strings.Contains(s.Error, "限流") {
				t.Fatalf("429 应识别为限流: %+v", s)
			}
		}
	}
	// NVD 挂了，但 OSV/GitHub/EPSS 还在 → 仍应有一条 hit（summary 来自 OSV 的为空也无所谓）。
	if len(res.Hits) != 1 {
		t.Fatalf("其它源应兜住，得到 %d 条", len(res.Hits))
	}
	if res.Hits[0].CVSS != 0 {
		t.Fatal("NVD 失败就不该有 CVSS")
	}
}

// ⑦ 全部源失败：空结果 + 每源都标失败 + note，且不返回 error。
func TestLookupAllSourcesFail(t *testing.T) {
	fakeSources(t, func(w http.ResponseWriter, r *http.Request, c *calls) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	res, err := Lookup(context.Background(), onOpts(), Query{CVE: "CVE-2021-41773"})
	if err != nil {
		t.Fatalf("全源失败也不该返回 error（本地结果必须可用）: %v", err)
	}
	if len(res.Hits) != 0 {
		t.Fatalf("全失败应为空，得到 %d 条", len(res.Hits))
	}
	if len(res.Sources) < 3 {
		t.Fatalf("每个源都要有状态记录: %+v", res.Sources)
	}
	for _, s := range res.Sources {
		if s.OK {
			t.Fatalf("源 %s 应标失败: %+v", s.Name, s)
		}
	}
	if res.Note == "" {
		t.Fatal("空结果必须带 note 说明原因")
	}
}

// ⑧ 缓存：第二次同查询不再出网。
func TestLookupCacheAvoidsSecondCall(t *testing.T) {
	c := fakeSources(t, okHandler)
	q := Query{CVE: "CVE-2021-41773"}
	if _, err := Lookup(context.Background(), onOpts(), q); err != nil {
		t.Fatalf("首次: %v", err)
	}
	first := c.total()
	res, err := Lookup(context.Background(), onOpts(), q)
	if err != nil {
		t.Fatalf("二次: %v", err)
	}
	if !res.Cached {
		t.Fatal("第二次应命中缓存")
	}
	if c.total() != first {
		t.Fatalf("命中缓存后不该再出网: 前 %d 次, 后 %d 次", first, c.total())
	}
}

// ⑨ 按组件名：只打 NVD + EPSS，绝不打 OSV/GitHub（后者的未认证额度只有 10 次/分）。
func TestLookupByProductSkipsGitHubAndOSV(t *testing.T) {
	c := fakeSources(t, func(w http.ResponseWriter, r *http.Request, c *calls) {
		if r.URL.Path == "/nvd" {
			w.Write([]byte(`{"totalResults":2,"vulnerabilities":[
			 {"cve":{"id":"CVE-2021-44228","descriptions":[{"lang":"en","value":"Log4Shell"}],
			  "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":10,"baseSeverity":"CRITICAL"}}]}}},
			 {"cve":{"id":"CVE-2017-5638","descriptions":[{"lang":"en","value":"Struts2"}],
			  "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}},{"cvssData":{"baseScore":10,"baseSeverity":"CRITICAL"}}]}}}]}`))
			return
		}
		okHandler(w, r, c)
	})
	res, err := Lookup(context.Background(), onOpts(), Query{Product: "apache struts", Limit: 5})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if atomic.LoadInt32(&c.github) != 0 || atomic.LoadInt32(&c.osv) != 0 {
		t.Fatalf("组件名检索不该打 GitHub/OSV: github=%d osv=%d", c.github, c.osv)
	}
	if len(res.Hits) != 2 {
		t.Fatalf("应有 2 条候选，得到 %d", len(res.Hits))
	}
	if res.Hits[0].CVE != "CVE-2021-44228" {
		t.Fatalf("CVSS 10 的应排第一，得到 %s", res.Hits[0].CVE)
	}
	if !strings.Contains(res.Note, "PoC") {
		t.Fatalf("应提示要 PoC 得按 CVE 再查: %q", res.Note)
	}
}

// ⑩ 无匹配：所有源都空 → 结果为空但必须带 note。
func TestLookupNoMatch(t *testing.T) {
	fakeSources(t, func(w http.ResponseWriter, r *http.Request, c *calls) {
		switch r.URL.Path {
		case "/nvd":
			w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
		case "/osv":
			w.WriteHeader(http.StatusNotFound)
		case "/github":
			w.Write([]byte(`{"total_count":0,"items":[]}`))
		case "/epss":
			w.Write([]byte(`{"data":[]}`))
		}
	})
	res, err := Lookup(context.Background(), onOpts(), Query{CVE: "CVE-9999-00000"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(res.Hits) != 0 {
		t.Fatalf("应无命中，得到 %d", len(res.Hits))
	}
	if res.Note == "" {
		t.Fatal("无命中应带 note")
	}
}

// ⑪ 源开关真的生效：只留 osv，其余一个请求都不该发。
func TestLookupRespectsSourceSelection(t *testing.T) {
	c := fakeSources(t, okHandler)
	o := Opts{Enabled: true, Sources: []string{SourceOSV}}
	res, err := Lookup(context.Background(), o, Query{CVE: "CVE-2021-41773"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if atomic.LoadInt32(&c.nvd) != 0 || atomic.LoadInt32(&c.github) != 0 {
		t.Fatalf("未启用的源不该被请求: nvd=%d github=%d", c.nvd, c.github)
	}
	if atomic.LoadInt32(&c.osv) != 1 {
		t.Fatalf("OSV 应被请求一次，实际 %d", c.osv)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("OSV 的 affected 应能凑出一条 hit，得到 %d", len(res.Hits))
	}
}

func TestParseSources(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", DefaultSources},
		{"nvd", []string{"nvd"}},
		{"NVD, osv ,nvd", []string{"nvd", "osv"}},
		{"nvd,bogus,github", []string{"nvd", "github"}},
		{"bogus", DefaultSources}, // 全是未知值 → 回退默认，不静默变成"全关"
	}
	for _, c := range cases {
		got := ParseSources(c.in)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Fatalf("ParseSources(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
