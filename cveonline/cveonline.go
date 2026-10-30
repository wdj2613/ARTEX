// Package cveonline 在线漏洞情报检索：NVD / OSV / GitHub PoC / FIRST EPSS。
//
// 与 cveidx 的分工：cveidx 是本地 nuclei 模板库（命中即有可执行验证命令），
// cveonline 是「模板还没写出来」那段时间窗口的补充——CVE 刚公布、模板库还没收录时，
// 只能靠在线源拿到版本区间、CVSS、是否已被野外利用（CISA KEV）、有没有公开 PoC。
//
// 设计上刻意保持三点：
//
//  1. **不产生可执行命令**。在线源给的是版本区间和链接，没有请求/匹配器，硬凑一条
//     next 会诱导模型以为可以直接跑。调用方拿到的只是"线索"，验证仍要自己构造请求。
//  2. **不依赖 db / ToolSet**。配置通过 Opts 传入，HTTP 客户端内部自建，测试用
//     httptest 假源就能覆盖全部失败路径。
//  3. **单个源失败不影响其它源**。每个源独立超时、独立记状态；全部失败时返回
//     空结果 + Sources 里的错误，绝不把错误升级成"整体失败"——本地模板结果必须
//     照常可用。
//
// 额度现实（2026-10 实测，容器内直连均可达）：
//   - NVD：无 key 5 次/30s，有 key 50 次/30s
//   - OSV：无 key、无额度限制
//   - GitHub 搜索：未认证 10 次/**分钟**（不是 60/小时，那是 core API）
//   - EPSS：无 key、无明确限制
//
// 因为三个源不配 key 都能工作，Opts.Enabled 只受总开关控制：**缺 key 只降速，
// 不关闭功能**（这点与 web_search 相反，那边缺 key 会整个禁用工具）。
package cveonline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Source 名字常量。设置项 cve_online_sources 里用逗号分隔的这几个值。
const (
	SourceNVD    = "nvd"
	SourceOSV    = "osv"
	SourceGitHub = "github"
	SourceEPSS   = "epss"
)

// DefaultSources 是默认启用的源。epss 不单独开关（它只补充评分，一次 GET 批量拿）。
var DefaultSources = []string{SourceNVD, SourceOSV, SourceGitHub}

// AllSources 是设置页给用户勾选的全部可选项。
var AllSources = []string{SourceNVD, SourceOSV, SourceGitHub}

const maxBodyBytes = 2 << 20 // 2MB，防止异常响应打爆内存

// 提成 var 只为测试能调小（超时/缓存用例不必真等 8 秒 / 30 分钟）。
var (
	// PerSourceTimeout 是单源超时。取 8s：NVD 无 key 实测 1.4s 级，留足余量又不至于
	// 让一次工具调用被某个挂掉的源拖住。
	PerSourceTimeout = 8 * time.Second
	// CacheTTL 防止 worker 在同一任务里反复查同一条（也顺带保护 NVD 的 5 次/30s 额度）。
	CacheTTL = 30 * time.Minute
)

// Opts 是调用方（server 的 settings）注入的运行配置。
type Opts struct {
	Enabled     bool
	Sources     []string
	NVDKey      string
	GitHubToken string
	Proxy       string // 空=直连；不复用 global_proxy（那是打目标的出口）
}

// Has 判断某个源是否启用。
func (o Opts) Has(src string) bool {
	for _, s := range o.Sources {
		if s == src {
			return true
		}
	}
	return false
}

// ParseSources 把设置里的逗号串解析成源列表，过滤未知值；空则回退默认。
func ParseSources(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return append([]string{}, DefaultSources...)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(AllSources))
	for _, f := range strings.Split(s, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" || seen[f] {
			continue
		}
		if f != SourceNVD && f != SourceOSV && f != SourceGitHub && f != SourceEPSS {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	if len(out) == 0 {
		return append([]string{}, DefaultSources...)
	}
	return out
}

// Query 是一次检索请求。CVE 优先（精确）；否则按组件名/关键词。
type Query struct {
	CVE     string
	Product string
	Keyword string
	Limit   int
}

// Poc 是一条公开 PoC 线索。
type Poc struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Hit 是合并后的单条情报。字段都可能为空——不同源覆盖度不同。
type Hit struct {
	CVE        string   `json:"cve"`
	Summary    string   `json:"summary,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	CVSS       float64  `json:"cvss,omitempty"`
	EPSS       float64  `json:"epss,omitempty"`
	KEV        bool     `json:"kev,omitempty"` // CISA KEV：已被野外利用
	KEVName    string   `json:"kev_name,omitempty"`
	CWE        []string `json:"cwe,omitempty"`
	Affected   []string `json:"affected,omitempty"` // 版本区间描述
	Published  string   `json:"published,omitempty"`
	PocCount   int      `json:"poc_count,omitempty"`
	PocSamples []Poc    `json:"poc_samples,omitempty"`
	Refs       []string `json:"refs,omitempty"`
	Sources    []string `json:"sources,omitempty"`
}

// SourceStatus 记录每个源的成败，供出参如实反映降级情况。
type SourceStatus struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

// Result 是一次检索的完整结果。
type Result struct {
	Hits     []Hit          `json:"items"`
	Sources  []SourceStatus `json:"sources"`
	Degraded []string       `json:"degraded,omitempty"` // 如 "nvd:no_key(5次/30s)"
	Note     string         `json:"note,omitempty"`
	Cached   bool           `json:"cached,omitempty"`
}

// ErrDisabled 在总开关关闭时返回，调用方据此完全不出网。
var ErrDisabled = fmt.Errorf("在线漏洞检索未启用")

type cacheEntry struct {
	res Result
	at  time.Time
}

var (
	cacheMu sync.Mutex
	cache   = map[string]cacheEntry{}
)

// Invalidate 清空缓存（设置变更或测试时调用）。
func Invalidate() {
	cacheMu.Lock()
	cache = map[string]cacheEntry{}
	cacheMu.Unlock()
}

func cacheKey(o Opts, q Query) string {
	// 源集合与「key 是否配置」会影响结果，纳入 key 避免换了配置还吃旧缓存。
	return strings.Join([]string{
		q.CVE, q.Product, q.Keyword, strconv.Itoa(q.Limit),
		strings.Join(o.Sources, ","),
		strconv.FormatBool(strings.TrimSpace(o.NVDKey) != ""),
		strconv.FormatBool(strings.TrimSpace(o.GitHubToken) != ""),
	}, "|")
}

// Lookup 执行一次在线检索。返回值永远带 Sources 明细；err 只用于"根本没法查"
// （未启用）。单源失败一律降级，不返回 err。
func Lookup(ctx context.Context, o Opts, q Query) (Result, error) {
	if !o.Enabled {
		return Result{Note: "disabled"}, ErrDisabled
	}
	q.CVE = strings.ToUpper(strings.TrimSpace(q.CVE))
	q.Product = strings.TrimSpace(q.Product)
	q.Keyword = strings.TrimSpace(q.Keyword)
	if q.CVE == "" && q.Product == "" && q.Keyword == "" {
		return Result{}, fmt.Errorf("cve / product / keyword 至少给一个")
	}
	if q.Limit <= 0 {
		q.Limit = 5
	}
	if q.Limit > 10 {
		q.Limit = 10
	}

	ck := cacheKey(o, q)
	cacheMu.Lock()
	if e, ok := cache[ck]; ok && time.Since(e.at) < CacheTTL {
		res := e.res
		res.Cached = true
		cacheMu.Unlock()
		return res, nil
	}
	cacheMu.Unlock()

	res := fetch(ctx, o, q)

	cacheMu.Lock()
	cache[ck] = cacheEntry{res: res, at: time.Now()}
	cacheMu.Unlock()
	return res, nil
}

func fetch(ctx context.Context, o Opts, q Query) Result {
	cl := newClient(o.Proxy)
	var res Result
	if q.CVE != "" {
		res = fetchByCVE(ctx, cl, o, q)
	} else {
		res = fetchByKeyword(ctx, cl, o, q)
	}
	if len(res.Hits) == 0 && res.Note == "" {
		res.Note = "在线源没有匹配结果"
	}
	return res
}

// fetchByCVE：精确 CVE。NVD 先拿权威数据，随后 OSV / GitHub / EPSS 补充。
func fetchByCVE(ctx context.Context, cl *http.Client, o Opts, q Query) Result {
	res := Result{}
	hit := Hit{CVE: q.CVE}

	if o.Has(SourceNVD) {
		h, st := nvdByCVE(ctx, cl, o, q.CVE)
		res.Sources = append(res.Sources, st)
		if st.OK {
			hit = h
		}
		if strings.TrimSpace(o.NVDKey) == "" {
			res.Degraded = append(res.Degraded, "nvd:no_key(5次/30s)")
		}
	}
	if o.Has(SourceOSV) {
		if st := osvByCVE(ctx, cl, &hit, q.CVE); st != nil {
			res.Sources = append(res.Sources, *st)
		}
	}
	if o.Has(SourceGitHub) {
		st := githubPoC(ctx, cl, o, &hit, q.CVE)
		res.Sources = append(res.Sources, st)
		if strings.TrimSpace(o.GitHubToken) == "" {
			res.Degraded = append(res.Degraded, "github:no_token(10次/分)")
		}
	}
	// EPSS 总是取（无 key、无限制），即使勾选里没有——它只是补一个 0~1 的评分。
	if st := epssBatch(ctx, cl, []*Hit{&hit}); st != nil {
		res.Sources = append(res.Sources, *st)
	}

	// PoC 也算一条情报：刚披露的 CVE 常常 NVD 还没录入、OSV 也没有，但 GitHub 已经有
	// 公开 PoC —— 这种情况下只给 repo 列表也比"什么都没有"有用。
	if hit.Summary != "" || hit.CVSS > 0 || hit.KEV || len(hit.Affected) > 0 || hit.PocCount > 0 {
		res.Hits = []Hit{hit}
	}
	return res
}

// fetchByKeyword：按组件名/关键词。NVD 出候选列表 + EPSS 批量补分。
//
// 刻意不查 OSV / GitHub：OSV 只能按包名查（关键词没意义），GitHub 搜索未认证只有
// 10 次/分钟，一个组件名能匹配上百条 CVE，逐条查必然 403。要 PoC 线索时按 CVE
// 精确再查一次。
func fetchByKeyword(ctx context.Context, cl *http.Client, o Opts, q Query) Result {
	res := Result{Note: "按组件名/关键词只取 NVD 最新候选 + EPSS 评分（关键词是宽泛匹配，可能含无关厂商，请用 affected 里的 CPE 名核对）；要 PoC 线索请按具体 CVE 再查一次"}
	if !o.Has(SourceNVD) {
		res.Note = "组件名检索依赖 NVD，但 NVD 未启用"
		return res
	}
	hits, st := nvdByKeyword(ctx, cl, o, q)
	res.Sources = append(res.Sources, st)
	if strings.TrimSpace(o.NVDKey) == "" {
		res.Degraded = append(res.Degraded, "nvd:no_key(5次/30s)")
	}
	if len(hits) == 0 {
		return res
	}
	ptrs := make([]*Hit, len(hits))
	for i := range hits {
		ptrs[i] = &hits[i]
	}
	if st := epssBatch(ctx, cl, ptrs); st != nil {
		res.Sources = append(res.Sources, *st)
	}
	res.Hits = hits
	return res
}

// 各源的 base URL 提成包级变量：只为让测试能把它们指向 httptest 假源，
// 生产运行时不会被改（没有任何导出 setter）。
var (
	nvdBase    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	osvBase    = "https://api.osv.dev/v1/vulns/"
	githubBase = "https://api.github.com/search/repositories"
	epssBase   = "https://api.first.org/data/v1/epss"
)

// ---------------------------------------------------------------- HTTP 基础

func newClient(proxy string) *http.Client {
	tr := &http.Transport{}
	if p := strings.TrimSpace(proxy); p != "" {
		if pu, err := url.Parse(p); err == nil && pu.Host != "" {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{Timeout: PerSourceTimeout, Transport: tr}
}

func getJSON(ctx context.Context, cl *http.Client, u string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ARTEX-cve-lookup")
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("限流/拒绝 (HTTP %d)", resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("未找到 (HTTP 404)")
	case resp.StatusCode >= 400:
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("响应不是合法 JSON: %w", err)
	}
	return nil
}

func srcErr(name string, err error) SourceStatus {
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120] + "…"
	}
	return SourceStatus{Name: name, OK: false, Error: msg}
}

// ---------------------------------------------------------------- NVD

// nvdCVE 是 NVD 2.0 响应里 cve 对象的子集（只取用得上的字段）。
type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	VulnStatus   string `json:"vulnStatus"`
	CISAExploit  string `json:"cisaExploitAdd"`
	CISAName     string `json:"cisaVulnerabilityName"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V31 []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		V2 []struct {
			CVSSData struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssData"`
			BaseSeverity string `json:"baseSeverity"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdResp struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

func nvdURL(q url.Values) string {
	return nvdBase + "?" + q.Encode()
}

func nvdHeaders(o Opts) map[string]string {
	if k := strings.TrimSpace(o.NVDKey); k != "" {
		return map[string]string{"apiKey": k}
	}
	return nil
}

func nvdByCVE(ctx context.Context, cl *http.Client, o Opts, cve string) (Hit, SourceStatus) {
	q := url.Values{}
	q.Set("cveId", cve)
	var r nvdResp
	if err := getJSON(ctx, cl, nvdURL(q), nvdHeaders(o), &r); err != nil {
		return Hit{CVE: cve}, srcErr(SourceNVD, err)
	}
	if len(r.Vulnerabilities) == 0 {
		return Hit{CVE: cve}, SourceStatus{Name: SourceNVD, OK: true, Count: 0}
	}
	return nvdConvert(r.Vulnerabilities[0].CVE), SourceStatus{Name: SourceNVD, OK: true, Count: 1}
}

// nvdByKeyword 按关键词取候选。
//
// NVD 2.0 没有排序参数，keywordSearch 默认按 CVE 号升序返回（= 最老优先）。直接取
// 前 N 条会拿到 1999 年的 CVE——实测 "apache http server" 的 555 条里，前 3 条是
// CVE-1999/2000。产品维度的候选只有"最近的"有价值，所以先花一次请求读 totalResults，
// 再翻到最后一页取最新的若干条，最后本地按 KEV/EPSS/CVSS 重排。
// 代价是产品检索固定 2 次请求（无 key 时 5 次/30s），所以调用方必须缓存。
func nvdByKeyword(ctx context.Context, cl *http.Client, o Opts, qq Query) ([]Hit, SourceStatus) {
	kw := strings.TrimSpace(qq.Product + " " + qq.Keyword)

	head := url.Values{}
	head.Set("keywordSearch", kw)
	head.Set("resultsPerPage", "1")
	var hr nvdResp
	if err := getJSON(ctx, cl, nvdURL(head), nvdHeaders(o), &hr); err != nil {
		return nil, srcErr(SourceNVD, err)
	}
	if hr.TotalResults == 0 {
		return nil, SourceStatus{Name: SourceNVD, OK: true, Count: 0}
	}

	want := qq.Limit * 2
	if want < 6 {
		want = 6
	}
	if want > 100 {
		want = 100
	}
	start := hr.TotalResults - want
	if start < 0 {
		start = 0
	}
	page := url.Values{}
	page.Set("keywordSearch", kw)
	page.Set("startIndex", strconv.Itoa(start))
	page.Set("resultsPerPage", strconv.Itoa(want))
	var r nvdResp
	if err := getJSON(ctx, cl, nvdURL(page), nvdHeaders(o), &r); err != nil {
		return nil, srcErr(SourceNVD, err)
	}
	hits := make([]Hit, 0, len(r.Vulnerabilities))
	for _, v := range r.Vulnerabilities {
		hits = append(hits, nvdConvert(v.CVE))
	}
	sortHits(hits)
	if len(hits) > qq.Limit {
		hits = hits[:qq.Limit]
	}
	return hits, SourceStatus{Name: SourceNVD, OK: true, Count: len(hits)}
}

func nvdConvert(c nvdCVE) Hit {
	h := Hit{CVE: c.ID, Published: c.Published, Sources: []string{SourceNVD}}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			h.Summary = d.Value
			break
		}
	}
	if len(c.Metrics.V31) > 0 {
		h.CVSS = c.Metrics.V31[0].CVSSData.BaseScore
		h.Severity = strings.ToLower(c.Metrics.V31[0].CVSSData.BaseSeverity)
	} else if len(c.Metrics.V2) > 0 {
		h.CVSS = c.Metrics.V2[0].CVSSData.BaseScore
		h.Severity = strings.ToLower(c.Metrics.V2[0].BaseSeverity)
	}
	if c.CISAExploit != "" {
		h.KEV = true
		h.KEVName = c.CISAName
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if v := strings.TrimSpace(d.Value); v != "" && v != "NVD-CWE-Other" && v != "NVD-CWE-noinfo" {
				h.CWE = append(h.CWE, v)
			}
		}
	}
	h.CWE = dedupe(h.CWE, 3)
	// 版本区间：把 cpeMatch 压成人能读的 "vendor product <= 2.4.49"，最多 5 条。
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			for _, m := range n.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				if s := cpeRangeText(m.Criteria, m.VersionStartIncluding, m.VersionEndIncluding, m.VersionEndExcluding); s != "" {
					h.Affected = append(h.Affected, s)
				}
			}
		}
	}
	h.Affected = dedupe(h.Affected, 5)
	for _, r := range c.References {
		if u := strings.TrimSpace(r.URL); u != "" {
			h.Refs = append(h.Refs, u)
		}
	}
	h.Refs = dedupe(h.Refs, 5)
	return h
}

// cpeRangeText 把 CPE 2.3 串 + 版本约束翻译成可读文本。
// 形如 "cpe:2.3:a:apache:http_server:2.4.49:*:*:..." → "apache http_server = 2.4.49"。
func cpeRangeText(criteria, startIncl, endIncl, endExcl string) string {
	parts := strings.Split(criteria, ":")
	if len(parts) < 5 {
		return ""
	}
	name := strings.TrimSpace(parts[3] + " " + parts[4])
	version := ""
	if len(parts) > 5 {
		version = parts[5]
	}
	var cond []string
	if startIncl != "" {
		cond = append(cond, ">= "+startIncl)
	}
	if endIncl != "" {
		cond = append(cond, "<= "+endIncl)
	}
	if endExcl != "" {
		cond = append(cond, "< "+endExcl)
	}
	if len(cond) > 0 {
		return name + " " + strings.Join(cond, ", ")
	}
	if version != "" && version != "*" && version != "-" {
		return name + " = " + version
	}
	return name
}

// ---------------------------------------------------------------- OSV

func osvByCVE(ctx context.Context, cl *http.Client, h *Hit, cve string) *SourceStatus {
	var r struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Affected []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced string `json:"introduced"`
					Fixed      string `json:"fixed"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	err := getJSON(ctx, cl, osvBase+url.PathEscape(cve), nil, &r)
	if err != nil {
		st := srcErr(SourceOSV, err)
		return &st
	}
	if h.Summary == "" {
		h.Summary = strings.TrimSpace(r.Summary)
	}
	for _, a := range r.Affected {
		name := strings.TrimSpace(a.Package.Ecosystem + " " + a.Package.Name)
		for _, rg := range a.Ranges {
			var in, fixed string
			for _, e := range rg.Events {
				if e.Introduced != "" {
					in = e.Introduced
				}
				if e.Fixed != "" {
					fixed = e.Fixed
				}
			}
			switch {
			case in != "" && fixed != "":
				h.Affected = append(h.Affected, fmt.Sprintf("%s >= %s, < %s", name, in, fixed))
			case fixed != "":
				h.Affected = append(h.Affected, fmt.Sprintf("%s < %s", name, fixed))
			}
		}
	}
	h.Affected = dedupe(h.Affected, 6)
	h.Sources = append(h.Sources, SourceOSV)
	return &SourceStatus{Name: SourceOSV, OK: true, Count: len(r.Affected)}
}

// ---------------------------------------------------------------- GitHub PoC

func githubPoC(ctx context.Context, cl *http.Client, o Opts, h *Hit, cve string) SourceStatus {
	q := url.Values{}
	// 只匹配仓库名和描述。带上 readme 会把 "Awesome-POC" 这类大清单按 star 排到前面，
	// 实测首条会变成 How-To-Secure-A-Linux-Server（3.2 万星，跟这个 CVE 没关系）。
	q.Set("q", cve+" in:name,description")
	q.Set("per_page", "5")
	q.Set("sort", "stars")
	q.Set("order", "desc")
	var r struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			FullName    string `json:"full_name"`
			HTMLURL     string `json:"html_url"`
			Stargazers  int    `json:"stargazers_count"`
			Description string `json:"description"`
		} `json:"items"`
	}
	hdr := map[string]string{"Accept": "application/vnd.github+json"}
	if t := strings.TrimSpace(o.GitHubToken); t != "" {
		hdr["Authorization"] = "Bearer " + t
	}
	if err := getJSON(ctx, cl, githubBase+"?"+q.Encode(), hdr, &r); err != nil {
		return srcErr(SourceGitHub, err)
	}
	h.PocCount = r.TotalCount
	for _, it := range r.Items {
		name := it.FullName
		if it.Stargazers > 0 {
			name = fmt.Sprintf("%s (★%d)", name, it.Stargazers)
		}
		h.PocSamples = append(h.PocSamples, Poc{Name: name, URL: it.HTMLURL})
	}
	if len(h.PocSamples) > 3 {
		h.PocSamples = h.PocSamples[:3]
	}
	h.Sources = append(h.Sources, SourceGitHub)
	return SourceStatus{Name: SourceGitHub, OK: true, Count: r.TotalCount}
}

// ---------------------------------------------------------------- EPSS

func epssBatch(ctx context.Context, cl *http.Client, hits []*Hit) *SourceStatus {
	var ids []string
	for _, h := range hits {
		if h.CVE != "" {
			ids = append(ids, h.CVE)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	var r struct {
		Data []struct {
			CVE  string `json:"cve"`
			EPSS string `json:"epss"`
		} `json:"data"`
	}
	u := epssBase + "?cve=" + url.QueryEscape(strings.Join(ids, ","))
	if err := getJSON(ctx, cl, u, nil, &r); err != nil {
		st := srcErr(SourceEPSS, err)
		return &st
	}
	byID := map[string]float64{}
	for _, d := range r.Data {
		if v, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
			byID[strings.ToUpper(d.CVE)] = v
		}
	}
	n := 0
	for _, h := range hits {
		if v, ok := byID[strings.ToUpper(h.CVE)]; ok {
			h.EPSS = v
			n++
			if !containsStr(h.Sources, SourceEPSS) {
				h.Sources = append(h.Sources, SourceEPSS)
			}
		}
	}
	return &SourceStatus{Name: SourceEPSS, OK: true, Count: n}
}

// ---------------------------------------------------------------- 小工具

// sortHits 的排序就是"该先打哪个"：已被野外利用（KEV）> EPSS 高 > CVSS 高 > CVE 新。
func sortHits(hits []Hit) {
	sort.SliceStable(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return a.CVE > b.CVE // 同分取年份新的
	})
}

func dedupe(in []string, max int) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= max {
			break
		}
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
