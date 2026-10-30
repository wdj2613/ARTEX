// Package cveidx 是 nuclei 模板库的只读索引。
//
// 它把镜像内自带的 1.4 万个模板抽成「CVE 号 / 厂商 / 产品 / CPE / 严重度 /
// 模板路径」的结构化表，供 cve_lookup 工具按 CVE 号或组件名检索，并给出**可直接
// 执行**的验证命令。
//
// 为什么用模板库而不是 NVD：模板本身就是请求 + 匹配器，检索结果能直接落到一条
// `nuclei -t <path>` 命令上，跑完就是可复现证据；而 NVD/OSV 只返回版本区间文本，
// 还要人再写 PoC——那是多一步，不是少一步。
//
// 为什么独立成包：索引不依赖 db、不依赖 ToolSet，可以用 fixture 目录单测，符合
// 项目「小文件低耦合、新逻辑不往几千行的包里堆」的惯例（同 enrich/、traffic/）。
package cveidx

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Entry 是一个模板条目。一个模板可能声明多个 CVE，这里一 CVE 一条。
type Entry struct {
	CVE        string
	TemplateID string
	Path       string // 模板绝对路径，供直接拼 nuclei -t 使用
	Name       string
	Severity   string
	CVSS       float64
	EPSS       float64
	Verified   bool
	Vendor     string
	Product    string
	CPE        string
	Tags       []string
	Year       int // 从 CVE 号解析出的年份；0 表示解析不出
}

// Index 是构建完成后的只读快照，可并发查询。
type Index struct {
	Dir          string
	TemplateNum  int
	WithCVENum   int
	BuiltAt      time.Time
	entries      []*Entry
	byCVE        map[string]*Entry
	byVendorProd map[string][]*Entry
	byToken      map[string][]*Entry // vendor / product / cpe 产品段 归一化 → 条目
}

// SearchOpts 是一次组件名检索的入参。
type SearchOpts struct {
	Product  string // 归一化后匹配 product / vendor / CPE 产品段
	CPE      string // 精确 CPE 前缀，如 cpe:2.3:a:apache:http_server
	Keyword  string // 匹配 name 子串
	Verified bool   // 只要 verified:true
	MinCVSS  float64
	Limit    int
}

// 候选目录优先级：nuclei 自己的默认目录在前，旧镜像的目录兜底。
// 顺序即「单一真源」的落点——Dockerfile、索引、以后的更新按钮都指向同一个目录。
var candidateDirs = []string{
	"/root/nuclei-templates",
	"/root/.local/share/nuclei-templates",
}

// ResolveDir 返回第一个存在且含 yaml 的模板目录。ARTEX_NUCLEI_TEMPLATES_DIR 优先。
func ResolveDir() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_NUCLEI_TEMPLATES_DIR")); v != "" {
		return v
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		p := filepath.Join(home, "nuclei-templates")
		if hasYAML(p) {
			return p
		}
	}
	for _, d := range candidateDirs {
		if hasYAML(d) {
			return d
		}
	}
	return ""
}

func hasYAML(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()
	names, err := f.Readdirnames(64)
	if err != nil && len(names) == 0 {
		return false
	}
	for _, n := range names {
		if strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") || !strings.Contains(n, ".") {
			return true // 目录里有模板或子目录（模板按年份分层）
		}
	}
	return len(names) > 0
}

// ---------------- YAML 容错解码 ----------------
// 模板字段在 1.4 万个文件里写法并不完全一致（cve-id 有标量也有数组，cvss 有数值
// 也有字符串）。这里用宽容类型，避免个别畸形模板让整份索引构建失败。

type stringList []string

func (s *stringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var one string
		if err := n.Decode(&one); err != nil {
			return err
		}
		one = strings.TrimSpace(one)
		if one == "" {
			*s = nil
			return nil
		}
		*s = []string{one}
		return nil
	}
	var many []string
	if err := n.Decode(&many); err != nil {
		return err
	}
	*s = many
	return nil
}

type flexFloat float64

func (f *flexFloat) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			*f = 0
			return nil
		}
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			*f = 0
			return nil // 解析不出就当 0，不要因为一个字段毁掉整条
		}
		*f = flexFloat(v)
		return nil
	}
	var v float64
	if err := n.Decode(&v); err != nil {
		*f = 0
		return nil
	}
	*f = flexFloat(v)
	return nil
}

type templateDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string     `yaml:"name"`
		Severity string     `yaml:"severity"`
		Tags     stringList `yaml:"tags"`
		Class    struct {
			CVEID stringList `yaml:"cve-id"`
			CVSS  flexFloat  `yaml:"cvss-score"`
			EPSS  flexFloat  `yaml:"epss-score"`
			CPE   string     `yaml:"cpe"`
		} `yaml:"classification"`
		Meta struct {
			Verified bool   `yaml:"verified"`
			Vendor   string `yaml:"vendor"`
			Product  string `yaml:"product"`
		} `yaml:"metadata"`
	} `yaml:"info"`
}

// ---------------- 构建 ----------------

// Load 扫描 dir 构建索引。dir 为空或不存在时返回错误，由调用方降级为 unavailable。
func Load(dir string) (*Index, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("模板目录未找到（检查 /root/nuclei-templates 或设置 ARTEX_NUCLEI_TEMPLATES_DIR）")
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("模板目录不可用: %s", dir)
	}

	idx := &Index{
		Dir:          dir,
		BuiltAt:      time.Now(),
		byCVE:        map[string]*Entry{},
		byVendorProd: map[string][]*Entry{},
		byToken:      map[string][]*Entry{},
	}

	start := time.Now()
	tplNum := 0
	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 单个文件读不了不该中断整份索引
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		tplNum++
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var doc templateDoc
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil // 畸形模板跳过，不影响其它
		}
		base := &Entry{
			TemplateID: strings.TrimSpace(doc.ID),
			Path:       path,
			Name:       strings.TrimSpace(doc.Info.Name),
			Severity:   strings.ToLower(strings.TrimSpace(doc.Info.Severity)),
			CVSS:       float64(doc.Info.Class.CVSS),
			EPSS:       float64(doc.Info.Class.EPSS),
			Verified:   doc.Info.Meta.Verified,
			Vendor:     strings.ToLower(strings.TrimSpace(doc.Info.Meta.Vendor)),
			Product:    strings.ToLower(strings.TrimSpace(doc.Info.Meta.Product)),
			CPE:        strings.TrimSpace(doc.Info.Class.CPE),
			Tags:       []string(doc.Info.Tags),
		}
		cves := doc.Info.Class.CVEID
		if len(cves) == 0 && strings.HasPrefix(strings.ToUpper(base.TemplateID), "CVE-") {
			cves = []string{base.TemplateID}
		}
		if len(cves) == 0 {
			// 没有 CVE 号的模板（暴露面/配置类）也保留：按产品名检索时仍有价值。
			idx.addTokenHits(base)
			idx.entries = append(idx.entries, base)
			return nil
		}
		for _, c := range cves {
			c = strings.ToUpper(strings.TrimSpace(c))
			if !strings.HasPrefix(c, "CVE-") {
				continue
			}
			e := *base
			e.CVE = c
			e.Year = cveYear(c)
			idx.entries = append(idx.entries, &e)
			if _, ok := idx.byCVE[c]; !ok {
				idx.byCVE[c] = &e
			}
			idx.addTokenHits(&e)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	idx.TemplateNum = tplNum
	idx.finalize()
	// 预排序：verified 优先 → CVSS 降序 → 年份降序。查询时截断即可，无需每次重排。
	for _, list := range idx.byVendorProd {
		sortEntries(list)
	}
	for _, list := range idx.byToken {
		sortEntries(list)
	}
	log.Printf("[cveidx] 索引就绪: 目录=%s 模板=%d 带CVE=%d 耗时=%s", dir, tplNum, idx.WithCVENum, time.Since(start).Round(time.Millisecond))
	return idx, nil
}

// finalize 按 CVE 号去重：同一个 CVE 在真实模板库里常有多个模板（Log4Shell 就有
// 三条 http/network 变体），不去重会让工具出参前五条全是同一条 CVE，白占上下文。
// 保留"最好"的那条（verified 优先 → CVSS 高 → EPSS 高 → 路径含 /http/ 优先），
// 再用去重后的集合重建全部查询索引。
func (idx *Index) finalize() {
	best := make(map[string]*Entry, len(idx.entries))
	var order []string
	var noCVE []*Entry
	for _, e := range idx.entries {
		if e.CVE == "" {
			noCVE = append(noCVE, e)
			continue
		}
		cur, ok := best[e.CVE]
		if !ok {
			best[e.CVE] = e
			order = append(order, e.CVE)
			continue
		}
		if betterEntry(e, cur) {
			best[e.CVE] = e
		}
	}

	dedup := make([]*Entry, 0, len(order)+len(noCVE))
	dedup = append(dedup, noCVE...)
	for _, c := range order {
		dedup = append(dedup, best[c])
	}
	idx.entries = dedup

	idx.byCVE = make(map[string]*Entry, len(order))
	idx.byVendorProd = map[string][]*Entry{}
	idx.byToken = map[string][]*Entry{}
	for _, e := range dedup {
		if e.CVE != "" {
			idx.byCVE[e.CVE] = e
		}
		idx.addTokenHits(e)
	}
	idx.WithCVENum = len(idx.byCVE)
}

// betterEntry 判断 a 是否比 b 更适合作为该 CVE 的代表模板。
func betterEntry(a, b *Entry) bool {
	if a.Verified != b.Verified {
		return a.Verified
	}
	if a.CVSS != b.CVSS {
		return a.CVSS > b.CVSS
	}
	if a.EPSS != b.EPSS {
		return a.EPSS > b.EPSS
	}
	// 同分时偏好 http 模板：它的 jsonl 里同时有 request 和 response，证据最完整。
	ah, bh := strings.Contains(a.Path, "/http/"), strings.Contains(b.Path, "/http/")
	if ah != bh {
		return ah
	}
	return a.Path < b.Path
}

func (idx *Index) addTokenHits(e *Entry) {
	seen := map[string]bool{}
	add := func(k string) {
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
		idx.byToken[k] = append(idx.byToken[k], e)
	}
	add(e.Product)
	add(e.Vendor)
	// CPE 三段式：cpe:2.3:a:<vendor>:<product>:<version>
	if e.CPE != "" {
		parts := strings.Split(e.CPE, ":")
		if len(parts) >= 5 {
			add(normalize(parts[3]))
			add(normalize(parts[4]))
		}
	}
	if e.Product != "" && e.Vendor != "" {
		idx.byVendorProd[e.Vendor+":"+e.Product] = append(idx.byVendorProd[e.Vendor+":"+e.Product], e)
	}
}

func sortEntries(list []*Entry) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Verified != b.Verified {
			return a.Verified
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.Year != b.Year {
			return a.Year > b.Year
		}
		return a.CVE < b.CVE
	})
}

func cveYear(cve string) int {
	parts := strings.Split(cve, "-")
	if len(parts) < 2 {
		return 0
	}
	y, err := strconv.Atoi(parts[1])
	if err != nil || y < 1999 || y > 2100 {
		return 0
	}
	return y
}

func normalize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---------------- 查询 ----------------

// LookupCVE 按 CVE 号精确取一条。
func (idx *Index) LookupCVE(cve string) (*Entry, bool) {
	if idx == nil {
		return nil, false
	}
	e, ok := idx.byCVE[strings.ToUpper(strings.TrimSpace(cve))]
	return e, ok
}

// Search 按组件名 / CPE / 关键词检索，返回已排序、已截断的候选。
func (idx *Index) Search(o SearchOpts) []*Entry {
	if idx == nil {
		return nil
	}
	var pool []*Entry
	switch {
	case strings.TrimSpace(o.CPE) != "":
		prefix := strings.ToLower(strings.TrimSpace(o.CPE))
		for _, e := range idx.entries {
			if strings.HasPrefix(strings.ToLower(e.CPE), prefix) {
				pool = append(pool, e)
			}
		}
	case strings.TrimSpace(o.Product) != "":
		// 组件名归一化后查 token 索引（product/vendor/CPE 段都在里面）。
		key := normalize(o.Product)
		if list, ok := idx.byToken[key]; ok {
			pool = list
		} else {
			// 退一步：宽松前缀匹配（"http server" ↔ "http_server" 这类差异）。
			for k, list := range idx.byToken {
				if len(key) >= 3 && strings.Contains(k, key) {
					pool = append(pool, list...)
				}
			}
		}
	case strings.TrimSpace(o.Keyword) != "":
		kw := strings.ToLower(strings.TrimSpace(o.Keyword))
		for _, e := range idx.entries {
			if strings.Contains(strings.ToLower(e.Name), kw) {
				pool = append(pool, e)
			}
		}
	default:
		return nil
	}

	out := make([]*Entry, 0, len(pool))
	seen := map[string]bool{}
	for _, e := range pool {
		// 一个 CVE 只出一条：真实库里同一 CVE 常有多个模板，重复列出只会白占上下文。
		key := e.CVE
		if key == "" {
			key = e.Path
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if o.Verified && !e.Verified {
			continue
		}
		if o.MinCVSS > 0 && e.CVSS < o.MinCVSS {
			continue
		}
		out = append(out, e)
	}
	sortEntries(out)
	if o.Limit > 0 && len(out) > o.Limit {
		out = out[:o.Limit]
	}
	return out
}

// Stats 返回索引规模，供工具出参与排查使用。
func (idx *Index) Stats() (templates, withCVE int, builtAt time.Time) {
	if idx == nil {
		return 0, 0, time.Time{}
	}
	return idx.TemplateNum, idx.WithCVENum, idx.BuiltAt
}

// ---------------- 进程级缓存 ----------------

var (
	cacheMu   sync.RWMutex
	cacheIdx  *Index
	cacheErr  error
	cacheOnce sync.Once
)

// Get 返回进程内缓存的索引，首次调用时构建（1.4 万模板约 1–3 秒，只付一次）。
// 构建失败时缓存错误；调用方把它降级成 {"available": false}，不要 500。
func Get() (*Index, error) {
	cacheOnce.Do(func() {
		cacheMu.Lock()
		defer cacheMu.Unlock()
		dir := ResolveDir()
		if dir == "" {
			cacheErr = fmt.Errorf("未找到 nuclei 模板目录")
			return
		}
		cacheIdx, cacheErr = Load(dir)
	})
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	return cacheIdx, cacheErr
}

// Invalidate 丢弃缓存，下次 Get 重新扫描。模板更新（设置页的更新按钮）后必须调它，
// 否则索引会一直是旧的。
func Invalidate() {
	cacheMu.Lock()
	cacheIdx, cacheErr = nil, nil
	cacheMu.Unlock()
	cacheOnce = sync.Once{}
}
