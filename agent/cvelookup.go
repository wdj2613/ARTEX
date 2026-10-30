package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/cveidx"
	actool "github.com/Autumn-27/norma/tool"
)

// cve_lookup：把「这个组件/CVE 有什么已知漏洞」变成一条可执行命令。
//
// 设计依据（见 cveidx 包注释与 CHANGELOG）：镜像内置 1.4 万个 nuclei 模板，
// 其中约 4.6 千条带 CVE 号，模板本身就是请求+匹配器——所以检索结果可以直接落到
// `nuclei -t <模板绝对路径>` 上，跑完拿到的 jsonl 里带 request/response，就是
// finding 需要的可复现证据。不需要额外查流量表。
//
// 刻意不做的事：
//   - 不做版本区间推断。线上指纹里只有 7% 带版本号，做版本匹配等于给自己制造
//     假精度；版本约束交给模板自己的 matcher 判定，跑一次就知道真假。
//   - 不在无版本时倾倒候选。实测按产品名宽泛匹配时单条资产能捞出 126 个历史
//     CVE（"Apache" 一条），worker 的墙钟预算根本跑不完。所以无版本只给
//     verified 里最新的少量几条，并在出参里明确标注"版本未知"。
//   - 不返回漏洞结论。这里只给候选与执行命令；结论必须真实触发（与 worker
//     提示词里"严禁把 CVE 匹配当 finding"的纪律一致）。
func (t *ToolSet) cveLookup() actool.CoreTool {
	return readTool("cve_lookup",
		"按 CVE 号或组件名检索【本地 nuclei 模板库】，返回可执行验证命令。"+
			"cve 精确查（零噪声，首选）；product 按组件名查候选（指纹里没有版本号时会退化为宽泛匹配，出参会标注）；cpe 按 CPE 前缀查。"+
			"每条结果带 next 字段：把 <target> 换成本次目标的 URL/host 直接执行，命中后按 jsonl 里的 request/response 报 finding。"+
			"注意：本工具只给候选与命令，**不等于漏洞已存在**，必须真实触发才算确认。",
		obj(map[string]any{
			"cve":     str("CVE 号，如 CVE-2021-41773。最精确，优先用它"),
			"product": str("组件名，如 nginx / apache / fastapi / thinkphp。指纹里带版本时可写成 \"nginx 1.24.0\""),
			"cpe":     str("CPE 前缀，如 cpe:2.3:a:apache:http_server"),
			"keyword": str("模板名称关键词，如 \"path traversal\"（前三个都不给时才用）"),
			"verified_only": map[string]any{
				"type": "boolean", "description": "只要 nuclei 官方标注 verified:true 的模板（推荐开启）",
			},
			"min_cvss": map[string]any{
				"type": "number", "description": "只要 CVSS 不低于该值的候选（可选，如 7）",
			},
			"limit": intp("返回条数上限。默认 5；组件名无版本时默认 3、上限 10"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				CVE          string  `json:"cve"`
				Product      string  `json:"product"`
				CPE          string  `json:"cpe"`
				Keyword      string  `json:"keyword"`
				VerifiedOnly bool    `json:"verified_only"`
				MinCVSS      float64 `json:"min_cvss"`
				Limit        int     `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)

			cve := strings.ToUpper(strings.TrimSpace(a.CVE))
			product := strings.TrimSpace(a.Product)
			cpe := strings.TrimSpace(a.CPE)
			keyword := strings.TrimSpace(a.Keyword)
			if cve == "" && product == "" && cpe == "" && keyword == "" {
				return actool.Errorf("至少给 cve / product / cpe / keyword 之一"), nil
			}

			idx, err := cveidx.Get()
			if err != nil {
				// 降级而非报错：模板目录缺失不该让 worker 卡住，它还能继续手搓验证。
				return jsonResult(map[string]any{
					"available": false,
					"reason":    err.Error(),
					"hint":      "模板库不可用；可改用 web_search 查该组件/CVE 的公开资料，再用 Bash 手工构造验证请求。",
				})
			}

			// 无版本号的组件名查询 → 收窄条数，避免把整个产品线的历史 CVE 倾倒进上下文。
			versionless := product != "" && cve == "" && cpe == "" && !hasVersionToken(product)
			limit := a.Limit
			if limit <= 0 {
				if versionless {
					limit = 3
				} else {
					limit = 5
				}
			}
			maxLimit := 30
			if versionless {
				maxLimit = 10
			}
			if limit > maxLimit {
				limit = maxLimit
			}

			out := map[string]any{"available": true, "source": "local-templates"}
			tplNum, cveNum, builtAt := idx.Stats()
			out["template_count"] = tplNum
			out["cve_template_count"] = cveNum
			out["index_built_at"] = builtAt.Format("2006-01-02 15:04:05")

			items := make([]map[string]any, 0, limit)
			if cve != "" {
				if e, ok := idx.LookupCVE(cve); ok {
					items = append(items, cveItem(e))
				}
			} else {
				for _, e := range idx.Search(cveidx.SearchOpts{
					Product: product, CPE: cpe, Keyword: keyword,
					Verified: a.VerifiedOnly, MinCVSS: a.MinCVSS, Limit: limit,
				}) {
					items = append(items, cveItem(e))
				}
			}

			out["count"] = len(items)
			out["items"] = items
			if len(items) == 0 {
				out["hint"] = "本地模板库没有匹配。可用 web_search 查该组件/CVE 的公开资料与 PoC，再自行构造验证请求（或 Write 一个自定义 nuclei 模板到工作目录后用 -t 跑）。"
				return jsonResult(out)
			}
			if versionless {
				out["version_unknown"] = true
				out["hint"] = fmt.Sprintf("指纹里没有该组件的版本号，只能按产品名宽泛匹配（可能命中与目标版本无关的历史 CVE）。"+
					"已按 verified+CVSS 排序只给前 %d 条：先确认目标实际版本，再逐条跑 next 命令验证；不要把所有候选都当成存在漏洞。", len(items))
			}
			out["evidence_rule"] = "next 命令带 -jsonl 落盘：命中后读该 jsonl，用其中 request/response 作为证据报 report_finding(vulnclass=\"<CVE 号>\")。" +
				"命令未命中即该候选不成立，记为 record_fact 的 inferred 结论，不要当 finding 上报。"
			return jsonResult(out)
		})
}

// cveItem 把一条索引条目压成紧凑出参。next 用模板绝对路径——实测 `nuclei -id <CVE>`
// 单独使用会报 "no templates provided for scan"，只有 -t <路径> 可用。
func cveItem(e *cveidx.Entry) map[string]any {
	m := map[string]any{
		"cve":      e.CVE,
		"template": e.TemplateID,
		"name":     e.Name,
		"severity": e.Severity,
		"verified": e.Verified,
		"next": fmt.Sprintf("nuclei -t '%s' -u <target> -jsonl -o cve-%s.jsonl",
			e.Path, strings.ReplaceAll(e.CVE, "/", "_")),
	}
	if e.CVSS > 0 {
		m["cvss"] = e.CVSS
	}
	if e.EPSS > 0 {
		m["epss"] = e.EPSS
	}
	if e.Vendor != "" || e.Product != "" {
		m["component"] = strings.TrimPrefix(e.Vendor+"/"+e.Product, "/")
	}
	if e.CPE != "" {
		m["cpe"] = e.CPE
	}
	return m
}

// hasVersionToken 判断组件名里是否带版本号（"nginx 1.24.0" 有，"nginx" 没有）。
func hasVersionToken(s string) bool {
	for _, f := range strings.Fields(s) {
		f = strings.TrimPrefix(strings.ToLower(f), "v")
		if f == "" {
			continue
		}
		dot, digit := false, false
		for _, r := range f {
			switch {
			case r == '.':
				dot = true
			case r >= '0' && r <= '9':
				digit = true
			default:
				dot, digit = false, false
			}
			if dot && digit {
				return true
			}
		}
	}
	return false
}
