package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// search_knowledge：在【所有任务】里按关键词找已经确认过的漏洞与探索事实，让规划者直接
// 复用别的任务得到的结论和手法，而不是从零再打一遍。
//
// 为什么需要：任务级共享本来就有（list_findings / list_facts 覆盖本任务 + 直接关联任务），
// 但"直接关联"依赖 task_relations，线上只有 1 条记录 → 跨任务继承事实上不存在；而线上
// 17 个资产被 2~3 个任务共用、同一厂商的多个部署分散在不同任务里，成果互不可见。
//
// 为什么必须配去重与预算：关键词命中量很大（"admin" 命中 709 条、摘要合计 17.8 万字符
// ≈ 6 万 token），不加约束的搜索会立刻吃光上下文；而线上现有检索工具的使用数据已经证明
// "反复查"是主要噪声源（list_facts 单任务 604~626 次调用，大量返回 total:0）。所以这里
// 三道闸：只回指针、同词不重复展开、任务级查询预算。

const (
	// knowledgeSearchDefaultLimit / Max 是单次返回条数的默认与上限。
	knowledgeSearchDefaultLimit = 15
	knowledgeSearchMaxLimit     = 30
	// knowledgeRepeatIDsShown 是同词重复搜索时仍然重列多少条 id（够它挑一条继续看即可）。
	knowledgeRepeatIDsShown = 5
	// crossTaskFindingsLimit 是 graph_overview 里被动展示的跨任务漏洞条数上限。
	crossTaskFindingsLimit = 8
	// knowledgeQueryBudgetDefault 是每个任务允许的不同查询词条数（可在设置里改）。
	knowledgeQueryBudgetDefault = 6
)

// KnowledgeSearchEnabled 报告是否启用跨任务知识检索（设置项 agent_knowledge_search）。
// nil 视为启用：默认开，因为它只读、且不改变任何既有工具的行为。
var KnowledgeSearchEnabled = func() bool { return true }

// KnowledgeQueryBudget 返回每个任务允许的不同查询词条数；nil 或非正值回默认。
var KnowledgeQueryBudget = func() int { return knowledgeQueryBudgetDefault }

// knowledgeBudget 取当前生效的预算（防御性地夹到合理区间）。
func knowledgeBudget() int {
	n := knowledgeQueryBudgetDefault
	if KnowledgeQueryBudget != nil {
		if v := KnowledgeQueryBudget(); v > 0 {
			n = v
		}
	}
	if n > 50 {
		n = 50
	}
	return n
}

// searchKnowledge 是 planner 侧工具。返回结构刻意区分两种"没有新内容"的情况：
//   - repeat=true：同一个词在本任务里搜过，命中集合没变 → 不再展开，只给数量与前几个 id；
//   - 命中集合变了 → 正常返回，并注明比上次多了/少了多少。
func (t *ToolSet) searchKnowledge() actool.CoreTool {
	return t.readExpTool("search_knowledge",
		"在【所有任务】里按关键词(q)检索已经确认过的漏洞与探索事实——用来复用别的任务得到的结论和手法（同一厂商的多个部署、同族目标、同一套后台/验证码/越权套路）。"+
			"只返回指针（node_id + 一行摘要 + 来源 task_id/任务描述 + 是否同资产），全文用 node_detail(node_id) 取。"+
			fmt.Sprintf("为避免反复检索把上下文吃光：同一个关键词在本任务里只展开一次（重复搜只回数量和前 %d 个 id）；不同关键词合计上限 %d 个，用完就不再放行。", knowledgeRepeatIDsShown, knowledgeBudget())+
			"结果里的结论**只在来源任务的目标上被验证过**：手法可以借鉴，结论必须在本目标重新确认后才能写进 fact/finding。",
		obj(map[string]any{
			"q":     str("关键词（匹配漏洞名称/分类/摘要/正文与事实摘要/正文），尽量具体：组件名、路径、报错特征、手法名"),
			"limit": intp(fmt.Sprintf("返回条数，默认 %d，上限 %d（可选）", knowledgeSearchDefaultLimit, knowledgeSearchMaxLimit)),
		}, "q"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if KnowledgeSearchEnabled != nil && !KnowledgeSearchEnabled() {
				return actool.Errorf("跨任务知识检索已关闭（设置项 agent_knowledge_search）"), nil
			}
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			q := strings.TrimSpace(a.Q)
			if q == "" {
				return actool.Errorf("q 必填"), nil
			}
			limit := a.Limit
			if limit <= 0 {
				limit = knowledgeSearchDefaultLimit
			}
			if limit > knowledgeSearchMaxLimit {
				limit = knowledgeSearchMaxLimit
			}
			qNorm := db.NormalizeKnowledgeQuery(q)
			seen, used, lastCount, lastRefs, err := t.ts.KnowledgeQueryState(qNorm)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			budget := knowledgeBudget()
			if !seen && used >= budget {
				return actool.Errorf(fmt.Sprintf(
					"本任务的跨任务检索额度已用完（%d/%d 个关键词）。改用 graph_overview 里已展示的跨任务漏洞、list_facts(q=...)、list_findings 或 node_detail 取具体内容。",
					used, budget)), nil
			}
			hits, total, err := t.ts.SearchKnowledge(q, limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			refs := knowledgeRefs(hits)
			if err := t.ts.RecordKnowledgeQuery(qNorm, total, refs); err != nil {
				// 账本写失败不该让检索本身失败，但要在结果里说明，免得调用方以为去重生效了。
				return jsonResult(map[string]any{
					"query": q, "hit_count": total, "hits": hits,
					"warning": fmt.Sprintf("查询账本写入失败（去重与预算本次未生效）: %v", err),
				})
			}
			if seen && total == lastCount && sameRefs(refs, lastRefs) {
				shown := refs
				if len(shown) > knowledgeRepeatIDsShown {
					shown = shown[:knowledgeRepeatIDsShown]
				}
				return jsonResult(map[string]any{
					"query": q, "repeat": true, "hit_count": total, "refs": shown,
					"note": fmt.Sprintf("本任务已用同样的关键词搜过，命中集合没有变化，不再重复展开。refs 里的 n:xxx 用 node_detail(node_id) 取全文；换更具体的关键词或换个方向。剩余额度 %d/%d。",
						maxInt(budget-used, 0), budget),
				})
			}
			out := map[string]any{
				"query": q, "hit_count": total, "hits": hits,
				"remaining_budget": maxInt(budget-used-1, 0),
				"note":             "结论只在来源任务的目标上验证过：手法可借鉴，结论必须在本目标复验后再落库。",
			}
			if seen {
				out["changed_since_last"] = total - lastCount
			}
			if total > len(hits) {
				out["truncated"] = fmt.Sprintf("只返回 %d/%d 条：换更具体的关键词收窄，不要靠翻页。", len(hits), total)
			}
			return jsonResult(out)
		})
}

// knowledgeRefs 把命中列表压成稳定引用串（"n:节点id" / "f:漏洞id"），写进查询账本。
func knowledgeRefs(hits []db.KnowledgeHit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		if h.NodeID > 0 {
			out = append(out, fmt.Sprintf("n:%d", h.NodeID))
			continue
		}
		out = append(out, fmt.Sprintf("f:%d", h.FindingID))
	}
	return out
}

// sameRefs 比较两次命中的引用集合（顺序敏感即可：排序稳定，同一集合顺序一致）。
func sameRefs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// crossTaskFindingsBrief 把被动展示的跨任务漏洞压成概览条目：只留判 severity 与定位所需
// 的字段，名字截短——graph_overview 已经很长，这里只负责"让人知道有这回事"。
func crossTaskFindingsBrief(hits []db.KnowledgeHit) []map[string]any {
	out := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		out = append(out, map[string]any{
			"node_id": h.NodeID, "task_id": h.TaskID, "task": h.Task,
			"severity": h.Severity, "name": h.Summary,
		})
	}
	return out
}
