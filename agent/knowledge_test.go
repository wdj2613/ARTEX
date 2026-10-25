package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// kbFixture 造两个共用同一资产的任务：source 里有一条事实与一条漏洞，viewer 是观察方。
// 跨任务检索的价值全在"别人验证过的东西本任务能直接用"，所以同资产是关键设定。
type kbFixture struct {
	d        *db.DB
	source   *db.Task
	viewer   *db.Task
	stranger *db.Task
	assetID  int64
	factID   int64
}

func newKBFixture(t *testing.T, tag string) *kbFixture {
	t.Helper()
	d := testDB(t)
	source, err := d.CreateTask("KB "+tag+" 来源", "打 adminApi", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := d.CreateTask("KB "+tag+" 观察", "复测同一目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := d.CreateTask("KB "+tag+" 无关", "全新目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.DeleteTask(source.ID)
		_ = d.DeleteTask(viewer.ID)
		_ = d.DeleteTask(stranger.ID)
		_ = d.Close()
	})
	assets := d.Assets()
	host := fmt.Sprintf("kb-agent-%s-%d.invalid", tag, source.ID)
	assetID, err := assets.UpsertRootDomain(db.UpsertRootDomainReq{Domain: host, TaskID: source.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertRootDomain(db.UpsertRootDomainReq{Domain: host, TaskID: viewer.ID}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = assets.DeleteByIDs([]int64{assetID}) })

	factID, err := d.Exploration(source.ExplorationID).AddNode(db.KindFact, map[string]any{
		"summary": "gtq 的 adminApi 验证码可用 ddddocr 破解拿到 ticket",
		"detail":  "captchaStart 泄露 captchaImg/captchaCheck，识别后按 sign=MD5(MD5(code+ip)+JING) 提交",
	}, 0, "confirmed", "worker", []int64{assetID})
	if err != nil {
		t.Fatal(err)
	}
	return &kbFixture{d: d, source: source, viewer: viewer, stranger: stranger, assetID: assetID, factID: factID}
}

// kbTools 给 viewer 任务造一个 planner 侧 ToolSet。
func (f *kbFixture) tools(t *testing.T) *ToolSet {
	t.Helper()
	assets := f.d.Assets()
	ts := NewToolSet(f.d.Exploration(f.viewer.ExplorationID), "planner")
	ts.SetTaskID(f.viewer.ID)
	ts.SetAssetStore(assets, assets.Companies())
	return ts
}

func callKnowledge(t *testing.T, ts *ToolSet, payload map[string]any) (map[string]any, bool) {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.searchKnowledge().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("search_knowledge 调用失败: %v", err)
	}
	text := res.Flatten()
	if res.IsError {
		return map[string]any{"error": text}, true
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("结果不是 JSON: %v\n%s", err, text)
	}
	return out, false
}

// 同一个关键词只展开一次：第二次只回数量与前几个引用，不再重复列条目——这是"反复查询
// 把上下文吃光"的第一道闸。
func TestSearchKnowledgeRepeatsCollapse(t *testing.T) {
	f := newKBFixture(t, "repeat")
	ts := f.tools(t)

	first, isErr := callKnowledge(t, ts, map[string]any{"q": "验证码"})
	if isErr {
		t.Fatalf("首次检索失败: %v", first)
	}
	if hits, _ := first["hits"].([]any); len(hits) == 0 {
		t.Fatalf("首次检索应有命中: %v", first)
	}
	if first["repeat"] != nil {
		t.Fatalf("首次检索不该标 repeat: %v", first)
	}

	// 大小写/空白不同的同一句话算同一个查询词（归一化后才比对）。
	second, isErr := callKnowledge(t, ts, map[string]any{"q": "  验证码 "})
	if isErr {
		t.Fatalf("重复检索不该报错: %v", second)
	}
	if second["repeat"] != true {
		t.Fatalf("同词再搜应标 repeat: %v", second)
	}
	if _, has := second["hits"]; has {
		t.Fatalf("重复检索不该再展开条目: %v", second)
	}
	refs, _ := second["refs"].([]any)
	if len(refs) == 0 || len(refs) > knowledgeRepeatIDsShown {
		t.Fatalf("重复检索应只回 ≤%d 个引用: %v", knowledgeRepeatIDsShown, refs)
	}
}

// 不同关键词的条数受任务级预算约束，用完就不再放行——第二道闸。
func TestSearchKnowledgeBudgetExhausted(t *testing.T) {
	f := newKBFixture(t, "budget")
	ts := f.tools(t)

	old := KnowledgeQueryBudget
	KnowledgeQueryBudget = func() int { return 1 }
	defer func() { KnowledgeQueryBudget = old }()

	if out, isErr := callKnowledge(t, ts, map[string]any{"q": "验证码"}); isErr {
		t.Fatalf("第一个关键词应放行: %v", out)
	}
	out, isErr := callKnowledge(t, ts, map[string]any{"q": "越权"})
	if !isErr {
		t.Fatalf("额度用完后新关键词应被拒: %v", out)
	}
	if msg, _ := out["error"].(string); msg == "" {
		t.Fatalf("拒绝时应说明原因与替代方案: %v", out)
	}
	// 已经搜过的词仍可再问（只回 repeat，不占新额度）。
	if again, isErr := callKnowledge(t, ts, map[string]any{"q": "验证码"}); isErr || again["repeat"] != true {
		t.Fatalf("已搜过的词应仍可重复询问: %v", again)
	}
}

// 开关关闭时工具直接拒绝，避免"关了还在偷偷检索"。
func TestSearchKnowledgeDisabled(t *testing.T) {
	f := newKBFixture(t, "off")
	ts := f.tools(t)
	old := KnowledgeSearchEnabled
	KnowledgeSearchEnabled = func() bool { return false }
	defer func() { KnowledgeSearchEnabled = old }()

	if out, isErr := callKnowledge(t, ts, map[string]any{"q": "验证码"}); !isErr {
		t.Fatalf("关闭时应拒绝: %v", out)
	}
}

// 被动展示：graph_overview 里出现"资产有交集的其他任务"的漏洞；无关任务不出现。
func TestGraphOverviewCarriesCrossTaskFindings(t *testing.T) {
	f := newKBFixture(t, "overview")
	if _, err := f.d.AddFinding(f.source.ID, 0, "captcha-bypass", "adminApi 人机验证可绕过", "high",
		"带 ticket 后 sms/send 穿过人机验证", "evidence", "worker", []int64{f.assetID}); err != nil {
		t.Fatal(err)
	}

	viewerTools := f.tools(t)
	data := viewerTools.graphOverviewData()
	brief, ok := data["cross_task_findings"].([]map[string]any)
	if !ok || len(brief) != 1 {
		t.Fatalf("同资产任务应看到来源任务的漏洞: %v", data["cross_task_findings"])
	}
	if brief[0]["task_id"] != f.source.ID || brief[0]["severity"] != "high" {
		t.Fatalf("跨任务漏洞条目字段不对: %v", brief[0])
	}
	for _, k := range []string{"node_id", "task", "name"} {
		if _, has := brief[0][k]; !has {
			t.Fatalf("条目缺少 %s: %v", k, brief[0])
		}
	}

	// 无关任务（无资产交集）不该出现该字段，避免历史结论误导。
	strangerTools := NewToolSet(f.d.Exploration(f.stranger.ExplorationID), "planner")
	strangerTools.SetTaskID(f.stranger.ID)
	if _, has := strangerTools.graphOverviewData()["cross_task_findings"]; has {
		t.Fatal("无资产交集的任务不该有跨任务漏洞展示")
	}
}

// 引用串与集合比较的边界（重复判定依赖它们）。
func TestKnowledgeRefsAndSameRefs(t *testing.T) {
	hits := []db.KnowledgeHit{
		{NodeID: 7, FindingID: 70},
		{FindingID: 9}, // 漏洞节点未回填：用漏洞 id 兜底
	}
	refs := knowledgeRefs(hits)
	if len(refs) != 2 || refs[0] != "n:7" || refs[1] != "f:9" {
		t.Fatalf("引用串不对: %v", refs)
	}
	if !sameRefs(refs, []string{"n:7", "f:9"}) {
		t.Fatal("相同集合应判为一致")
	}
	if sameRefs(refs, []string{"n:7"}) || sameRefs(refs, []string{"f:9", "n:7"}) {
		t.Fatal("长度或顺序不同应判为变化")
	}
}
