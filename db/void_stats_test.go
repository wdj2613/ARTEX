package db

import "testing"

// TestVoidStats 锁住「空转指标」的口径：
//   - 只统计 kind='tool_result' 的行；
//   - 「完全相同返回」按 (tool, summary) 分组，重复数 = 条数 - 种数；
//   - 过短摘要（< minRepeatSummaryLen）与错误返回不参与重复判定，但错误单独计数；
//   - 终态意图只把明确的零写回计为零产出，缺失或异常格式保持未知。
//
// 口径为什么不用「同一 URL 重复请求」见 void_stats.go 顶部注释。
func TestVoidStats(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("test", "空转指标")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) //nolint:errcheck
	es := d.Exploration(expID)

	seed := []struct {
		tool, summary string
		isErr         bool
	}{
		{"list_facts", "同样的图摘要 AAAAAAAAAAAAAAAAAAAAAAAA", false}, // 3 条完全相同 → 重复 2
		{"list_facts", "同样的图摘要 AAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"list_facts", "同样的图摘要 AAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"Bash", "nmap 输出 BBBBBBBBBBBBBBBBBBBBBBBBBBBB", false}, // 唯一内容 → 不重复
		{"Bash", "连接超时", true},                                  // 错误：单独计数，不进重复判定
		{"Read", "ok", false},                                   // 过短：不参与重复判定
	}
	for _, s := range seed {
		if _, err := es.AppendActivity(Activity{
			Kind: "tool_result", Tool: s.tool, Summary: s.summary, IsError: s.isErr,
		}); err != nil {
			t.Fatalf("append activity: %v", err)
		}
	}
	// 非 tool_result 的行不应被算进工具返回数。
	if _, err := es.AppendActivity(Activity{Kind: "text", Summary: "一段模型文本输出内容足够长"}); err != nil {
		t.Fatal(err)
	}

	zero, err := es.AddIntent(map[string]any{"summary": "零产出意图"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	withYield, err := es.AddIntent(map[string]any{"summary": "有产出意图"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	running, err := es.AddIntent(map[string]any{"summary": "还在跑"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.db.Exec(`UPDATE exploration_nodes SET state='done', payload = payload || '{"progress":{"yields":"0"}}'::jsonb WHERE id=$1`, zero); err != nil {
		t.Fatal(err)
	}
	if _, err := es.db.Exec(`UPDATE exploration_nodes SET state='exhausted', payload = payload || '{"progress":{"yields":"3"}}'::jsonb WHERE id=$1`, withYield); err != nil {
		t.Fatal(err)
	}
	if _, err := es.db.Exec(`UPDATE exploration_nodes SET state='running' WHERE id=$1`, running); err != nil {
		t.Fatal(err)
	}

	st, err := es.VoidStats()
	if err != nil {
		t.Fatalf("VoidStats: %v", err)
	}

	if st.ToolResults != len(seed) {
		t.Errorf("ToolResults = %d, want %d (只算 kind='tool_result')", st.ToolResults, len(seed))
	}
	if st.ToolErrors != 1 {
		t.Errorf("ToolErrors = %d, want 1", st.ToolErrors)
	}
	if st.IdenticalResults != 2 {
		t.Errorf("IdenticalResults = %d, want 2 (3 条相同 list_facts → 重复 2)", st.IdenticalResults)
	}
	if len(st.RepeatTools) != 1 {
		t.Fatalf("RepeatTools = %+v, want 只含 list_facts 一项", st.RepeatTools)
	}
	if got := st.RepeatTools[0]; got.Tool != "list_facts" || got.Calls != 3 || got.Repeat != 2 {
		t.Errorf("RepeatTools[0] = %+v, want {list_facts 3 2}", got)
	}
	if st.TerminalIntents != 2 {
		t.Errorf("TerminalIntents = %d, want 2 (running 不计)", st.TerminalIntents)
	}
	if st.ZeroYieldIntents != 1 {
		t.Errorf("ZeroYieldIntents = %d, want 1", st.ZeroYieldIntents)
	}
}

// TestVoidStatsEmpty 确认空任务返回零值而不是报错（前端据此显示「暂无记录」）。
func TestVoidStatsEmpty(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("test", "空任务")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) //nolint:errcheck

	st, err := d.Exploration(expID).VoidStats()
	if err != nil {
		t.Fatalf("VoidStats on empty: %v", err)
	}
	if st.ToolResults != 0 || st.IdenticalResults != 0 || st.TerminalIntents != 0 || len(st.RepeatTools) != 0 {
		t.Errorf("empty stats = %+v, want all zero", st)
	}
}
