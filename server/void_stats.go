package server

import "net/http"

// voidStats 返回一个任务的「空转指标」：工具返回重复率（按工具分组）、工具失败率、
// 终态意图零产出率。
//
// 只读聚合：直接读 activity 与 exploration_nodes，不新增埋点、不建表、不加列。
// 口径为什么不用「同一 URL 重复请求」，见 db/void_stats.go 顶部注释（渗透的重复请求
// 是攻击强度，不是浪费）。
//
// GET /api/exploration/void-stats?task=<task>
func (s *Server) voidStats(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil || t.Store == nil {
		writeJSON(w, 200, map[string]any{"available": false})
		return
	}
	st, err := t.Store.VoidStats()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"available":          true,
		"tool_results":       st.ToolResults,
		"tool_errors":        st.ToolErrors,
		"identical_results":  st.IdenticalResults,
		"repeat_tools":       st.RepeatTools,
		"terminal_intents":   st.TerminalIntents,
		"zero_yield_intents": st.ZeroYieldIntents,
	})
}
