package db

// VoidStats 量化「agent 是不是在空转」。
//
// 口径为什么不取「同一 URL 被请求了几次」：渗透本身就要对同一攻击面反复施压
// （fuzz、口令喷洒、payload 变异），生产库实测路径级重复率 56.3%，Top 明细全是
// shopapi/system/config、login_api、shop/fuzz 这类正常目标；而「完全相同的命令」
// 重复只有 1.1%。也就是说：重复请求 = 攻击强度，不是浪费。
//
// 真正的空转信号是「工具返回没有新信息」：同一任务内、同一工具、返回内容完全相同。
// 生产实测分布：TodoWrite 98.8%、list_untested_assets 81.3%、list_facts 57.1%、
// node_detail 53.7%、list_assets 52.7%、get_worker_output 47.4%，而 Bash 只有 10.6%
// —— 空转集中在只读查询类工具，不在渗透动作上。
//
// 第二个信号是「意图有没有产出」：只统计终态里明确记录零写回的意图。
// 引擎写入的历史格式为「事实0 资产0 漏洞0 [情报0]」，兼容旧的数字/字符串 0；
// 缺失、空白及无法解析的格式是未知，不应伪装成零产出。资产/情报也属于写回，
// 不能只凭 exploration yields 边判断（见 server/intent_progress.go）。
//
// 两个信号都是只读聚合，不新增埋点、不建表：activity 与 exploration_nodes 里本来就有。
type VoidStats struct {
	// ToolResults 参与统计的工具返回条数（kind='tool_result'）。
	ToolResults int `json:"tool_results"`
	// ToolErrors 其中 is_error=true 的条数。
	ToolErrors int `json:"tool_errors"`
	// IdenticalResults 返回内容与同任务内其他返回完全相同的条数。
	IdenticalResults int `json:"identical_results"`
	// RepeatTools 按工具聚合的重复情况，重复多的排前面（前端只取前几条展示）。
	RepeatTools []VoidRepeat `json:"repeat_tools"`
	// TerminalIntents 已进终态的意图数（done/exhausted/blocked/stopped）。
	TerminalIntents int `json:"terminal_intents"`
	// ZeroYieldIntents 其中有明确零写回记录的条数；未记录/未知格式不计零产出。
	ZeroYieldIntents int `json:"zero_yield_intents"`
}

// VoidRepeat 是单个工具的重复返回统计。
type VoidRepeat struct {
	Tool string `json:"tool"`
	// Calls 该工具参与判定的返回条数（已排除错误返回与过短摘要）。
	Calls int `json:"calls"`
	// Repeat 其中与同工具其他返回完全相同的条数（Calls 减「不同内容的种数」）。
	Repeat int `json:"repeat"`
}

// minRepeatSummaryLen 是参与「完全相同」判定的返回摘要最小长度。
// 太短的返回（"ok"、"0"、空行）天然大量重复，算进去会把噪声当空转。
const minRepeatSummaryLen = 15

// VoidStats 聚合一个任务的空转指标。只读，无副作用。
func (s *ExplorationStore) VoidStats() (VoidStats, error) {
	var out VoidStats
	if err := s.db.QueryRow(`
SELECT count(*), count(*) FILTER (WHERE is_error)
FROM activity
WHERE exploration_id=$1 AND kind='tool_result'`, s.expID,
	).Scan(&out.ToolResults, &out.ToolErrors); err != nil {
		return out, err
	}

	rows, err := s.db.Query(`
WITH r AS (
    SELECT tool, summary FROM activity
    WHERE exploration_id=$1 AND kind='tool_result' AND NOT is_error
      AND summary IS NOT NULL AND length(btrim(summary)) >= $2
), per AS (
    SELECT tool, count(*) AS c FROM r GROUP BY tool, summary
)
SELECT tool, sum(c)::int, (sum(c) - count(*))::int
FROM per
GROUP BY tool
HAVING sum(c) - count(*) > 0
ORDER BY (sum(c) - count(*)) DESC, sum(c) DESC`, s.expID, minRepeatSummaryLen)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.RepeatTools = []VoidRepeat{}
	for rows.Next() {
		var r VoidRepeat
		if err := rows.Scan(&r.Tool, &r.Calls, &r.Repeat); err != nil {
			return out, err
		}
		out.IdenticalResults += r.Repeat
		out.RepeatTools = append(out.RepeatTools, r)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}

	if err := s.db.QueryRow(`
SELECT count(*),
       count(*) FILTER (WHERE payload->'progress'->>'yields' ~
         '^[[:space:]]*(0|事实0[[:space:]]+资产0[[:space:]]+漏洞0([[:space:]]+情报0)?)[[:space:]]*$')
FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent'
  AND state IN ('done','exhausted','blocked','stopped')`, s.expID,
	).Scan(&out.TerminalIntents, &out.ZeroYieldIntents); err != nil {
		return out, err
	}
	return out, nil
}
