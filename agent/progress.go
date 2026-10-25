package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// report_progress：让 worker 把"做到哪一步"写回意图节点。
//
// 为什么需要这个工具：意图是**一次性时间预算**的原子任务，撞到步数/墙钟上限就变
// exhausted。此前进度只活在 worker 的临时脚本和 transcript 里（task#4 的 worker 转录
// 单条最大 66MB），规划者看不到"完成了哪些分片、还剩哪些候选"，只能原样再开一条同义
// 意图从头跑——线上 task#4 的 395 条意图里 385 条是这种续跑，前 6 小时换到 5 条发现，
// 之后 41 小时只多 1 条。
//
// 落点选在意图 payload.progress（而不是新增一张表或一个新的作业实体）：进度天然属于
// 这条意图，跟着节点一起被 graph_overview / node_detail 读出来，不需要新状态机、不需要
// 规划者多学一个概念。终局时若 worker 一次都没写过，引擎会用产出与终态原因自动补一条
// （见 server/engine.go 的 recordIntentProgress）。

// intentProgress 是写入 payload.progress 的结构。字段刻意为空时省略，便于规划者一眼看出
// "这条什么都没汇报过"。
type intentProgress struct {
	Completed []string `json:"completed,omitempty"`
	Remaining []string `json:"remaining,omitempty"`
	NextStep  string   `json:"next_step,omitempty"`
	Note      string   `json:"note,omitempty"`
	// Auto=true 表示这条记录是引擎在终局时按产出自动补的，不是 worker 自己的汇报。
	Auto bool `json:"auto,omitempty"`
	// Terminal 记录终态原因（exhausted 的来源：max_turns / timeout / killed / error）。
	Terminal string `json:"terminal,omitempty"`
	// Yields 是本次运行写回的事实/发现数量，便于判断"跑这么久值不值"。
	Yields string `json:"yields,omitempty"`
	At     string `json:"at,omitempty"`
}

// progressReport 归一化一次汇报：去掉空白项、限制长度，避免把整段日志塞进节点。
func progressReport(items []string, limit int) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		out = append(out, truncateRunes(it, limit))
	}
	return out
}

func truncateRunes(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit]) + "…"
}

// reportProgress 是 worker 侧工具：把自己推进到哪、还剩什么写回意图节点。
func (t *ToolSet) reportProgress() actool.CoreTool {
	return t.writeExpTool("report_progress",
		"把本次意图的执行进度写回平台（**强烈建议每推完一个分片就调一次**）：completed=已经做完的分片/候选，remaining=还没做的候选清单，next_step=下一步打算怎么做。意图撞到步数/墙钟上限会被迫收尾（exhausted），平台会把**你最后一次汇报**留给规划者；一次都没汇报时，下一条续跑意图只能从头再来。",
		obj(map[string]any{
			"completed": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "已经完成的分片/候选（例如\"已爆破 12 台节点的 admin 桶\"\"已否定 /api/login 是否有限速差异\"）"},
			"remaining": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "还没做完的候选清单——这是规划者决定要不要续跑、怎么续跑的关键，尽量具体"},
			"next_step": str("下一步打算怎么做（一句话）；若已无剩余工作可留空"),
			"note":      str("补充说明（可选）：卡在哪、被什么挡住、复用了哪个脚本"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Completed []string `json:"completed"`
				Remaining []string `json:"remaining"`
				NextStep  string   `json:"next_step"`
				Note      string   `json:"note"`
			}
			_ = json.Unmarshal(in, &a)
			node := t.ownerNode
			if node <= 0 {
				return actool.Errorf("report_progress 需要在某条意图内运行（当前没有可写入的意图节点）"), nil
			}
			prog := intentProgress{
				Completed: progressReport(a.Completed, 200),
				Remaining: progressReport(a.Remaining, 200),
				NextStep:  truncateRunes(strings.TrimSpace(a.NextStep), 300),
				Note:      truncateRunes(strings.TrimSpace(a.Note), 300),
				At:        nowStr(),
			}
			if len(prog.Completed) == 0 && len(prog.Remaining) == 0 && prog.NextStep == "" && prog.Note == "" {
				return actool.Errorf("至少要给 completed / remaining / next_step / note 之一"), nil
			}
			raw, err := json.Marshal(prog)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var asMap map[string]any
			_ = json.Unmarshal(raw, &asMap)
			if err := t.ts.SetIntentProgress(node, asMap); err != nil {
				return actool.Errorf(fmt.Sprintf("写入进度失败: %v", err)), nil
			}
			msg := fmt.Sprintf("进度已记录到意图 #%d", node)
			if len(prog.Remaining) > 0 {
				msg += fmt.Sprintf("（剩余 %d 项）", len(prog.Remaining))
			}
			return actool.Text(msg), nil
		})
}

// progressBrief 供 graph_overview 精简展示：只留最有用的两行，不把整段进度塞进概览。
func progressBrief(p map[string]any) map[string]any {
	if p == nil {
		return nil
	}
	out := map[string]any{}
	for _, k := range []string{"completed", "remaining", "next_step", "terminal", "auto"} {
		if v, ok := p[k]; ok && v != nil {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
