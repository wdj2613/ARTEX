package server

import (
	"encoding/json"
	"log"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

// recordIntentProgress 在意图收尾时把进度留在节点上，解决「exhausted 之后规划者只知道
// 这条结束了、不知道做到哪」的信息断层（线上 task#4 有 212 条意图这样收场，其中 385 条
// 续跑意图里多数是从零重来的同义意图）。
//
// 两种情况：
//   - worker 自己用 report_progress 汇报过 → 保留它的 completed/remaining/next_step，只补
//     终态原因与本次产出，规划者据此就能判断"续跑值得/该换方向"；
//   - 一次都没汇报（例如撞墙钟被就地打断，线上大量存在）→ 自动补一条 auto=true 的记录，
//     至少把终态原因与产出量说清楚，别让节点对"为什么停"完全沉默。
//
// 失败只记日志：进度是辅助信息，不能因为它丢掉意图的终态落库。
func recordIntentProgress(store *db.ExplorationStore, intentID int64, state string, reason harness.TerminalReason, wrote agent.WriteCounts) {
	if store == nil || intentID <= 0 {
		return
	}
	existing, err := store.IntentProgress(intentID)
	if err != nil {
		log.Printf("[progress] 意图 #%d 读取进度失败: %v", intentID, err)
		return
	}
	prog := existing
	if prog == nil {
		prog = map[string]any{"auto": true}
	}
	if r := string(reason); r != "" {
		prog["terminal"] = r
	} else if _, ok := prog["terminal"]; !ok {
		prog["terminal"] = state
	}
	prog["state"] = state
	prog["yields"] = wrote.String()
	if err := store.SetIntentProgress(intentID, prog); err != nil {
		log.Printf("[progress] 意图 #%d 写入进度失败: %v", intentID, err)
	}
}

// intentProgressJSON 仅用于测试断言：把进度序列化成稳定文本。
func intentProgressJSON(prog map[string]any) string {
	b, _ := json.Marshal(prog)
	return string(b)
}
