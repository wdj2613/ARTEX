package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/harness"
)

// 意图收尾时的进度补写：worker 汇报过就保留它的内容、只补终态；没汇报过就自动补一条，
// 让"为什么停"不再对规划者沉默（线上 task#4 有 212 条 exhausted 意图是这样收场的）。
func TestRecordIntentProgress(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, err := pg.CreateTask("intent progress settlement", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.DeleteTask(task.ID) })
	store := pg.Exploration(task.ExplorationID)

	newIntent := func() int64 {
		id, err := store.AddIntent(map[string]any{"summary": "对 12 台节点做 admin 桶爆破"}, 5, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SetIntentState(id, "running"); err != nil {
			t.Fatal(err)
		}
		return id
	}

	// 情形一：worker 一次都没汇报（撞墙钟被就地打断）→ 自动补一条，至少说清终态与产出。
	silent := newIntent()
	recordIntentProgress(store, silent, "exhausted", harness.ReasonTimeout, agent.WriteCounts{Facts: 3, Findings: 1})
	prog, err := store.IntentProgress(silent)
	if err != nil || prog == nil {
		t.Fatalf("未写入进度: %v %v", prog, err)
	}
	if prog["auto"] != true {
		t.Fatalf("自动补写应标 auto=true: %v", prog)
	}
	if prog["terminal"] != string(harness.ReasonTimeout) {
		t.Fatalf("终态原因丢失: %v", prog)
	}
	if y, _ := prog["yields"].(string); !strings.Contains(y, "事实3") || !strings.Contains(y, "漏洞1") {
		t.Fatalf("产出量丢失: %v", prog)
	}

	// 情形二：worker 汇报过 → 保留 completed/remaining/next_step，只补终态，且不覆盖成 auto。
	reported := newIntent()
	raw, _ := json.Marshal(map[string]any{"summary": "worker 自报进度"})
	_ = raw
	workerProg := map[string]any{
		"completed": []string{"已爆破 4/12 台"},
		"remaining": []string{"剩下 8 台"},
		"next_step": "继续分桶并行",
		"at":        "2026-10-25 13:00",
	}
	if err := store.SetIntentProgress(reported, workerProg); err != nil {
		t.Fatal(err)
	}
	recordIntentProgress(store, reported, "exhausted", harness.ReasonMaxTurns, agent.WriteCounts{Facts: 2})
	prog, _ = store.IntentProgress(reported)
	if prog["auto"] != nil {
		t.Fatalf("worker 汇报过的不该被标 auto: %v", prog)
	}
	if done, _ := prog["completed"].([]any); len(done) != 1 {
		t.Fatalf("completed 被覆盖: %v", prog)
	}
	rem, _ := prog["remaining"].([]any)
	if len(rem) != 1 || rem[0] != "剩下 8 台" {
		t.Fatalf("remaining 丢失: %v", prog)
	}
	if prog["terminal"] != string(harness.ReasonMaxTurns) {
		t.Fatalf("终态原因未补: %v", prog)
	}
	if prog["state"] != "exhausted" {
		t.Fatalf("终态未补: %v", prog)
	}
}
