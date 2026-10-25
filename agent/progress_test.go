package agent

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// report_progress 是"撞预算收尾后规划者唯一的进度来源"，必须真的落到意图节点上，
// 而且要能追加重报（每推完一个分片写一次，后一次覆盖前一次）。
func TestReportProgressWritesIntentPayload(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("intent progress", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "对 12 台节点做 admin 桶爆破"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID, ts.ownerNode = store, task.ID, intentID

	call := func(payload map[string]any) string {
		t.Helper()
		raw, _ := json.Marshal(payload)
		res, err := ts.reportProgress().Call(t.Context(), raw, nil)
		if err != nil {
			t.Fatalf("report_progress 调用失败: %v", err)
		}
		return res.Flatten()
	}

	if out := call(map[string]any{
		"completed": []string{"已爆破 4/12 台节点的 admin 桶"},
		"remaining": []string{"剩下 8 台节点", "复核 429 是否按主机计数"},
		"next_step": "继续按主机×用户名分桶并行",
	}); out == "" {
		t.Fatal("空返回")
	}
	prog, err := store.IntentProgress(intentID)
	if err != nil || prog == nil {
		t.Fatalf("进度未落库: %v %v", prog, err)
	}
	if got := prog["completed"]; got == nil {
		t.Fatalf("completed 丢失: %v", prog)
	}
	if rem, _ := prog["remaining"].([]any); len(rem) != 2 {
		t.Fatalf("remaining 应有两项: %v", prog)
	}
	if prog["auto"] != nil {
		t.Fatalf("worker 汇报不应被标成 auto: %v", prog)
	}

	// 再报一次（分片推进）：后一次覆盖前一次，不叠加历史噪声。
	call(map[string]any{"completed": []string{"已爆破 12/12 台节点（拿到 1 组可用凭据）"}, "next_step": "用凭据打后台入口"})
	prog, _ = store.IntentProgress(intentID)
	if rem, _ := prog["remaining"].([]any); len(rem) != 0 {
		t.Fatalf("后一次汇报应整体覆盖: %v", prog)
	}
	if done, _ := prog["completed"].([]any); len(done) != 1 {
		t.Fatalf("completed 应被覆盖为 1 项: %v", prog)
	}

	// 全空入参要被拒（否则会把已有进度清成空壳）。
	raw, _ := json.Marshal(map[string]any{})
	res, err := ts.reportProgress().Call(t.Context(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("空汇报应报错: %s", res.Flatten())
	}
}

// 没有意图上下文时不能瞎写（例如工具被误挂到规划者上）。
func TestReportProgressNeedsIntentContext(t *testing.T) {
	t.Parallel()
	ts := NewToolSet(nil, "")
	raw, _ := json.Marshal(map[string]any{"next_step": "x"})
	res, err := ts.reportProgress().Call(t.Context(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("无意图上下文应报错: %s", res.Flatten())
	}
}

// 进度串要截断：worker 容易把整段日志塞进来，节点 payload 不该被撑爆。
func TestProgressReportTruncatesAndDropsBlanks(t *testing.T) {
	t.Parallel()
	long := ""
	for i := 0; i < 300; i++ {
		long += "字"
	}
	got := progressReport([]string{"  ", long, "ok"}, 50)
	if len(got) != 2 {
		t.Fatalf("空白项应被丢弃: %v", got)
	}
	if r := []rune(got[0]); len(r) != 51 { // 50 字 + 省略号
		t.Fatalf("长串应截断到 50 字: %d", len(r))
	}
	if got[1] != "ok" {
		t.Fatalf("短串应原样保留且保序: %v", got)
	}
}

// graph_overview 里的意图条目要带上进度摘要：规划者判断"续跑还是换方向"靠它，
// 但只挑关键字段，不把整段进度塞进概览。
func TestCompactIntentsCarriesProgressBrief(t *testing.T) {
	t.Parallel()
	payload, _ := json.Marshal(map[string]any{
		"summary": "枚举 adminApi 端点并测越权",
		"progress": map[string]any{
			"completed": []any{"已枚举 7 个端点"},
			"remaining": []any{"还有 sms/send 未测"},
			"auto":      true,
			"internal":  "不该出现在概览里的字段",
			"at":        "2026-10-25 13:00",
		},
	})
	n := &db.Node{ID: 42, Kind: db.KindIntent, State: "exhausted", Payload: payload}
	out := compactIntents([]*db.Node{n}, nil, nil)
	if len(out) != 1 {
		t.Fatalf("条目数不对: %v", out)
	}
	prog, ok := out[0]["progress"].(map[string]any)
	if !ok {
		t.Fatalf("概览缺少 progress: %v", out[0])
	}
	for _, k := range []string{"completed", "remaining", "auto"} {
		if _, has := prog[k]; !has {
			t.Errorf("概览 progress 缺少 %s: %v", k, prog)
		}
	}
	for _, k := range []string{"internal", "at"} {
		if _, has := prog[k]; has {
			t.Errorf("概览 progress 不该带 %s: %v", k, prog)
		}
	}
	// 没有 progress 的意图不能凭空多出该字段。
	n2 := &db.Node{ID: 43, Kind: db.KindIntent, State: "open", Payload: []byte(`{"summary":"x"}`)}
	if got := compactIntents([]*db.Node{n2}, nil, nil); got[0]["progress"] != nil {
		t.Fatalf("无进度时不该有 progress 键: %v", got[0])
	}
}
