package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// kill_work 必须对任何意图状态都给出确定结果：规划者被意图收尾唤醒后回头去杀它，是
// 线上最常见的一类调用（历史数据里 78% 的调用落在已结束的意图上），报错只会误导模型。
func TestClassifyKillWorkCoversEveryIntentState(t *testing.T) {
	t.Parallel()
	cases := map[string]killWorkAction{
		// 终态：幂等回报，不再报错
		"done":      killWorkAlreadyDone,
		"blocked":   killWorkAlreadyDone,
		"exhausted": killWorkAlreadyDone,
		"stopped":   killWorkAlreadyDone,
		// 未在执行：可以直接落 stopped，省掉一次白跑
		"open":   killWorkStopOpen,
		"paused": killWorkStopOpen,
		// 运行中：交给 work 句柄终止
		"running": killWorkSignal,
	}
	for state, want := range cases {
		if got := classifyKillWork(state); got != want {
			t.Errorf("classifyKillWork(%q)=%v want=%v", state, got, want)
		}
	}
}

// 未知/新增状态不能静默变成"已完成"（那会让意图永远杀不掉），必须落到发信号这条路上。
func TestClassifyKillWorkUnknownStateSignals(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"", "queued", "retrying", "RUNNING"} {
		if got := classifyKillWork(state); got != killWorkSignal {
			t.Errorf("classifyKillWork(%q)=%v want=%v", state, got, killWorkSignal)
		}
	}
}

// 工具层的幂等契约要落到真实 store 上验证：状态没被误改、该发信号时发信号、竞态下不报错。
// 没有数据库配置时跳过（与 insert_assets / report_finding 等用例一致）。
func TestKillWorkToolIdempotentAcrossStates(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("kill_work idempotency", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)

	newIntent := func(state string) int64 {
		t.Helper()
		id, err := store.AddIntent(map[string]any{"summary": "fixture intent"}, 5, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SetIntentState(id, state); err != nil {
			t.Fatal(err)
		}
		return id
	}
	intentState := func(id int64) string {
		t.Helper()
		n, err := store.GetNode(id)
		if err != nil || n == nil {
			t.Fatalf("读意图 %d 失败: %v", id, err)
		}
		return n.State
	}

	signals := 0
	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID, ts.worker = store, task.ID, "fixture"
	ts.killWork = func(int64) error { signals++; return nil }
	call := func(id int64) string {
		t.Helper()
		res, err := ts.killWorkTool().Call(t.Context(), json.RawMessage(fmt.Sprintf(`{"intent_id":%d}`, id)), nil)
		if err != nil {
			t.Fatalf("kill_work 调用失败: %v", err)
		}
		return res.Flatten()
	}

	// 1) 已结束：不发信号、不改状态、不报错。
	settled := newIntent("exhausted")
	if out := call(settled); signals != 0 || !strings.Contains(out, "已结束") {
		t.Fatalf("已结束意图应按幂等成功回报: signals=%d out=%q", signals, out)
	}
	if got := intentState(settled); got != "exhausted" {
		t.Fatalf("终态被改写: %s", got)
	}

	// 2) 未领取：直接落 stopped，避免被 worker 领走后再白跑一轮。
	queued := newIntent("open")
	if out := call(queued); signals != 0 || !strings.Contains(out, "stopped") {
		t.Fatalf("open 意图应直接标记 stopped: signals=%d out=%q", signals, out)
	}
	if got := intentState(queued); got != "stopped" {
		t.Fatalf("open 意图未落 stopped: %s", got)
	}

	// 3) 运行中：发终止信号，状态交给 worker 收尾（工具不得越权改）。
	running := newIntent("running")
	if out := call(running); signals != 1 || !strings.Contains(out, "终止信号") {
		t.Fatalf("运行中意图应发终止信号: signals=%d out=%q", signals, out)
	}
	if got := intentState(running); got != "running" {
		t.Fatalf("工具不应直接改写运行中意图的状态: %s", got)
	}

	// 4) 竞态：读到 running、发信号时 work 已自行收尾 → 仍按幂等成功回报。
	ts.killWork = func(id int64) error {
		if err := store.SetIntentState(id, "done"); err != nil {
			t.Fatalf("模拟收尾失败: %v", err)
		}
		return errors.New("意图当前没有运行中的 work")
	}
	racing := newIntent("running")
	if out := call(racing); !strings.Contains(out, "已结束") {
		t.Fatalf("竞态下应按幂等成功回报: out=%q", out)
	}
}
