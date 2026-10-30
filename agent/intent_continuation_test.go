package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func continuationFixture(t *testing.T) (*db.DB, *ToolSet, int64) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTaskWithOptions("local continuation", "fixture only", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	ts.SetTaskID(task.ID)
	id, err := ts.ts.AddIntent(map[string]any{"summary": "original", "asset_ids": []int64{99}, "continuation": map[string]any{"recursive_secret": "do not copy"}, "progress": map[string]any{"completed": []string{"done partition"}, "remaining": []string{"last partition"}, "next_step": "read existing output", "note": "artifact exists", "task_id": "task_OLD"}}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err = ts.ts.SetIntentState(id, "exhausted"); err != nil {
		t.Fatal(err)
	}
	return d, ts, id
}

func TestIntentContinuationSnapshot(t *testing.T) {
	_, ts, source := continuationFixture(t)
	id, _, err := ts.addOneIntent(intentItem{Summary: "finish last partition; stop after verification", SourceIntentID: json.RawMessage(fmt.Sprint(source))})
	if err != nil {
		t.Fatal(err)
	}
	node, err := ts.ts.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Source       int64              `json:"source_intent_id"`
		Continuation intentContinuation `json:"continuation"`
	}
	if err = json.Unmarshal(node.Payload, &p); err != nil {
		t.Fatal(err)
	}
	c := p.Continuation
	if p.Source != source || c.SourceIntentID != source || c.SourceState != "exhausted" || len(c.Completed) != 1 || c.Remaining[0] != "last partition" {
		t.Fatalf("bad snapshot: %+v", p)
	}
	for _, bad := range []string{"recursive_secret", "task_OLD", "asset_ids"} {
		if strings.Contains(string(node.Payload), bad) {
			t.Fatalf("unexpected copied field %q", bad)
		}
	}
	if c.ArtifactDir != fmt.Sprintf("tasks/%d/i%d", ts.taskID, source) {
		t.Fatalf("artifact ref=%s", c.ArtifactDir)
	}
	if err = ts.ts.SetIntentProgress(source, map[string]any{"remaining": []string{"changed later"}}); err != nil {
		t.Fatal(err)
	}
	reread, _ := ts.ts.GetNode(id)
	if string(reread.Payload) != string(node.Payload) {
		t.Fatal("handoff mutated with source")
	}
	prompt := renderIntentContinuation(node, "/sandbox", ts.taskID)
	for _, want := range []string{fmt.Sprintf("#%d", source), filepath.Join("/sandbox", c.ArtifactDir), "不恢复来源会话", "旧后台 task id 不可复用", "当前约束"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt lacks %q: %s", want, prompt)
		}
	}
	if WorkerSessionID(ts.ts.ID(), source) == WorkerSessionID(ts.ts.ID(), id) {
		t.Fatal("new intent reused source transcript")
	}
}

func TestIntentContinuationRejectsBadSourcesBeforeInsert(t *testing.T) {
	d, ts, source := continuationFixture(t)
	other, err := d.CreateExploration("other", "other")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, other)
	foreign, err := d.Exploration(other).AddIntent(map[string]any{"summary": "foreign"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Exploration(other).SetIntentState(foreign, "done")
	fact, err := ts.ts.AddNode("fact", map[string]any{"summary": "fact"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		id    json.RawMessage
		state string
	}{
		{"missing", json.RawMessage("999999999"), "exhausted"}, {"cross task", json.RawMessage(fmt.Sprint(foreign)), "exhausted"},
		{"wrong kind", json.RawMessage(fmt.Sprint(fact)), "exhausted"}, {"open", json.RawMessage(fmt.Sprint(source)), "open"},
		{"running", json.RawMessage(fmt.Sprint(source)), "running"}, {"paused", json.RawMessage(fmt.Sprint(source)), "paused"},
		{"deleted", json.RawMessage(fmt.Sprint(source)), "deleted"}, {"negative", json.RawMessage("-1"), "exhausted"},
		{"zero", json.RawMessage("0"), "exhausted"}, {"decimal", json.RawMessage("1.5"), "exhausted"},
		{"quoted", json.RawMessage(`"1"`), "exhausted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ts.ts.SetIntentState(source, tc.state); err != nil {
				t.Fatal(err)
			}
			var before, after int
			_ = d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, ts.ts.ID()).Scan(&before)
			id, _, err := ts.addOneIntent(intentItem{Summary: "invalid continuation", SourceIntentID: tc.id})
			_ = d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, ts.ts.ID()).Scan(&after)
			if err == nil || id != 0 || before != after {
				t.Fatalf("id=%d error=%v count %d -> %d", id, err, before, after)
			}
		})
	}
}

func TestIntentContinuationTerminalStatesAndMissingProgress(t *testing.T) {
	_, ts, source := continuationFixture(t)
	for _, state := range []string{"done", "blocked", "exhausted", "stopped"} {
		if err := ts.ts.SetIntentState(source, state); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ts.addOneIntent(intentItem{Summary: "continue one remaining step", SourceIntentID: json.RawMessage(fmt.Sprint(source))}); err != nil {
			t.Fatalf("%s: %v", state, err)
		}
	}
	empty, err := ts.ts.AddIntent(map[string]any{"summary": "no checkpoint"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	_ = ts.ts.SetIntentState(empty, "done")
	id, _, err := ts.addOneIntent(intentItem{Summary: "check missing checkpoint", SourceIntentID: json.RawMessage(fmt.Sprint(empty))})
	if err != nil {
		t.Fatal(err)
	}
	n, _ := ts.ts.GetNode(id)
	if !strings.Contains(renderIntentContinuation(n, "/base", ts.taskID), "node_detail") {
		t.Fatal("must direct worker to source details")
	}
	// #references are hints for existing dedup, never implicit continuation links.
	plain, _, err := ts.addOneIntent(intentItem{Summary: fmt.Sprintf("ordinary direction mentioning #%d", source)})
	if err != nil {
		t.Fatal(err)
	}
	n, _ = ts.ts.GetNode(plain)
	if strings.Contains(string(n.Payload), "continuation") {
		t.Fatal("guessed source from summary")
	}
}

func TestIntentContinuationBatchAndBoundedSnapshot(t *testing.T) {
	_, ts, source := continuationFixture(t)
	items := make([]string, 40)
	for i := range items {
		items[i] = strings.Repeat("进度", 400)
	}
	if err := ts.ts.SetIntentProgress(source, map[string]any{"completed": items, "remaining": items, "next_step": strings.Repeat("下一步", 400), "note": strings.Repeat("备注", 400)}); err != nil {
		t.Fatal(err)
	}
	input := fmt.Sprintf(`{"intents":[{"summary":"finish bounded remaining batch","source_intent_id":%d},{"summary":"invalid","source_intent_id":-1},{"summary":"unrelated new direction"}]}`, source)
	res, err := ts.addIntent().Call(context.Background(), json.RawMessage(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		IDs    []int64           `json:"ids"`
		Errors map[string]string `json:"errors"`
	}
	if err = json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.IDs) != 3 || out.IDs[0] <= 0 || out.IDs[1] != 0 || out.IDs[2] <= 0 || out.Errors["1"] == "" {
		t.Fatalf("batch=%s", res.Flatten())
	}
	n, _ := ts.ts.GetNode(out.IDs[0])
	var p struct {
		Continuation intentContinuation `json:"continuation"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	if !p.Continuation.Truncated || len(p.Continuation.Completed) != 8 || len(p.Continuation.Remaining) != 8 || len([]rune(string(n.Payload))) > 5000 {
		t.Fatalf("unbounded snapshot len=%d", len([]rune(string(n.Payload))))
	}
}

func TestPlannerContinuationSurvivesPromptOverride(t *testing.T) {
	old := PromptOverride
	defer func() { PromptOverride = old }()
	PromptOverride = func(string) (string, bool) { return "CUSTOM BODY", true }
	prompt := plannerSystem("goal", "data", "/base")
	for _, want := range []string{"CUSTOM BODY", "source_intent_id", "停止条件", "parent_ids"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("missing %q", want)
		}
	}
	props := NewToolSet(nil, "").addIntent().InputSchema()["properties"].(map[string]any)
	if props["source_intent_id"] == nil {
		t.Fatal("new field not advertised")
	}
}
