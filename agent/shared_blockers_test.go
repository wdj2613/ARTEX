package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func blockerNode(t *testing.T, id int64, b sharedBlocker) *db.Node {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"progress": map[string]any{"blocker": b}})
	if err != nil {
		t.Fatal(err)
	}
	return &db.Node{ID: id, Kind: db.KindIntent, State: "exhausted", Payload: raw}
}
func TestSharedBlockerFreshnessAndRecovery(t *testing.T) {
	now := time.Now().UTC()
	b := sharedBlocker{Key: "egress-proxy", State: "blocked", Evidence: "checked", ReportedAt: now.Add(-time.Minute).Format(time.RFC3339Nano)}
	nodes := []*db.Node{blockerNode(t, 1, b)}
	if len(currentSharedBlockers(nodes, now)) != 1 {
		t.Fatal("fresh report absent")
	}
	if len(currentSharedBlockers(nodes, now.Add(16*time.Minute))) != 0 {
		t.Fatal("expired report still active")
	}
	b.State = "resolved"
	b.ReportedAt = now.Format(time.RFC3339Nano)
	nodes = append(nodes, blockerNode(t, 2, b))
	if len(currentSharedBlockers(nodes, now)) != 0 {
		t.Fatal("resolved key still blocks")
	}
	b.State = "blocked"
	b.ReportedAt = now.Add(time.Minute).Format(time.RFC3339Nano)
	if len(currentSharedBlockers([]*db.Node{blockerNode(t, 3, b)}, now)) != 0 {
		t.Fatal("future timestamp accepted")
	}
}
func TestSharedBlockerToolPersistsAndShares(t *testing.T) {
	_, ts, id := continuationFixture(t)
	ts.SetOwnerNode(id)
	input := `{"blocker":{"key":"egress-proxy","state":"blocked","evidence":"two independent dependency checks failed"}}`
	result, err := ts.reportProgress().Call(context.Background(), json.RawMessage(input), nil)
	if err != nil || result.IsError {
		t.Fatalf("%v %s", err, result.Flatten())
	}
	overview := ts.graphOverviewData()
	b := overview["shared_blockers"].([]sharedBlocker)
	if len(b) != 1 || b[0].IntentID != id {
		t.Fatalf("overview=%v", b)
	}
	// A normal progress update must not accidentally resolve a known blocker.
	result, err = ts.reportProgress().Call(context.Background(), json.RawMessage(`{"note":"offline work complete"}`), nil)
	if err != nil || result.IsError {
		t.Fatal(err)
	}
	if len(ts.graphOverviewData()["shared_blockers"].([]sharedBlocker)) != 1 {
		t.Fatal("normal update lost blocker")
	}
	_, err = ts.reportProgress().Call(context.Background(), json.RawMessage(`{"blocker":{"key":"egress-proxy","state":"resolved","evidence":"dependency checked again successfully"}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts.graphOverviewData()["shared_blockers"].([]sharedBlocker)) != 0 {
		t.Fatal("resolution not shared")
	}
	for _, key := range []string{"https://proxy:pass@host", "", "secret key"} {
		in, _ := json.Marshal(map[string]any{"blocker": map[string]any{"key": key, "state": "blocked", "evidence": "x"}})
		got, _ := ts.reportProgress().Call(context.Background(), in, nil)
		if !got.IsError {
			t.Fatalf("bad key accepted %q", key)
		}
	}
	// Shared state is not task lifecycle: reporting never pauses/resumes or starts a probe.
	n, _ := ts.ts.GetNode(id)
	if n.State != "exhausted" {
		t.Fatal(fmt.Sprint(n.State))
	}
}
