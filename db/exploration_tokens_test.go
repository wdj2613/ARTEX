package db

import (
	"fmt"
	"testing"
)

func TestTokenStatsFromUsageMapsSessions(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	expID, err := d.CreateExploration("token sessions", "aggregate ledger sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	defer d.Exec(`DELETE FROM llm_usage WHERE exploration_id=$1`, expID)
	store := d.Exploration(expID)

	intentID, err := store.AddIntent(map[string]any{"summary": "worker session"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	otherExpID, err := d.CreateExploration("other token sessions", "foreign rows must not match")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, otherExpID)
	defer d.Exec(`DELETE FROM llm_usage WHERE exploration_id=$1`, otherExpID)

	appendUsage := func(exp int64, session, worker string, input, output, read, write int) {
		t.Helper()
		if insertErr := d.InsertLLMUsage(&LLMUsage{
			TaskID:        fmt.Sprint(exp),
			ExplorationID: exp,
			Session:       session,
			Worker:        worker,
			Model:         "test-model",
			InputTokens:   input,
			OutputTokens:  output,
			CacheRead:     read,
			CacheWrite:    write,
			Status:        "ok",
		}); insertErr != nil {
			t.Fatal(insertErr)
		}
	}

	// Session ids are the transcript keys the harness already uses: the main agent
	// carries its conversation segment, workers carry their intent id.
	appendUsage(expID, fmt.Sprintf("exp%d-main", expID), "main", 11, 12, 13, 14)
	appendUsage(expID, fmt.Sprintf("exp%d-main-s3", expID), "main", 5, 6, 7, 8)
	appendUsage(expID, fmt.Sprintf("exp%d-planner", expID), "planner", 21, 22, 23, 24)
	// A completed run is many calls, and work#N slots are reusable — the intent id is
	// the identity, so every call of this intent folds into one session row.
	const calls = 205
	for i := 0; i < calls; i++ {
		appendUsage(expID, fmt.Sprintf("exp%d-worker-i%d", expID, intentID), "worker", 1, 2, 3, 4)
	}
	// Background lanes own no conversation row in the UI: total only.
	appendUsage(expID, fmt.Sprintf("exp%d-compactor", expID), "compactor", 41, 42, 43, 44)
	// Rows written before the session column existed (session NULL) must not invent
	// a session either — they still count toward the total.
	appendUsage(expID, "", "worker", 51, 52, 53, 54)
	// Another exploration's spend must never leak in.
	appendUsage(otherExpID, fmt.Sprintf("exp%d-worker-i%d", otherExpID, intentID), "worker", 1000, 1000, 1000, 1000)

	workers, sessions, total, err := store.TokenStatsFromUsage()
	if err != nil {
		t.Fatal(err)
	}

	got := make(map[string]SessionTokenUsage, len(sessions))
	for _, usage := range sessions {
		got[usage.Session] = usage
	}
	if len(got) != 4 {
		t.Fatalf("sessions = %+v, want main:0, main:3, plan and the local intent", sessions)
	}
	assertSessionTokens(t, got["main:0"], "main:0", 11, 12, 13, 14)
	assertSessionTokens(t, got["main:3"], "main:3", 5, 6, 7, 8)
	assertSessionTokens(t, got["plan"], "plan", 21, 22, 23, 24)
	assertSessionTokens(t, got[fmt.Sprintf("intent:%d", intentID)], fmt.Sprintf("intent:%d", intentID),
		calls, calls*2, calls*3, calls*4)

	// Lanes are the metering dimension (worker / planner / main / compactor …). A row
	// written before the session column existed still belongs to its lane — it just
	// owns no session row.
	wantLanes := map[string]bool{"main": true, "planner": true, "worker": true, "compactor": true}
	if len(workers) != len(wantLanes) {
		t.Fatalf("lanes = %+v, want %d entries", workers, len(wantLanes))
	}
	for _, w := range workers {
		if !wantLanes[w.Worker] {
			t.Fatalf("unexpected lane %q in %+v", w.Worker, workers)
		}
	}

	assertTokenUsage(t, total,
		11+5+21+calls+41+51,
		12+6+22+calls*2+42+52,
		13+7+23+calls*3+43+53,
		14+8+24+calls*4+44+54)
}

func TestTokenStatsFromUsageEmptyTask(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	expID, err := d.CreateExploration("token empty", "no calls yet")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)

	workers, sessions, total, err := d.Exploration(expID).TokenStatsFromUsage()
	if err != nil {
		t.Fatal(err)
	}
	if len(workers) != 0 || len(sessions) != 0 {
		t.Fatalf("empty ledger returned workers=%+v sessions=%+v", workers, sessions)
	}
	if total != (TokenUsage{}) {
		t.Fatalf("empty ledger total = %+v, want zero", total)
	}
}

func TestUsageSessionKey(t *testing.T) {
	cases := map[string]string{
		"exp6-worker-i42": "intent:42",
		"exp6-main":       "main:0",
		"exp6-main-s5":    "main:5",
		"exp6-planner":    "plan",
		// Background lanes, chat conversations and junk map to no UI row.
		"exp6-compactor": "",
		"exp6-goals":     "",
		"exp6-btw-17":    "",
		"12":             "",
		"":               "",
		"exp6":           "",
		"exp6-":          "",
		"exp6-main-sx":   "",
		"exp6-worker-i":  "",
		"exp6-worker-ix": "",
	}
	for session, want := range cases {
		if got := usageSessionKey(session); got != want {
			t.Fatalf("usageSessionKey(%q) = %q, want %q", session, got, want)
		}
	}
}

func assertSessionTokens(t *testing.T, got SessionTokenUsage, session string, input, output, read, write int) {
	t.Helper()
	if got.Session != session || got.InputTokens != input || got.OutputTokens != output ||
		got.CacheReadTokens != read || got.CacheWriteTokens != write {
		t.Fatalf("session %q = %+v, want input=%d output=%d cache-read=%d cache-write=%d",
			session, got, input, output, read, write)
	}
}

func assertTokenUsage(t *testing.T, got TokenUsage, input, output, read, write int) {
	t.Helper()
	if got.InputTokens != input || got.OutputTokens != output ||
		got.CacheReadTokens != read || got.CacheWriteTokens != write {
		t.Fatalf("token total = %+v, want input=%d output=%d cache-read=%d cache-write=%d",
			got, input, output, read, write)
	}
}

// A task metered before llm_usage carried a session id has nothing to attribute its
// spend with, so the breakdown falls back to the run summary rows in activity.
func TestUsageSessionsFallBackToRunRowsForLegacyTask(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	expID, err := d.CreateExploration("legacy sessions", "no session ids in the ledger")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	defer d.Exec(`DELETE FROM llm_usage WHERE exploration_id=$1`, expID)
	store := d.Exploration(expID)

	intentID, err := store.AddIntent(map[string]any{"summary": "legacy intent"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	at := func(tokens int) *int { return &tokens }
	// Run summary rows are the only record of the lane/segment each run belongs to.
	if _, err := store.AppendActivity(Activity{
		Worker: "mainagent", Kind: "result", MainSeg: at(2),
		InputTokens: at(30), OutputTokens: at(3), CacheReadTokens: at(1), CacheWriteTokens: at(0),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendActivity(Activity{
		Worker: "planner", Kind: "result",
		InputTokens: at(40), OutputTokens: at(4), CacheReadTokens: at(2), CacheWriteTokens: at(1),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendActivity(Activity{
		NodeID: &intentID, Worker: "work#1", Kind: "result",
		InputTokens: at(50), OutputTokens: at(5), CacheReadTokens: at(3), CacheWriteTokens: at(2),
	}); err != nil {
		t.Fatal(err)
	}
	for _, usage := range []LLMUsage{
		{TaskID: fmt.Sprint(expID), ExplorationID: expID, Worker: "main", Model: "m", InputTokens: 30, OutputTokens: 3, CacheRead: 1, Status: "ok"},
		{TaskID: fmt.Sprint(expID), ExplorationID: expID, Worker: "planner", Model: "m", InputTokens: 40, OutputTokens: 4, CacheRead: 2, CacheWrite: 1, Status: "ok"},
		{TaskID: fmt.Sprint(expID), ExplorationID: expID, Worker: "worker", Model: "m", InputTokens: 50, OutputTokens: 5, CacheRead: 3, CacheWrite: 2, Status: "ok"},
	} {
		usage := usage
		if err := d.InsertLLMUsage(&usage); err != nil {
			t.Fatal(err)
		}
	}

	_, sessions, total, err := store.TokenStatsFromUsage()
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]SessionTokenUsage, len(sessions))
	for _, usage := range sessions {
		got[usage.Session] = usage
	}
	if len(got) != 3 {
		t.Fatalf("sessions = %+v, want the three legacy run rows", sessions)
	}
	assertSessionTokens(t, got["main:2"], "main:2", 30, 3, 1, 0)
	assertSessionTokens(t, got["plan"], "plan", 40, 4, 2, 1)
	assertSessionTokens(t, got[fmt.Sprintf("intent:%d", intentID)], fmt.Sprintf("intent:%d", intentID), 50, 5, 3, 2)
	// The task total always comes from the ledger, never from the fallback.
	assertTokenUsage(t, total, 120, 12, 6, 3)
}

// Once the ledger carries session ids the fallback is off: the activity rows are the
// same spend described a second way, so reading both would double count.
func TestUsageSessionsPreferLedgerWhenSessionIsPresent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	expID, err := d.CreateExploration("ledger sessions", "session ids present")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	defer d.Exec(`DELETE FROM llm_usage WHERE exploration_id=$1`, expID)
	store := d.Exploration(expID)

	runs := func(tokens int) *int { return &tokens }
	if _, err := store.AppendActivity(Activity{
		Worker: "mainagent", Kind: "result", MainSeg: runs(0),
		InputTokens: runs(999), OutputTokens: runs(999), CacheReadTokens: runs(999), CacheWriteTokens: runs(999),
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.InsertLLMUsage(&LLMUsage{
		TaskID: fmt.Sprint(expID), ExplorationID: expID, Session: fmt.Sprintf("exp%d-main", expID),
		Worker: "main", Model: "m", InputTokens: 7, OutputTokens: 8, CacheRead: 9, CacheWrite: 10, Status: "ok",
	}); err != nil {
		t.Fatal(err)
	}

	_, sessions, total, err := store.TokenStatsFromUsage()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v, want only the ledger session", sessions)
	}
	assertSessionTokens(t, sessions[0], "main:0", 7, 8, 9, 10)
	assertTokenUsage(t, total, 7, 8, 9, 10)
}
