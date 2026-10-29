package db

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompareAndSetIntentStateAllowsSingleWinner(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("intent CAS", "only one controller wins")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)
	intentID, err := store.AddIntent(map[string]any{"summary": "controlled"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimIntent(intentID, "worker"); err != nil || !claimed {
		t.Fatalf("claim: claimed=%v err=%v", claimed, err)
	}

	const contenders = 12
	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			changed, transitionErr := store.CompareAndSetIntentState(intentID, "running", "paused")
			if transitionErr != nil {
				t.Errorf("transition: %v", transitionErr)
				return
			}
			if changed {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("CAS winners=%d, want 1", got)
	}
	node, err := store.GetNode(intentID)
	if err != nil || node == nil || node.State != "paused" {
		t.Fatalf("node=%+v err=%v, want paused", node, err)
	}
}

func TestCancelIntentPreservesTokenMeteringWithoutDoubleCount(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("cancel token rollup", "preserve consumed tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)
	intentID, err := store.AddIntent(map[string]any{"summary": "cancelled"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimIntent(intentID, "work#1"); err != nil || !claimed {
		t.Fatalf("claim: claimed=%v err=%v", claimed, err)
	}

	appendUsage := func(kind string, at time.Time, input, output, read, write *int) {
		t.Helper()
		activityID, appendErr := store.AppendActivity(Activity{
			NodeID: &intentID, Worker: "work#1", Kind: kind,
			InputTokens: input, OutputTokens: output,
			CacheReadTokens: read, CacheWriteTokens: write,
		})
		if appendErr != nil {
			t.Fatal(appendErr)
		}
		if _, updateErr := d.Exec(`UPDATE activity SET created_at=$1 WHERE id=$2`, at, activityID); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	values := func(input, output, read, write int) (*int, *int, *int, *int) {
		return &input, &output, &read, &write
	}

	now := time.Now().UTC()
	atUTCNoon := func(daysAgo int) time.Time {
		at := now.AddDate(0, 0, -daysAgo)
		return time.Date(at.Year(), at.Month(), at.Day(), 12, 0, 0, 0, time.UTC)
	}
	authoritativeDay := atUTCNoon(6)
	fallbackDay := atUTCNoon(4)
	trailingDay := atUTCNoon(2)

	// Run 1 has an authoritative result; its preceding cumulative frame must not be
	// counted a second time or move usage to the frame's earlier date.
	i, o, r, w := values(100, 100, 100, 100)
	appendUsage("usage", atUTCNoon(7), i, o, r, w)
	i, o, r, w = values(10, 11, 12, 13)
	appendUsage("result", authoritativeDay, i, o, r, w)
	// Run 2 models a legacy failed result that omitted usage. Its fallback belongs
	// to the result's date, not the cumulative frame's date.
	i, o, r, w = values(20, 21, 22, 23)
	appendUsage("usage", atUTCNoon(5), i, o, r, w)
	appendUsage("result", fallbackDay, nil, nil, nil, nil)
	// Run 3 was interrupted before a terminal result was persisted.
	i, o, r, w = values(30, 31, 32, 33)
	appendUsage("usage", trailingDay, i, o, r, w)

	if err := store.SetIntentState(intentID, "paused"); err != nil {
		t.Fatal(err)
	}
	cleanup, err := store.CancelIntent(intentID)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.Activities != 5 {
		t.Fatalf("deleted activities=%d, want 5", cleanup.Activities)
	}

	// Cancelling deletes the intent's activity rows, so the only surviving trace of
	// the tokens it burned is the dated token-ledger rollup — one row per token day,
	// carrying exactly the day's metered spend.
	type rollup struct {
		day                     string
		input, output, read, wr int
	}
	loadRollups := func() map[string]rollup {
		t.Helper()
		rows, queryErr := d.Query(`SELECT to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'),
			COALESCE(input_tokens,0), COALESCE(output_tokens,0),
			COALESCE(cache_read_tokens,0), COALESCE(cache_write_tokens,0)
			FROM activity
			WHERE exploration_id=$1 AND worker='token-ledger' AND kind='result'
			  AND metadata->>'cancelled_intent_id'=$2`, expID, fmt.Sprint(intentID))
		if queryErr != nil {
			t.Fatal(queryErr)
		}
		defer rows.Close()
		out := map[string]rollup{}
		for rows.Next() {
			var item rollup
			if scanErr := rows.Scan(&item.day, &item.input, &item.output, &item.read, &item.wr); scanErr != nil {
				t.Fatal(scanErr)
			}
			out[item.day] = item
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			t.Fatal(rowsErr)
		}
		return out
	}
	day := func(at time.Time) string { return at.UTC().Format(time.DateOnly) }
	afterCancel := loadRollups()
	if len(afterCancel) != 3 {
		t.Fatalf("token rollups = %+v, want one row per consumed day", afterCancel)
	}
	for _, want := range []rollup{
		{day: day(authoritativeDay), input: 10, output: 11, read: 12, wr: 13},
		{day: day(fallbackDay), input: 20, output: 21, read: 22, wr: 23},
		{day: day(trailingDay), input: 30, output: 31, read: 32, wr: 33},
	} {
		if got := afterCancel[want.day]; got != want {
			t.Fatalf("rollup for %s = %+v, want %+v", want.day, got, want)
		}
	}
	var rollups, datedRollups int
	if err := d.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (
			WHERE metadata->>'token_day'=TO_CHAR(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')
		) FROM activity
		WHERE exploration_id=$1 AND worker='token-ledger' AND kind='result'
		  AND metadata->>'cancelled_intent_id'=$2`, expID, fmt.Sprint(intentID)).Scan(&rollups, &datedRollups); err != nil {
		t.Fatal(err)
	}
	if rollups != 3 || datedRollups != rollups {
		t.Fatalf("token rollups=%d dated=%d, want three correctly dated rows", rollups, datedRollups)
	}
	if _, err := store.CancelIntent(intentID); err == nil {
		t.Fatal("second cancellation unexpectedly succeeded")
	}
	// Re-cancelling must not write a second rollup: the ledger keeps its total.
	afterRetry := loadRollups()
	if len(afterRetry) != len(afterCancel) {
		t.Fatalf("rollups changed after retry: got=%+v want=%+v", afterRetry, afterCancel)
	}
	for key, want := range afterCancel {
		if got := afterRetry[key]; got != want {
			t.Fatalf("rollup %s changed after retry: got=%+v want=%+v", key, got, want)
		}
	}
}

func TestCancelIntentPreservesOutputsYieldedByAnotherIntent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("shared intent output", "preserve shared facts and findings")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)
	first, err := store.AddIntent(map[string]any{"summary": "first"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddIntent(map[string]any{"summary": "second"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	fact, err := store.AddNode(KindFact, map[string]any{"text": "shared fact"}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := store.AddNode(KindFinding, map[string]any{"summary": "shared finding"}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, intentID := range []int64{first, second} {
		if err := store.Link(intentID, RelYields, fact); err != nil {
			t.Fatal(err)
		}
		if err := store.Link(intentID, RelYields, finding); err != nil {
			t.Fatal(err)
		}
	}
	if claimed, err := store.ClaimIntent(first, "work#1"); err != nil || !claimed {
		t.Fatalf("claim: claimed=%v err=%v", claimed, err)
	}
	if err := store.SetIntentState(first, "paused"); err != nil {
		t.Fatal(err)
	}

	cleanup, err := store.CancelIntent(first)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.Intents != 1 || cleanup.Facts != 0 || cleanup.Findings != 0 {
		t.Fatalf("cleanup=%+v, want only the cancelled intent", cleanup)
	}
	for _, nodeID := range []int64{fact, finding} {
		node, getErr := store.GetNode(nodeID)
		if getErr != nil || node == nil {
			t.Fatalf("shared node %d was removed: node=%+v err=%v", nodeID, node, getErr)
		}
	}
}
