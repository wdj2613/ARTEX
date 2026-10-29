package db

import (
	"fmt"
	"testing"
	"time"
)

// The dashboard aggregates may only count spend that some task screen can show. A
// hard-deleted task deliberately keeps its ledger rows, but nothing can ever display
// them again — counting them would make the dashboard disagree with "Σ task list +
// Σ conversations". Chat rows (no exploration) must still count.
func TestDashboardAggregatesSkipRowsWithoutTask(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	// Probe profile names keep the assertions independent of other tests' rows and of
	// the archives merged into the same aggregates.
	const orphanProfile, chatProfile = "probe-orphan", "probe-chat"
	defer d.Exec(`DELETE FROM llm_usage WHERE profile_name IN ($1,$2)`, orphanProfile, chatProfile)

	// A task that no longer exists: its exploration id is not in tasks.
	var orphanExp int64 = 1 << 40
	var exists bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM tasks WHERE exploration_id=$1)`, orphanExp).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatalf("probe exploration %d unexpectedly belongs to a task", orphanExp)
	}

	tasksBefore, err := d.UsageTaskCount()
	if err != nil {
		t.Fatal(err)
	}
	insert := func(taskID any, expID any, profile string, input, output int) {
		t.Helper()
		if _, err := d.Exec(`
INSERT INTO llm_usage(task_id, exploration_id, session, worker, model, profile_name,
                      input_tokens, output_tokens, cache_read, cache_write, status, ts)
VALUES ($1,$2,'','worker','probe-model',$3,$4,$5,0,0,'ok',$6)`,
			taskID, expID, profile, input, output, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	insert(fmt.Sprint(orphanExp), orphanExp, orphanProfile, 100, 10)
	// A chat thread has no task at all and is spend the user can still inspect.
	insert(nil, nil, chatProfile, 7, 3)

	rows, err := d.UsageByProfile()
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]ProfileUsage, len(rows))
	for _, row := range rows {
		byName[row.ProfileName] = row
	}
	if _, counted := byName[orphanProfile]; counted {
		t.Fatalf("deleted task's spend leaked into the dashboard: %+v", byName[orphanProfile])
	}
	chat, counted := byName[chatProfile]
	if !counted {
		t.Fatalf("chat spend missing from the dashboard: %+v", rows)
	}
	if chat.InputTokens != 7 || chat.OutputTokens != 3 || chat.Calls != 1 {
		t.Fatalf("chat spend = %+v, want 1 call / 7 in / 3 out", chat)
	}

	daily, err := d.UsageDaily(7)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range daily {
		seen[row.ProfileName] = true
	}
	if seen[orphanProfile] {
		t.Fatalf("deleted task's spend leaked into the daily chart")
	}
	if !seen[chatProfile] {
		t.Fatalf("chat spend missing from the daily chart")
	}

	// The orphan row carries a task_id, so without the filter it would add a distinct
	// "task" the task list can never show.
	tasksAfter, err := d.UsageTaskCount()
	if err != nil {
		t.Fatal(err)
	}
	if tasksAfter != tasksBefore {
		t.Fatalf("task count moved from %d to %d after inserting an orphan row", tasksBefore, tasksAfter)
	}
}
