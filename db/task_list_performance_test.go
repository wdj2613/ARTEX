package db

import (
	"fmt"
	"testing"
	"time"
)

func TestListTasksBulkHydratesTaskContext(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	stamp := time.Now().UnixNano()
	profileID, err := d.SaveProfile(&LLMProfile{
		Name: fmt.Sprintf("bulk-list-profile-%d", stamp), Format: "openai", Model: "test", APIKey: "test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteProfile(profileID) })
	source, err := d.CreateTask(fmt.Sprintf("bulk-list-source-%d", stamp), "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(source.ID) })
	companyID, _, err := d.Companies().UpsertCompany(fmt.Sprintf("Bulk List Company %d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Companies().DeleteCompany(companyID) })
	child, err := d.CreateTaskWithOptions("bulk-list-child", "goal", TaskCreateOptions{
		LLMProfileIDs: []int64{profileID},
		SourceTaskIDs: []int64{source.ID},
		CompanyIDs:    []int64{companyID},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(child.ID) })

	tasks, err := d.ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	var got *Task
	for _, task := range tasks {
		if task.ID == child.ID {
			got = task
			break
		}
	}
	if got == nil {
		t.Fatalf("task %d missing from list", child.ID)
	}
	if len(got.LLMProfileIDs) != 1 || got.LLMProfileIDs[0] != profileID ||
		got.ActiveLLMProfileID == nil || *got.ActiveLLMProfileID != profileID || got.LLMFailoverState != "ready" {
		t.Fatalf("LLM context was not bulk hydrated: %+v", got)
	}
	if len(got.SourceTaskIDs) != 1 || got.SourceTaskIDs[0] != source.ID {
		t.Fatalf("source task context was not bulk hydrated: %v", got.SourceTaskIDs)
	}
	if len(got.CompanyIDs) != 1 || got.CompanyIDs[0] != companyID {
		t.Fatalf("company context was not bulk hydrated: %v", got.CompanyIDs)
	}
}

func TestTaskListMetricsAll(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	task, err := d.CreateTask("task-list-metrics", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	latestAt := time.Now().Add(-time.Second).Truncate(time.Second)
	// Token metrics come from the llm_usage ledger, not from activity rows: an
	// activity row carrying tokens must no longer contribute.
	if _, err := d.Exec(`
INSERT INTO activity(
    exploration_id, kind, input_tokens, output_tokens,
    cache_read_tokens, cache_write_tokens, created_at
) VALUES ($1,'result',999,999,999,999,$2)`, task.ExplorationID, latestAt); err != nil {
		t.Fatal(err)
	}
	for _, usage := range []LLMUsage{
		{TaskID: fmt.Sprint(task.ID), ExplorationID: task.ExplorationID, Session: fmt.Sprintf("exp%d-main", task.ExplorationID), Worker: "main", Model: "m", InputTokens: 11, OutputTokens: 7, CacheRead: 3, CacheWrite: 2, Status: "ok"},
		{TaskID: fmt.Sprint(task.ID), ExplorationID: task.ExplorationID, Session: fmt.Sprintf("exp%d-planner", task.ExplorationID), Worker: "planner", Model: "m", InputTokens: 5, OutputTokens: 1, CacheRead: 2, CacheWrite: 0, Status: "ok"},
	} {
		usage := usage
		if err := d.InsertLLMUsage(&usage); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Exec(`
INSERT INTO exploration_nodes(exploration_id, kind, payload, state)
VALUES ($1,'goal','{}','met'), ($1,'goal','{}','open')`, task.ExplorationID); err != nil {
		t.Fatal(err)
	}

	all, err := d.TaskListMetricsAll()
	if err != nil {
		t.Fatal(err)
	}
	metrics, ok := all[task.ExplorationID]
	if !ok {
		t.Fatalf("metrics for exploration %d missing", task.ExplorationID)
	}
	if metrics.Tokens.InputTokens != 16 || metrics.Tokens.OutputTokens != 8 ||
		metrics.Tokens.CacheReadTokens != 5 || metrics.Tokens.CacheWriteTokens != 2 {
		t.Fatalf("unexpected token metrics: %+v", metrics.Tokens)
	}
	if metrics.LastActivity != latestAt.Unix() {
		t.Fatalf("last activity=%d, want %d", metrics.LastActivity, latestAt.Unix())
	}
	if metrics.Goals.Total != 2 || metrics.Goals.Met != 1 {
		t.Fatalf("unexpected goal metrics: %+v", metrics.Goals)
	}
}

// An archived task has its detail rows (activity + llm_usage) extracted into the cold
// archive, so the live ledger is empty for it. The list must fall back to the archive
// manifest's aggregate instead of reporting that the task spent nothing.
func TestTaskListMetricsAllUsesArchivedTokenAggregate(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	task, err := d.CreateTask("task-list-archived", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	if _, err := d.Exec(`
INSERT INTO task_archives(task_id, state, aggregate_stats)
VALUES ($1,'ready', $2::jsonb)`, task.ID, `{"tokens":{"calls":42,"input_tokens":700,"output_tokens":90,"cache_read_tokens":500,"cache_write_tokens":12}}`); err != nil {
		t.Fatal(err)
	}

	all, err := d.TaskListMetricsAll()
	if err != nil {
		t.Fatal(err)
	}
	metrics, ok := all[task.ExplorationID]
	if !ok {
		t.Fatalf("metrics for exploration %d missing", task.ExplorationID)
	}
	if metrics.Tokens.InputTokens != 700 || metrics.Tokens.OutputTokens != 90 ||
		metrics.Tokens.CacheReadTokens != 500 || metrics.Tokens.CacheWriteTokens != 12 {
		t.Fatalf("archived token metrics = %+v, want the manifest aggregate", metrics.Tokens)
	}
}
