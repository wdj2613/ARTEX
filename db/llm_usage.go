package db

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// LLMUsage is one lightweight LLM-call metering row — the always-on usage ledger,
// distinct from llm_records (which stores full request/response bodies and is a
// gated debug feature). One row per completion call, written on both success and
// error, so token accounting is complete even for interrupted/failed runs. Carries
// only the dimensions needed to slice token spend (model / profile / task / agent /
// session), never any prompt or response content.
type LLMUsage struct {
	TaskID        string `json:"task_id"`        // task registry id (matches llm_records.task_id)
	ExplorationID int64  `json:"exploration_id"` // exploration id parsed from the session (0 = unknown/non-task)
	Session       string `json:"session"`        // transcript session id: exp<N>-worker-i<ID> / exp<N>-main-s<SEG> / exp<N>-planner / <conversation id>
	Worker        string `json:"worker"`         // agent lane: worker / planner / main / compactor / goals / btw
	Model         string `json:"model"`
	ProfileName   string `json:"profile_name"`
	LatencyMs     int    `json:"latency_ms"`
	InputTokens   int    `json:"input_tokens"`
	OutputTokens  int    `json:"output_tokens"`
	CacheRead     int    `json:"cache_read"`
	CacheWrite    int    `json:"cache_write"`
	Status        string `json:"status"` // ok | error
}

const llmUsageSchema = `
CREATE TABLE IF NOT EXISTS llm_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    task_id        TEXT,
    exploration_id BIGINT,
    worker         TEXT,
    model          TEXT,
    profile_name   TEXT,
    latency_ms     INTEGER,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    cache_read     INTEGER NOT NULL DEFAULT 0,
    cache_write    INTEGER NOT NULL DEFAULT 0,
    status         TEXT
);
ALTER TABLE llm_usage ADD COLUMN IF NOT EXISTS session TEXT;
CREATE INDEX IF NOT EXISTS idx_llm_usage_task  ON llm_usage(task_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_model ON llm_usage(task_id, model);
CREATE INDEX IF NOT EXISTS idx_llm_usage_exp   ON llm_usage(exploration_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_session ON llm_usage(exploration_id, session);
`

// EnsureLLMUsageTable creates the llm_usage metering table if it does not exist.
func (d *DB) EnsureLLMUsageTable() error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(llmUsageSchema); err != nil {
		return err
	}
	return tx.Commit()
}

// InsertLLMUsage appends one metering row. Best-effort: callers log and continue on
// error (a lost metering row must never break the LLM call).
func (d *DB) InsertLLMUsage(u *LLMUsage) error {
	var expID any
	if u.ExplorationID > 0 {
		expID = u.ExplorationID
	}
	_, err := d.Exec(`
INSERT INTO llm_usage(task_id, exploration_id, session, worker, model, profile_name, latency_ms, input_tokens, output_tokens, cache_read, cache_write, status)
VALUES (NULLIF($1,''),$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),$7,$8,$9,$10,$11,$12)`,
		u.TaskID, expID, u.Session, u.Worker, u.Model, u.ProfileName,
		u.LatencyMs, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.Status)
	return err
}

// TokenByModel aggregates a task's LLM token usage grouped by model, most-used
// first, from the always-on llm_usage ledger. taskID is the task registry id.
// Accurate even with per-agent model bindings, pool rotation/failover, and
// interrupted runs, since every call (success or error) is metered.
func (d *DB) TokenByModel(taskID string) ([]ModelTokenStat, error) {
	rows, err := d.Query(`
SELECT COALESCE(NULLIF(model,''),'(unknown)') AS model, COUNT(*) AS calls,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage
WHERE COALESCE(task_id,'') = $1
GROUP BY model
ORDER BY SUM(input_tokens) + SUM(output_tokens) DESC, model`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ModelTokenStat{}
	for rows.Next() {
		var m ModelTokenStat
		if err := rows.Scan(&m.Model, &m.Calls, &m.InputTokens, &m.OutputTokens,
			&m.CacheReadTokens, &m.CacheWriteTokens); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// usageSessionKey maps a transcript session id onto the key the task-detail UI uses
// for one conversation row (main:<seg> / plan / intent:<id>). Background lanes
// (compactor / goals / btw) and chat conversations have no row in that list, so they
// map to "" and only count toward the task total.
func usageSessionKey(session string) string {
	if !strings.HasPrefix(session, "exp") {
		return ""
	}
	rest := session[3:] // after "exp"
	i := strings.IndexByte(rest, '-')
	if i < 0 {
		return ""
	}
	role := rest[i+1:]
	switch {
	case role == "planner":
		return "plan"
	case role == "main":
		return "main:0" // the implicit original segment
	case strings.HasPrefix(role, "main-s"):
		if seg := role[len("main-s"):]; usageAllDigits(seg) {
			return "main:" + seg
		}
	case strings.HasPrefix(role, "worker-i"):
		if id := role[len("worker-i"):]; usageAllDigits(id) {
			return "intent:" + id
		}
	}
	return ""
}

func usageAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// TokenStatsFromUsage aggregates one task's metering ledger for the task detail page:
// per-lane totals, per-session totals keyed like the UI's conversation rows, and the
// whole-task total (every lane, including background ones that own no UI row). This
// is the only token source for a task — activity rows carry usage snapshots for the
// live display only and never drive totals.
func (s *ExplorationStore) TokenStatsFromUsage() ([]TokenUsage, []SessionTokenUsage, TokenUsage, error) {
	var total TokenUsage
	workers, err := s.usageByLane()
	if err != nil {
		return nil, nil, total, err
	}
	for _, w := range workers {
		total.InputTokens += w.InputTokens
		total.OutputTokens += w.OutputTokens
		total.CacheReadTokens += w.CacheReadTokens
		total.CacheWriteTokens += w.CacheWriteTokens
	}
	sessions, err := s.usageSessions()
	if err != nil {
		return nil, nil, total, err
	}
	return workers, sessions, total, nil
}

// usageSessions returns one row per conversation the task-detail UI lists
// (main:<seg> / plan / intent:<id>).
//
// Calls metered since the session column exists carry their transcript session id, so
// the ledger alone answers this. Rows written before that column existed have no
// session and their spend cannot be attributed from the ledger — the run summary rows
// in activity are the only record of which main segment / intent / planner run spent
// it. The fallback therefore reads those rows, but only for a task whose ledger holds
// no session-tagged call at all: switching per task keeps the two sources from ever
// describing the same spend twice.
func (s *ExplorationStore) usageSessions() ([]SessionTokenUsage, error) {
	rows, err := s.db.Query(`
SELECT COALESCE(session,''),
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage WHERE exploration_id=$1
GROUP BY 1`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byKey := map[string]SessionTokenUsage{}
	tagged := 0
	for rows.Next() {
		var session string
		var input, output, cacheRead, cacheWrite int
		if err := rows.Scan(&session, &input, &output, &cacheRead, &cacheWrite); err != nil {
			return nil, err
		}
		key := usageSessionKey(session)
		if key == "" {
			continue // background lane / chat / pre-session-column row: total only
		}
		tagged++
		cur := byKey[key]
		cur.Session = key
		cur.InputTokens += input
		cur.OutputTokens += output
		cur.CacheReadTokens += cacheRead
		cur.CacheWriteTokens += cacheWrite
		byKey[key] = cur
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if tagged == 0 {
		return s.legacyRunSessions()
	}
	sessions := make([]SessionTokenUsage, 0, len(byKey))
	for _, v := range byKey {
		sessions = append(sessions, v)
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Session < sessions[j].Session })
	return sessions, nil
}

// legacyRunSessions derives the per-conversation breakdown from the run summary rows
// (kind='result') for tasks metered before llm_usage carried a session id. Kept as a
// read-only bridge for that history; new spend never needs it.
func (s *ExplorationStore) legacyRunSessions() ([]SessionTokenUsage, error) {
	rows, err := s.db.Query(`SELECT
		CASE
			WHEN COALESCE(a.worker,'')='mainagent' THEN 'main:' || COALESCE(a.main_seg,0)::text
			WHEN COALESCE(a.worker,'')='planner' THEN 'plan'
			WHEN n.id IS NOT NULL THEN 'intent:' || n.id::text
			ELSE ''
		END AS session_key,
		COALESCE(SUM(a.input_tokens),0), COALESCE(SUM(a.output_tokens),0),
		COALESCE(SUM(a.cache_read_tokens),0), COALESCE(SUM(a.cache_write_tokens),0)
	FROM activity a
	LEFT JOIN exploration_nodes n
	  ON n.id=a.node_id AND n.exploration_id=a.exploration_id AND n.kind='intent'
	WHERE a.exploration_id=$1 AND a.kind='result'
	  AND (COALESCE(a.worker,'') IN ('mainagent','planner') OR n.id IS NOT NULL)
	GROUP BY session_key
	ORDER BY session_key`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SessionTokenUsage{}
	for rows.Next() {
		var u SessionTokenUsage
		if err := rows.Scan(&u.Session, &u.InputTokens, &u.OutputTokens, &u.CacheReadTokens, &u.CacheWriteTokens); err != nil {
			return nil, err
		}
		if u.Session == "" {
			continue
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// usageByLane returns the task's token spend per agent lane (worker / planner / main /
// compactor / goals / btw), from the always-on metering ledger.
func (s *ExplorationStore) usageByLane() ([]TokenUsage, error) {
	rows, err := s.db.Query(`
SELECT COALESCE(worker,''),
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage WHERE exploration_id=$1
GROUP BY 1 ORDER BY 1`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TokenUsage{}
	for rows.Next() {
		var u TokenUsage
		if err := rows.Scan(&u.Worker, &u.InputTokens, &u.OutputTokens, &u.CacheReadTokens, &u.CacheWriteTokens); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// usageOwnedByExistingTask restricts the global (dashboard) aggregates to spend that
// some task screen can actually show: chat rows (exploration_id IS NULL) and rows whose
// task still exists. A hard-deleted task keeps its ledger rows on purpose — it really
// did spend the tokens — but nothing can display them, so counting them in the
// dashboard would break the invariant "dashboard = Σ task list + Σ conversations".
const usageOwnedByExistingTask = `(exploration_id IS NULL OR EXISTS (
    SELECT 1 FROM tasks t WHERE t.exploration_id = llm_usage.exploration_id))`

// UsageTaskCount returns how many distinct tasks the ledger covers — live rows plus
// cold archives whose detail rows were extracted. Summing UsageByProfile's per-profile
// task counts would count a task once per profile it used, so dashboards must use this
// figure instead.
func (d *DB) UsageTaskCount() (int, error) {
	var n int
	err := d.QueryRow(`
SELECT COUNT(*) FROM (
    SELECT DISTINCT 'task:'||task_id AS k FROM llm_usage
     WHERE COALESCE(task_id,'') <> '' AND ` + usageOwnedByExistingTask + `
    UNION
    SELECT DISTINCT 'task:'||ta.task_id::text AS k FROM task_archives ta
     WHERE (ta.aggregate_stats->'tokens') IS NOT NULL
) x`).Scan(&n)
	return n, err
}

// ProfileUsage aggregates the whole ledger's token spend for one LLM profile
// (global, all tasks). Powers the dashboard's per-profile token card (new source).
type ProfileUsage struct {
	ProfileName      string `json:"profile_name"`
	Calls            int    `json:"calls"`
	Tasks            int    `json:"tasks"`
	InputTokens      int    `json:"input_tokens"`
	OutputTokens     int    `json:"output_tokens"`
	CacheReadTokens  int    `json:"cache_read_tokens"`
	CacheWriteTokens int    `json:"cache_write_tokens"`
}

// UsageByProfile returns global token spend grouped by profile name, most-used
// first. profile_name may be empty for calls made on env/non-persisted configs.
func (d *DB) UsageByProfile() ([]ProfileUsage, error) {
	rows, err := d.Query(`
SELECT COALESCE(profile_name,'') AS profile_name, COUNT(*) AS calls,
       COUNT(DISTINCT task_id) AS tasks,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage
WHERE ` + usageOwnedByExistingTask + `
GROUP BY profile_name
ORDER BY SUM(input_tokens) + SUM(output_tokens) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProfileUsage{}
	for rows.Next() {
		var p ProfileUsage
		if err := rows.Scan(&p.ProfileName, &p.Calls, &p.Tasks,
			&p.InputTokens, &p.OutputTokens, &p.CacheReadTokens, &p.CacheWriteTokens); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]ProfileUsage, len(out))
	for _, current := range out {
		byName[current.ProfileName] = current
	}
	for _, aggregate := range archived {
		for _, cold := range aggregate.TokenProfiles {
			current := byName[cold.ProfileName]
			current.ProfileName = cold.ProfileName
			current.Calls += cold.Calls
			current.Tasks += cold.Tasks
			current.InputTokens += cold.InputTokens
			current.OutputTokens += cold.OutputTokens
			current.CacheReadTokens += cold.CacheReadTokens
			current.CacheWriteTokens += cold.CacheWriteTokens
			byName[cold.ProfileName] = current
		}
	}
	out = out[:0]
	for _, current := range byName {
		out = append(out, current)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].InputTokens + out[i].OutputTokens
		right := out[j].InputTokens + out[j].OutputTokens
		if left != right {
			return left > right
		}
		return out[i].ProfileName < out[j].ProfileName
	})
	return out, nil
}

// ProfileDayUsage is one (profile, UTC calendar day) token bucket for the daily
// chart. Unlike the activity-based chart, ts is the real call time, so this is
// actual per-day consumption rather than tokens bucketed by task creation date.
type ProfileDayUsage struct {
	ProfileName     string `json:"profile_name"`
	Date            string `json:"date"` // YYYY-MM-DD (UTC)
	InputTokens     int    `json:"input_tokens"`
	OutputTokens    int    `json:"output_tokens"`
	CacheReadTokens int    `json:"cache_read_tokens"`
}

// UsageDaily returns per-(profile, day) token buckets for the past `days` days
// (default 365 when days<=0), so the dashboard can slice by profile + range.
func (d *DB) UsageDaily(days int) ([]ProfileDayUsage, error) {
	if days <= 0 {
		days = 365
	}
	rows, err := d.Query(`
SELECT COALESCE(profile_name,'') AS profile_name,
       to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), COALESCE(SUM(cache_read),0)
FROM llm_usage
WHERE ts >= now() - ($1 * interval '1 day')
  AND `+usageOwnedByExistingTask+`
GROUP BY profile_name, day
ORDER BY day`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProfileDayUsage{}
	for rows.Next() {
		var p ProfileDayUsage
		if err := rows.Scan(&p.ProfileName, &p.Date, &p.InputTokens, &p.OutputTokens, &p.CacheReadTokens); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	byKey := make(map[string]ProfileDayUsage, len(out))
	for _, current := range out {
		byKey[current.ProfileName+"\x00"+current.Date] = current
	}
	for _, aggregate := range archived {
		for _, cold := range aggregate.TokenDaily {
			if cold.Date < cutoff {
				continue
			}
			key := cold.ProfileName + "\x00" + cold.Date
			current := byKey[key]
			current.ProfileName = cold.ProfileName
			current.Date = cold.Date
			current.InputTokens += cold.InputTokens
			current.OutputTokens += cold.OutputTokens
			current.CacheReadTokens += cold.CacheReadTokens
			byKey[key] = current
		}
	}
	out = out[:0]
	for _, current := range byKey {
		out = append(out, current)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Date != out[j].Date {
			return out[i].Date < out[j].Date
		}
		return out[i].ProfileName < out[j].ProfileName
	})
	return out, nil
}

// JudgeDayUsage is one UTC-day token bucket for the intercept fallback judge,
// for the config page's recent-spend sparkline.
type JudgeDayUsage struct {
	Date         string `json:"date"` // YYYY-MM-DD (UTC)
	Calls        int    `json:"calls"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
}

// JudgeUsage is the cumulative token spend of the intercept fallback judge
// (worker='judge' rows in the always-on ledger), plus a recent daily series.
type JudgeUsage struct {
	Calls            int             `json:"calls"`
	InputTokens      int             `json:"input_tokens"`
	OutputTokens     int             `json:"output_tokens"`
	CacheReadTokens  int             `json:"cache_read_tokens"`
	CacheWriteTokens int             `json:"cache_write_tokens"`
	Daily            []JudgeDayUsage `json:"daily"`
}

// JudgeUsageStats returns the fallback judge's all-time token totals and a
// per-day series over the past `days` days (default 30). Sourced from the
// always-on llm_usage ledger, so it is accurate across pool rotation and
// interrupted/failed judge calls. days only bounds the daily series; totals are
// all-time.
func (d *DB) JudgeUsageStats(days int) (JudgeUsage, error) {
	if days <= 0 {
		days = 30
	}
	var u JudgeUsage
	err := d.QueryRow(`
SELECT COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage
WHERE worker = 'judge'`).Scan(&u.Calls, &u.InputTokens, &u.OutputTokens,
		&u.CacheReadTokens, &u.CacheWriteTokens)
	if err != nil {
		return JudgeUsage{}, err
	}
	rows, err := d.Query(`
SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
       COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)
FROM llm_usage
WHERE worker = 'judge' AND ts >= now() - ($1 * interval '1 day')
GROUP BY day
ORDER BY day`, days)
	if err != nil {
		return JudgeUsage{}, err
	}
	defer rows.Close()
	u.Daily = []JudgeDayUsage{}
	for rows.Next() {
		var day JudgeDayUsage
		if err := rows.Scan(&day.Date, &day.Calls, &day.InputTokens, &day.OutputTokens); err != nil {
			return JudgeUsage{}, err
		}
		u.Daily = append(u.Daily, day)
	}
	if err := rows.Err(); err != nil {
		return JudgeUsage{}, err
	}
	return u, nil
}

// ParseExpID turns the exploration-id segment parsed from a session string into an
// int64 (0 when empty/non-numeric, e.g. chat sessions keyed by conversation id).
func ParseExpID(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
