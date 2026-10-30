package agent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Reports are observations, not health probes or permission to switch endpoints.
// A short TTL prevents forgotten reports from suppressing future exploration.
const sharedBlockerTTL = 15 * time.Minute

var blockerKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

type sharedBlocker struct {
	Key        string `json:"key"`
	State      string `json:"state"`
	Evidence   string `json:"evidence"`
	ReportedAt string `json:"reported_at"`
	IntentID   int64  `json:"intent_id"`
}

func prepareSharedBlocker(raw json.RawMessage, id int64) (*sharedBlocker, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var b sharedBlocker
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("blocker 格式错误: %w", err)
	}
	if !blockerKeyPattern.MatchString(b.Key) || (b.State != "blocked" && b.State != "resolved") || strings.TrimSpace(b.Evidence) == "" {
		return nil, fmt.Errorf("blocker 需要资源短名 key（小写字母/数字/._-，不含凭据）、state=blocked|resolved 和 evidence；单次失败不足以推定公共故障")
	}
	b.Evidence = truncateRunes(strings.TrimSpace(b.Evidence), 300)
	b.ReportedAt = time.Now().UTC().Format(time.RFC3339Nano)
	b.IntentID = id
	return &b, nil
}
func currentSharedBlockers(nodes []*db.Node, now time.Time) []sharedBlocker {
	latest := map[string]sharedBlocker{}
	times := map[string]time.Time{}
	for _, n := range nodes {
		if n.Kind != db.KindIntent || n.State == "deleted" {
			continue
		}
		var p struct {
			Progress struct {
				Blocker *sharedBlocker `json:"blocker"`
			} `json:"progress"`
		}
		if json.Unmarshal(n.Payload, &p) != nil || p.Progress.Blocker == nil {
			continue
		}
		b := *p.Progress.Blocker
		at, err := time.Parse(time.RFC3339Nano, b.ReportedAt)
		if err != nil || !blockerKeyPattern.MatchString(b.Key) || at.After(now) || now.Sub(at) > sharedBlockerTTL {
			continue
		}
		if old, ok := times[b.Key]; ok && !at.After(old) {
			continue
		}
		b.IntentID = n.ID
		b.Evidence = truncateRunes(b.Evidence, 300)
		latest[b.Key] = b
		times[b.Key] = at
	}
	out := []sharedBlocker{}
	for _, b := range latest {
		if b.State == "blocked" {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

const sharedBlockerSpec = `

【共同阻塞处理（观察提示，不自动暂停）】
report_progress 可用 blocker={key:"egress-proxy",state:"blocked",evidence:"已核实的公共依赖故障与检查结果"} 交接公共阻塞；key 用资源短名，不放URL或凭据。先复用 shared_blockers 的检查，避免多个 worker 反复诊断同一出口。不要把单次目标失败推定为全局故障。恢复须经实际检查后报告 state=resolved；报告15分钟过期，不等于已恢复。规划者先核对依赖，再安排不依赖故障资源的剩余工作；不要无意义地重复派依赖未满足的同向工作，也不要据此标记目标达成。所有范围、出口和复测审批仍按现有约束；本提示不执行暂停、重试、换出口或恢复任务。
`
