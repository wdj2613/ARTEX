package agent

// Regression tests for the late-stage compaction pathologies seen in production
// (task 6, 2026-10-26): blocks that grew to 360+ members were refused by the
// model ("empty body from model") on every planner round, a major retired the
// old digests before its replacements existed (coverage dropped, the cold set
// grew back, the same block retried), and one shared 5-minute budget let a slow
// block starve every block behind it.

import (
	"context"
	"fmt"
	"iter"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

// fakeCompressProvider answers compaction calls: it fails (the way the model
// did) whenever the rendered block is longer than limit, and succeeds otherwise.
type fakeCompressProvider struct {
	limit int
	calls int
}

func (f *fakeCompressProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func (f *fakeCompressProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	f.calls++
	if err := ctx.Err(); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	size := 0
	for _, m := range req.Messages {
		size += len(m.Text())
	}
	if f.limit > 0 && size > f.limit {
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("empty body from model")
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("这一片探索得出了一条结论（#1）。")}}, "", llm.Usage{}, nil
}

// TestPartitionCapsBlockSize is the direct guard against 360-member blocks: an
// oversized connected component is cut into chunks of at most MaxMembers, and
// every member is assigned exactly once.
func TestPartitionCapsBlockSize(t *testing.T) {
	const n = 95
	nodes := make([]cgNode, 0, n)
	edges := make([]cgEdge, 0, n-1)
	for i := int64(1); i <= n; i++ {
		nodes = append(nodes, fact(i))
		if i > 1 {
			edges = append(edges, yields(i-1, i)) // one long chain → one component
		}
	}
	g := newColdGraph(nodes, edges)
	ids := make([]int64, 0, n)
	for i := int64(1); i <= n; i++ {
		ids = append(ids, i)
	}
	chunks := g.partition(ids, 40)
	if len(chunks) != 3 {
		t.Fatalf("95 members with MaxMembers=40 → want 3 chunks, got %d (%v)", len(chunks), chunks)
	}
	seen := map[int64]int{}
	for _, c := range chunks {
		if len(c) > 40 {
			t.Fatalf("chunk over the cap: %d members", len(c))
		}
		for _, id := range c {
			seen[id]++
		}
	}
	for i := int64(1); i <= n; i++ {
		if seen[i] != 1 {
			t.Fatalf("member %d assigned %d times, want exactly 1", i, seen[i])
		}
	}
}

// TestGroupCapsOversizedComponent runs the cap through group(), i.e. the path the
// compactor actually uses, and checks the partitions still carry anchors.
func TestGroupCapsOversizedComponent(t *testing.T) {
	// hot parent #100, then 60 cold children hanging off it (shared-parent rule
	// §3.1 merges them into one component).
	nodes := []cgNode{intent(100, "running")}
	edges := []cgEdge{}
	for i := int64(1); i <= 60; i++ {
		nodes = append(nodes, fact(i))
		edges = append(edges, derived(100, i))
	}
	g := newColdGraph(nodes, edges)
	set := map[int64]bool{}
	for i := int64(1); i <= 60; i++ {
		set[i] = true
	}
	p := defaultColdParams()
	if p.MaxMembers != 40 {
		t.Fatalf("default MaxMembers = %d, want 40", p.MaxMembers)
	}
	blocks := g.group(set, p)
	if len(blocks) != 2 {
		t.Fatalf("60 cold siblings → want 2 blocks of ≤40, got %d", len(blocks))
	}
	total := 0
	for _, b := range blocks {
		if len(b.Members) > p.MaxMembers {
			t.Fatalf("block over cap: %d members", len(b.Members))
		}
		if len(b.Anchors) == 0 || b.Anchors[0] != 100 {
			t.Fatalf("block lost its shared-parent anchor: %v", b.Anchors)
		}
		total += len(b.Members)
	}
	if total != 60 {
		t.Fatalf("members covered = %d, want 60", total)
	}
}

// TestRetirableDigestsNeverDropsCoverage: a stale digest may only be retired once
// every member of it is covered again. This is the fix for the runaway loop where
// superseding first and compressing second silently un-covered members.
func TestRetirableDigestsNeverDropsCoverage(t *testing.T) {
	old := staleDigest{id: 7, members: []int64{1, 2, 3}}
	other := staleDigest{id: 8, members: []int64{4, 5}}
	stale := []staleDigest{old, other}

	// Nothing re-covered → retire nothing.
	if got := retirableDigests(stale, nil, nil); len(got) != 0 {
		t.Fatalf("nothing covered → want no retirement, got %v", got)
	}
	// Partial re-coverage → still keep both.
	if got := retirableDigests(stale, nil, [][]int64{{1, 2}}); len(got) != 0 {
		t.Fatalf("partial coverage → want no retirement, got %v", got)
	}
	// 7 fully re-created by a fresh block, 8 covered by a surviving digest.
	got := retirableDigests(stale, []staleDigest{{id: 99, members: []int64{4, 5}}}, [][]int64{{1, 2, 3}})
	if len(got) != 2 || got[0] != 7 || got[1] != 8 {
		t.Fatalf("want [7 8] retirable, got %v", got)
	}
	// A survivor that does not cover 8's members must not enable 8's retirement.
	got = retirableDigests(stale, []staleDigest{{id: 99, members: []int64{4}}}, [][]int64{{1, 2, 3}})
	if len(got) != 1 || got[0] != 7 {
		t.Fatalf("want only [7], got %v", got)
	}
}

// TestBlockFailureBackoff: a refused block must stop being re-sent every round.
func TestBlockFailureBackoff(t *testing.T) {
	c := NewCompactor(nil, "")
	const sig = "sig-a"
	if c.retryBlocked(sig, 10) {
		t.Fatal("fresh block must not be blocked")
	}
	c.noteBlockFailure(sig, 10) // skip 1 round
	if !c.retryBlocked(sig, 10) || c.retryBlocked(sig, 11) {
		t.Fatal("after 1 failure the block should be blocked only in round 10")
	}
	c.noteBlockFailure(sig, 11) // 2 failures → skip 2 rounds (resume at round 13)
	if !c.retryBlocked(sig, 12) || c.retryBlocked(sig, 13) {
		t.Fatal("2 failures must buy a 2-round backoff")
	}
	for i := 0; i < 5; i++ { // cap at 8 rounds, not unbounded
		c.noteBlockFailure(sig, 20)
	}
	if !c.retryBlocked(sig, 27) || c.retryBlocked(sig, 28) {
		t.Fatal("backoff should cap at 8 rounds")
	}
	c.noteBlockSuccess(sig)
	if c.retryBlocked(sig, 28) {
		t.Fatal("success must clear the backoff")
	}
}

// --- DB-backed: fold/retire behaviour ---

func newTestExploration(t *testing.T, d *db.DB) int64 {
	t.Helper()
	var id int64
	if err := d.QueryRow(`INSERT INTO explorations(description, goal) VALUES($1,$2) RETURNING id`,
		"compaction robustness test", "fold blocks").Scan(&id); err != nil {
		t.Fatalf("create exploration: %v", err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM exploration_edges WHERE exploration_id=$1`, id)
		d.Exec(`DELETE FROM exploration_nodes WHERE exploration_id=$1`, id)
		d.Exec(`DELETE FROM explorations WHERE id=$1`, id)
	})
	return id
}

func addTestFacts(t *testing.T, d *db.DB, expID int64, n int) []int64 {
	t.Helper()
	var ids []int64
	for i := 0; i < n; i++ {
		var id int64
		payload := fmt.Sprintf(`{"summary":"事实 %d：目标站点存在登录入口，用户名可枚举","confidence":"observed"}`, i+1)
		if err := d.QueryRow(`INSERT INTO exploration_nodes(exploration_id, kind, payload, state)
			VALUES($1,$2,$3,$4) RETURNING id`, expID, db.KindFact, payload, "confirmed").Scan(&id); err != nil {
			t.Fatalf("insert fact: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

// TestFoldBlockBisectsOversizedBlock: when the model refuses a block, the block is
// halved and the halves are folded, so coverage still advances instead of the whole
// block being lost.
func TestFoldBlockBisectsOversizedBlock(t *testing.T) {
	d := testDB(t)
	expID := newTestExploration(t, d)
	memberIDs := addTestFacts(t, d, expID, 6)
	ts := d.Exploration(expID)

	nodes, err := ts.Nodes(1000)
	if err != nil {
		t.Fatalf("load nodes: %v", err)
	}
	byID := map[int64]*db.Node{}
	cgNodes := make([]cgNode, 0, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
		cgNodes = append(cgNodes, cgNode{ID: n.ID, Kind: n.Kind, State: n.State})
	}
	g := newColdGraph(cgNodes, nil)
	cvers, err := ts.ContentVersions()
	if err != nil {
		t.Fatalf("content versions: %v", err)
	}

	// A limit that the 6-member block always exceeds but a 3-member half fits.
	full := buildCompressionInput(g, block{Members: memberIDs}, byID)
	half := buildCompressionInput(g, block{Members: memberIDs[:3]}, byID)
	prov := &fakeCompressProvider{limit: (len(full) + len(half)) / 2}
	if len(full) <= prov.limit || len(half) > prov.limit {
		t.Fatalf("test setup: full=%d half=%d limit=%d", len(full), len(half), prov.limit)
	}

	c := NewCompactor(prov, "test-model")
	covered := c.foldBlock(context.Background(), ts, g, block{Members: memberIDs}, byID, cvers, 1, 1)
	if len(covered) != 6 {
		t.Fatalf("bisected fold covered %d members, want 6 (%v)", len(covered), covered)
	}
	cov, err := ts.CoveredMembers()
	if err != nil {
		t.Fatalf("covered members: %v", err)
	}
	for _, id := range memberIDs {
		if _, ok := cov[id]; !ok {
			t.Fatalf("member %d left uncovered after a bisected fold", id)
		}
	}
}

// TestMajorKeepsCoverageWhenCompressionFails: an existing digest must survive a
// major in which every compression fails — otherwise its members silently become
// "uncompressed", the cold set regrows past the minor threshold and the same block
// is retried on every planner round (the production loop).
func TestMajorKeepsCoverageWhenCompressionFails(t *testing.T) {
	d := testDB(t)
	expID := newTestExploration(t, d)
	memberIDs := addTestFacts(t, d, expID, 4)
	ts := d.Exploration(expID)

	oldID, err := ts.AddDigest(map[string]any{
		"body":       "旧结论：登录入口可枚举用户名（#…）",
		"member_ids": map[string]any{"facts": memberIDs, "intents": []int64{}},
		"generation": 1,
		"signature":  "signature-from-a-previous-major",
	}, memberIDs)
	if err != nil {
		t.Fatalf("seed digest: %v", err)
	}

	// Every compression fails; no cold stamps exist so no block is eligible either.
	prov := &fakeCompressProvider{limit: 1}
	c := NewCompactor(prov, "test-model")
	c.major(context.Background(), ts)

	active, err := ts.ActiveDigests()
	if err != nil {
		t.Fatalf("active digests: %v", err)
	}
	found := false
	for _, a := range active {
		if a.ID == oldID {
			found = true
		}
	}
	if !found {
		t.Fatalf("digest %d was retired without a replacement — coverage dropped", oldID)
	}
	cov, err := ts.CoveredMembers()
	if err != nil {
		t.Fatalf("covered members: %v", err)
	}
	for _, id := range memberIDs {
		if cov[id] != oldID {
			t.Fatalf("member %d no longer covered by the surviving digest (got %d)", id, cov[id])
		}
	}
}
