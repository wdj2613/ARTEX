package db

import "testing"

func TestFindingVerificationHandoff(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("verification fixture", "no probes", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	id, err := d.AddFinding(task.ID, 0, "TEST", "fixture", "high", "claim", "", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id=$1`, id)
	f, err := d.GetFinding(id)
	if err != nil {
		t.Fatal(err)
	}
	h, err := d.FindingVerificationHandoff(f)
	if err != nil {
		t.Fatal(err)
	}
	if !h.NeedsReview || h.EvidencePresent || h.RetestCount != 0 {
		t.Fatalf("empty=%+v", h)
	}
	if _, err = d.Exec(`UPDATE findings SET evidence='saved evidence',asset_ids='[1]'::jsonb,evidence_version=2,report='report' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	f, _ = d.GetFinding(id)
	// Directly seed historical results; no retester is launched.
	if _, err = d.Exec(`INSERT INTO finding_retests(finding_id,status,verdict,snapshot) VALUES($1,'completed','reproduced','{"finding":{"evidence_version":2}}'::jsonb)`, id); err != nil {
		t.Fatal(err)
	}
	h, err = d.FindingVerificationHandoff(f)
	if err != nil {
		t.Fatal(err)
	}
	if h.NeedsReview || !h.ReportPresent || h.LatestVerdict != "reproduced" {
		t.Fatalf("confirmed=%+v", h)
	}
	f.EvidenceVersion = 3
	h, err = d.FindingVerificationHandoff(f)
	if err != nil || !h.NeedsReview || !h.EvidenceChangedSinceRetest {
		t.Fatalf("stale=%+v err=%v", h, err)
	}
	if _, err = d.Exec(`INSERT INTO finding_retests(finding_id,status,verdict,snapshot) VALUES($1,'completed','inconclusive','{}'::jsonb)`, id); err != nil {
		t.Fatal(err)
	}
	h, err = d.FindingVerificationHandoff(f)
	if err != nil || h.LatestVerdict != "inconclusive" || !h.NeedsReview {
		t.Fatalf("newer failed=%+v %v", h, err)
	}
	original, _ := d.GetFinding(id)
	if original.Status != FindingPending {
		t.Fatal("read helper mutated triage")
	}
}
