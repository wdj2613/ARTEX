package server

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestFindingRecordIncludesVerificationHandoff(t *testing.T) {
	s, _, ids := testCaseServer(t)
	raw, err := s.performFindingCaseTool(context.Background(), "get_finding_record", findingCaseRequest{FindingID: json.RawMessage(fmt.Sprint(ids[0]))})
	if err != nil {
		t.Fatal(err)
	}
	out := raw.(map[string]any)
	h, ok := out["verification_handoff"].(db.VerificationHandoff)
	if !ok || !h.NeedsReview || h.RetestCount != 0 {
		t.Fatalf("handoff=%v", out)
	}
	var n int
	if err = s.m.pg.QueryRow(`SELECT count(*) FROM finding_retests WHERE finding_id=$1`, ids[0]).Scan(&n); err != nil || n != 0 {
		t.Fatal("reading started retest")
	}
}
