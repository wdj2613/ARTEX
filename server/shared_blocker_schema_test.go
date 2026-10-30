package server

import (
	"encoding/json"
	"testing"
)

func TestSharedBlockerSchemaPreservesOverrides(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	_, err := s.m.pg.Exec(`UPDATE tools SET description='custom blocker description',enabled=false,agents='["mainagent"]'::jsonb,schema='{"type":"object","properties":{"note":{"type":"string","default":"custom note"}}}'::jsonb WHERE key='report_progress'`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.m.pg.Exec(`DELETE FROM settings WHERE key='shared_blocker_schema_v1'`)
	if err != nil {
		t.Fatal(err)
	}
	s.seedSharedBlockerSchema()
	row, err := s.m.pg.GetTool("report_progress")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	_ = json.Unmarshal(row.Schema, &schema)
	props := schema["properties"].(map[string]any)
	if props["blocker"] == nil || props["note"].(map[string]any)["default"] != "custom note" || row.Enabled || row.Description != "custom blocker description" || len(row.Agents) != 1 || row.Agents[0] != "mainagent" {
		t.Fatalf("override lost: %+v", row)
	}
}
