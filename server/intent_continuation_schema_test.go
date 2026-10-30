package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIntentContinuationSchemaUpgradePreservesCustomization(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	const custom = `{"type":"object","properties":{"summary":{"type":"string","description":"CUSTOM SUMMARY","default":"keep default"},"extra":{"type":"boolean"}},"required":["summary"]}`
	if _, err := s.m.pg.Exec(`UPDATE tools SET description='CUSTOM DESC',schema=$1::jsonb,agents='["mainagent"]'::jsonb,enabled=false,deferred=true WHERE key='add_intent'`, custom); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec(`DELETE FROM settings WHERE key='intent_continuation_schema_v1'`); err != nil {
		t.Fatal(err)
	}
	s.seedIntentContinuationSchema()
	row, err := s.m.pg.GetTool("add_intent")
	if err != nil || row == nil {
		t.Fatal(err)
	}
	if row.Description != "CUSTOM DESC" || row.Enabled || !row.Deferred || len(row.Agents) != 1 || row.Agents[0] != "mainagent" {
		t.Fatalf("lost configuration: %+v", row)
	}
	var schema map[string]any
	if err = json.Unmarshal(row.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	props := schema["properties"].(map[string]any)
	if props["source_intent_id"] == nil || props["extra"] == nil || props["summary"].(map[string]any)["default"] != "keep default" {
		t.Fatalf("schema=%s", row.Schema)
	}
	if got, _, _ := s.m.pg.GetSetting("intent_continuation_schema_v1"); got != "true" {
		t.Fatal("upgrade not marked complete")
	}
	if response := request("GET", "/api/tools", ""); response.Code != 200 || !strings.Contains(response.Body.String(), "source_intent_id") {
		t.Fatalf("schema not exposed by authenticated API: %d %s", response.Code, response.Body)
	}
	// Repeated startup neither resets the optional field's edited description nor
	// rewrites the user's bindings. This also covers new DBs already seeded with it.
	props["source_intent_id"].(map[string]any)["description"] = "CUSTOM SOURCE"
	raw, _ := json.Marshal(schema)
	if _, err := s.m.pg.Exec(`UPDATE tools SET schema=$1::jsonb WHERE key='add_intent'`, string(raw)); err != nil {
		t.Fatal(err)
	}
	s.seedIntentContinuationSchema()
	row, err = s.m.pg.GetTool("add_intent")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(row.Schema, &schema)
	if schema["properties"].(map[string]any)["source_intent_id"].(map[string]any)["description"] != "CUSTOM SOURCE" {
		t.Fatal("repeat startup overwrote field")
	}
	// If the field existed before the first migration it too remains user-owned.
	if _, err := s.m.pg.Exec(`DELETE FROM settings WHERE key='intent_continuation_schema_v1'`); err != nil {
		t.Fatal(err)
	}
	s.seedIntentContinuationSchema()
	row, _ = s.m.pg.GetTool("add_intent")
	_ = json.Unmarshal(row.Schema, &schema)
	if schema["properties"].(map[string]any)["source_intent_id"].(map[string]any)["description"] != "CUSTOM SOURCE" {
		t.Fatal("initial upgrade overwrote existing field")
	}
}
