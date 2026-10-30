package server

import (
	"encoding/json"
	"log"

	"github.com/Autumn-27/artex/agent"
)

// SeedTool is first-insert-only. Add the optional input to old DB schemas,
// preserving edited descriptions/defaults, bindings and disabled flags. Do not
// bump the broad refresh flag: that would overwrite unrelated tool settings.
func (s *Server) seedIntentContinuationSchema() {
	const flag = "intent_continuation_schema_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	var property json.RawMessage
	for _, seed := range agent.BuiltinToolSeeds() {
		if seed.Key == "add_intent" {
			properties, _ := seed.Schema["properties"].(map[string]any)
			property, _ = json.Marshal(properties["source_intent_id"])
		}
	}
	if len(property) == 0 || string(property) == "null" {
		return
	}
	var raw string
	err := s.m.pg.QueryRow(`SELECT schema::text FROM tools WHERE key='add_intent' AND system`).Scan(&raw)
	if err != nil {
		log.Printf("[tools] continuation schema read: %v", err)
		return
	}
	var schema map[string]any
	if json.Unmarshal([]byte(raw), &schema) != nil || schema == nil {
		return
	}
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
		schema["properties"] = props
	}
	if _, exists := props["source_intent_id"]; !exists {
		props["source_intent_id"] = property
	}
	// A compare-and-set avoids overwriting a concurrent UI edit. Retry next start
	// if the schema moved; no successful marker is written in that case.
	updated, _ := json.Marshal(schema)
	res, err := s.m.pg.Exec(`UPDATE tools SET schema=$1::jsonb,updated_at=now() WHERE key='add_intent' AND system AND schema=$2::jsonb`, string(updated), raw)
	if err != nil {
		log.Printf("[tools] continuation schema update: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[tools] continuation schema marker: %v", err)
	}
}
