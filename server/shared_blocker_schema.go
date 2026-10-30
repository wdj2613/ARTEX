package server

import (
	"encoding/json"
	"log"

	"github.com/Autumn-27/artex/agent"
)

func (s *Server) seedSharedBlockerSchema() {
	const flag = "shared_blocker_schema_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, seed := range agent.BuiltinToolSeeds() {
		if seed.Key == "report_progress" {
			props, _ := seed.Schema["properties"].(map[string]any)
			raw, err := json.Marshal(props["blocker"])
			if err != nil || string(raw) == "null" {
				return
			}
			_, err = s.m.pg.Exec(`UPDATE tools SET schema=jsonb_set(schema,'{properties,blocker}',$1::jsonb,true),updated_at=now() WHERE key='report_progress' AND system AND NOT(COALESCE(schema->'properties','{}'::jsonb)?'blocker')`, string(raw))
			if err != nil {
				log.Printf("[tools] blocker schema: %v", err)
				return
			}
			_ = s.m.pg.SetSetting(flag, "true")
			return
		}
	}
}
