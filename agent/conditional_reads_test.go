package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Autumn-27/norma/tool"
)

func TestConditionalNodeReadInvalidatesOnContent(t *testing.T) {
	_, ts, id := continuationFixture(t)
	wrapped := conditionalReadTools([]tool.CoreTool{ts.nodeDetail()})[0]
	read := func(version string) map[string]any {
		t.Helper()
		in, _ := json.Marshal(map[string]any{"id": id, "if_version": version})
		res, err := wrapped.Call(context.Background(), in, nil)
		if err != nil || res.IsError {
			t.Fatalf("%v %s", err, res.Flatten())
		}
		var out map[string]any
		if err = json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	full := read("")
	v, ok := full["read_version"].(string)
	if !ok || v == "" || full["payload"] == nil {
		t.Fatalf("first=%v", full)
	}
	same := read(v)
	if same["unchanged"] != true || same["payload"] != nil {
		t.Fatalf("repeat=%v", same)
	}
	if err := ts.ts.SetIntentProgress(id, map[string]any{"note": "new evidence"}); err != nil {
		t.Fatal(err)
	}
	changed := read(v)
	if changed["unchanged"] == true || changed["payload"] == nil || changed["read_version"] == v {
		t.Fatal("served stale content")
	}
	if read("")["payload"] == nil {
		t.Fatal("cannot recover evicted context")
	}
}
func TestConditionalReadDoesNotSuppressErrorsOrDifferentEntities(t *testing.T) {
	_, ts, id := continuationFixture(t)
	wrapper := conditionalReadTools([]tool.CoreTool{ts.nodeDetail()})[0]
	res, _ := wrapper.Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"id":%d}`, id)), nil)
	var full map[string]any
	_ = json.Unmarshal([]byte(res.Flatten()), &full)
	missing, _ := wrapper.Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"id":99999999,"if_version":%q}`, full["read_version"])), nil)
	if !missing.IsError {
		t.Fatal("error was suppressed")
	}
	plain := ts.nodeDetail().InputSchema()["properties"].(map[string]any)
	if plain["if_version"] != nil {
		t.Fatal("mutated original schema")
	}
}
