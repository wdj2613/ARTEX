package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	actool "github.com/Autumn-27/norma/tool"
)

// Conditional reads do not cache DB data or silently omit it. Every call still
// reads current data; only a caller-provided matching version suppresses payload.
// Apply after DB tool overrides so old installations advertise the new optional
// field without resetting their descriptions, bindings, defaults or schema.
func conditionalReadTools(tools []actool.CoreTool) []actool.CoreTool {
	out := append([]actool.CoreTool(nil), tools...)
	for i, t := range out {
		if (t.Name() == "node_detail" || t.Name() == "get_worker_output") && t.IsReadOnly(nil) {
			raw, _ := json.Marshal(t.InputSchema())
			var schema map[string]any
			_ = json.Unmarshal(raw, &schema)
			if schema == nil {
				continue
			}
			props, _ := schema["properties"].(map[string]any)
			if props == nil {
				props = map[string]any{}
				schema["properties"] = props
			}
			if _, exists := props["if_version"]; exists {
				continue
			}
			props["if_version"] = str("可选：上次同工具同实体返回的 read_version；当前内容完全相同则返回 unchanged，不重发全文。缺少旧正文时省略本参数重新取全量。")
			out[i] = &conditionalReadTool{CoreTool: t, schema: schema}
		}
	}
	return out
}

type conditionalReadTool struct {
	actool.CoreTool
	schema map[string]any
}

func (t *conditionalReadTool) InputSchema() map[string]any { return t.schema }
func (t *conditionalReadTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var args map[string]json.RawMessage
	if json.Unmarshal(in, &args) != nil {
		return t.CoreTool.Call(ctx, in, tc)
	}
	var previous string
	_ = json.Unmarshal(args["if_version"], &previous)
	delete(args, "if_version")
	clean, _ := json.Marshal(args)
	result, err := t.CoreTool.Call(ctx, clean, tc)
	if err != nil || result.IsError {
		return result, err
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(result.Flatten()), &value) != nil || value == nil {
		return result, nil
	}
	// Include exact identity and all source fields, including evidence/traffic and
	// inherited-source metadata. Changes outside node content_version still count.
	normalized, _ := json.Marshal(value)
	sum := sha256.Sum256(append(append([]byte(t.Name()+":"), clean...), normalized...))
	version := hex.EncodeToString(sum[:])
	if previous == version {
		return jsonResult(map[string]any{"unchanged": true, "read_version": version, "note": "当前内容与该版本一致。复用已读正文；若已压缩/丢失旧正文，请省略 if_version 重取。"})
	}
	value["read_version"], _ = json.Marshal(version)
	return jsonResult(value)
}
