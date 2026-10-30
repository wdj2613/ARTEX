package db

import (
	"encoding/json"
	"testing"
)

// Unknown legacy progress must not become a measured zero. Exercise the actual
// SQL predicate and producer format rather than testing a second Go parser.
func TestVoidStatsYieldFormats(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cases := []struct {
		name    string
		value   any
		missing bool
		want    int
	}{
		{name: "engine zero", value: "事实0 资产0 漏洞0", want: 1},
		{name: "explicit intelligence zero", value: "事实0 资产0 漏洞0 情报0", want: 1},
		{name: "whitespace", value: " \t事实0  资产0\t漏洞0\n", want: 1},
		{name: "legacy zero", value: "0", want: 1},
		{name: "numeric zero", value: 0, want: 1},
		{name: "facts", value: "事实1 资产0 漏洞0"},
		{name: "assets", value: "事实0 资产2 漏洞0"},
		{name: "findings", value: "事实0 资产0 漏洞1"},
		{name: "intelligence", value: "事实0 资产0 漏洞0 情报1"},
		{name: "legacy positive", value: "3"},
		{name: "missing", missing: true},
		{name: "null", value: nil},
		{name: "empty", value: " "},
		{name: "unknown", value: "unknown"},
		{name: "partial", value: "事实0 资产0"},
		{name: "trailing unknown counter", value: "事实0 资产0 漏洞0 自定义1"},
		{name: "object", value: map[string]any{"count": 0}},
		{name: "array", value: []int{0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exp, err := d.CreateExploration("yield formats", tc.name)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Exec(`DELETE FROM explorations WHERE id=$1`, exp)
			es := d.Exploration(exp)
			id, err := es.AddIntent(map[string]any{"summary": tc.name}, 5, nil, "planner")
			if err != nil {
				t.Fatal(err)
			}
			progress := map[string]any{}
			if !tc.missing {
				progress["yields"] = tc.value
			}
			raw, err := json.Marshal(progress)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = d.Exec(`UPDATE exploration_nodes SET state='done',payload=jsonb_set(payload,'{progress}',$2::jsonb) WHERE id=$1`, id, string(raw)); err != nil {
				t.Fatal(err)
			}
			got, err := es.VoidStats()
			if err != nil {
				t.Fatal(err)
			}
			if got.TerminalIntents != 1 || got.ZeroYieldIntents != tc.want {
				t.Fatalf("VoidStats=%+v, want terminal=1 zero=%d", got, tc.want)
			}
		})
	}
}
