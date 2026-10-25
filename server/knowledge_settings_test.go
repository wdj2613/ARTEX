package server

import (
	"errors"
	"testing"
)

// 额度归一化：写错/读库失败都不能把额度变成"无限制"，缺省回 6，上限夹到 50。
func TestKnowledgeQueryBudgetOf(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
		ok    bool
		err   error
		want  int
	}{
		{"未配置", "", false, nil, 6},
		{"正常值", "12", true, nil, 12},
		{"带空格", " 9 ", true, nil, 9},
		{"零按默认", "0", true, nil, 6},
		{"负数按默认", "-3", true, nil, 6},
		{"非数字按默认", "abc", true, nil, 6},
		{"超大夹到 50", "9999", true, nil, 50},
		{"读库出错按默认", "", false, errors.New("boom"), 6},
	}
	for _, c := range cases {
		got := knowledgeQueryBudgetOf(func() (string, bool, error) { return c.value, c.ok, c.err })
		if got != c.want {
			t.Errorf("%s: knowledgeQueryBudgetOf=%d want=%d", c.name, got, c.want)
		}
	}
}

// 设置项要走通 API：未配置时回显"开 + 6"，PUT 能落库并即时回显，越界值被拒且不覆盖旧值。
func TestKnowledgeSettingAPIRoundTrip(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	pg := s.m.pg
	if _, err := pg.Exec(`DELETE FROM settings WHERE key = ANY($1::text[])`,
		[]string{settingAgentKnowledgeSearch, settingAgentKnowledgeQueryBudget}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pg.SetBool(settingAgentKnowledgeSearch, true)
		_ = pg.SetSetting(settingAgentKnowledgeQueryBudget, "6")
	})

	payload := s.settingsPayload()
	if payload[settingAgentKnowledgeSearch] != true {
		t.Fatalf("未配置时应默认开启: %v", payload[settingAgentKnowledgeSearch])
	}
	if payload[settingAgentKnowledgeQueryBudget] != 6 {
		t.Fatalf("未配置时额度应回显 6: %v", payload[settingAgentKnowledgeQueryBudget])
	}

	if r := request("PUT", "/api/settings", `{"agent_knowledge_search":false,"agent_knowledge_query_budget":12}`); r.Code != 200 {
		t.Fatalf("PUT 失败: %d %s", r.Code, r.Body)
	}
	if v, ok, _ := pg.GetSetting(settingAgentKnowledgeSearch); !ok || v != "false" {
		t.Fatalf("开关未落库: %q ok=%v", v, ok)
	}
	if v, ok, _ := pg.GetSetting(settingAgentKnowledgeQueryBudget); !ok || v != "12" {
		t.Fatalf("额度未落库: %q ok=%v", v, ok)
	}
	payload = s.settingsPayload()
	if payload[settingAgentKnowledgeSearch] != false || payload[settingAgentKnowledgeQueryBudget] != 12 {
		t.Fatalf("改完应即时回显: %v / %v", payload[settingAgentKnowledgeSearch], payload[settingAgentKnowledgeQueryBudget])
	}

	for _, body := range []string{`{"agent_knowledge_query_budget":0}`, `{"agent_knowledge_query_budget":51}`} {
		if r := request("PUT", "/api/settings", body); r.Code != 400 {
			t.Fatalf("越界额度应被拒(%s): %d %s", body, r.Code, r.Body)
		}
	}
	if v, _, _ := pg.GetSetting(settingAgentKnowledgeQueryBudget); v != "12" {
		t.Fatalf("非法值不该覆盖旧值: %q", v)
	}
}
