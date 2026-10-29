package server

import (
	"errors"
	"testing"
)

// 主 Agent 边界闸的归一化：写错配置不能把闸悄悄关掉（那等于把主 Agent 放回"自己下场"的
// 老路），缺省必须是 warn。
func TestMainAgentDirectActionOf(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
		ok    bool
		err   error
		want  string
	}{
		{"未配置", "", false, nil, "warn"},
		{"off", "off", true, nil, "off"},
		{"warn", "warn", true, nil, "warn"},
		{"block", "block", true, nil, "block"},
		{"大小写与空格", "  Block ", true, nil, "block"},
		{"写错的值按 warn", "b1ock", true, nil, "warn"},
		{"读库出错按 warn", "", false, errors.New("boom"), "warn"},
	}
	for _, c := range cases {
		got := mainAgentDirectActionOf(func() (string, bool, error) { return c.value, c.ok, c.err })
		if got != c.want {
			t.Errorf("%s: mainAgentDirectActionOf=%q want=%q", c.name, got, c.want)
		}
	}
}

// 设置项要走通 API：未配置回显 warn（不是空），PUT 能落库并即时回显，非法值被拒且不覆盖旧值。
func TestMainAgentDirectActionSettingAPIRoundTrip(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	pg := s.m.pg
	if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, settingMainAgentDirectAction); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.SetSetting(settingMainAgentDirectAction, "warn") })

	if got := s.settingsPayload()[settingMainAgentDirectAction]; got != "warn" {
		t.Fatalf("未配置时应回显 warn: %v", got)
	}
	if r := request("PUT", "/api/settings", `{"mainagent_direct_action":"block"}`); r.Code != 200 {
		t.Fatalf("PUT 失败: %d %s", r.Code, r.Body)
	}
	if v, ok, _ := pg.GetSetting(settingMainAgentDirectAction); !ok || v != "block" {
		t.Fatalf("未落库: %q ok=%v", v, ok)
	}
	if got := s.settingsPayload()[settingMainAgentDirectAction]; got != "block" {
		t.Fatalf("改完应即时回显: %v", got)
	}
	if r := request("PUT", "/api/settings", `{"mainagent_direct_action":"nope"}`); r.Code != 400 {
		t.Fatalf("非法值应被拒: %d %s", r.Code, r.Body)
	}
	if v, _, _ := pg.GetSetting(settingMainAgentDirectAction); v != "block" {
		t.Fatalf("非法值不该覆盖旧值: %q", v)
	}
}
