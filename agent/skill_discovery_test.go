package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
)

func TestSkillDiscoveryIsBoundedAndDoesNotUnlock(t *testing.T) {
	calls := 0
	reg := skill.NewRegistry(skill.Skill{Name: "allowed", Description: "local procedure", Instructions: "PRIVATE FULL BODY", MCPs: []string{"browser"}})
	reg.OnInvoke = func(skill.Skill) string { calls++; return "unlocked" }
	hints := []SkillHint{}
	for i := 0; i < 20; i++ {
		hints = append(hints, SkillHint{Name: "allowed", Description: strings.Repeat("用途", 200)})
	}
	text := skillDiscoveryGuidance(hints, []actool.CoreTool{reg.Tool()})
	if text == "" || len([]rune(text)) > 2500 || strings.Contains(text, "PRIVATE FULL BODY") || calls != 0 {
		t.Fatalf("unbounded or invoked: length=%d calls=%d", len([]rune(text)), calls)
	}
	if skillDiscoveryGuidance(hints, nil) != "" {
		t.Fatal("advertised disabled Skill")
	}
	if skillDiscoveryGuidance(nil, []actool.CoreTool{reg.Tool()}) != "" {
		t.Fatal("advertised nonexistent skill")
	}
}
func TestSkillDiscoverySurvivesAssemblyAndRespectsFilter(t *testing.T) {
	oldAug, oldResolve := ToolAugment, ToolResolve
	defer func() { ToolAugment = oldAug; ToolResolve = oldResolve }()
	reg := skill.NewRegistry(skill.Skill{Name: "allowed", Description: "local", Instructions: "FULL SECRET"})
	ToolAugment = func(_ context.Context, _ string) ([]actool.CoreTool, DeferredInfo, func()) {
		return []actool.CoreTool{reg.Tool()}, DeferredInfo{VisibleSkillHints: []SkillHint{{Name: "allowed", Description: "local"}}}, nil
	}
	_, def, cleanup := AugmentTools(context.Background(), "worker", nil)
	defer cleanup()
	sys, _ := deferredSystem("CUSTOM PROMPT", def)
	if !strings.Contains(sys[0], "allowed") || strings.Contains(sys[0], "FULL SECRET") {
		t.Fatal("discovery assembly missing/bloated")
	}
	ToolResolve = func(_ context.Context, _ string, _ []actool.CoreTool) []actool.CoreTool { return nil }
	_, def, cleanup = AugmentTools(context.Background(), "worker", nil)
	defer cleanup()
	if def.SkillGuidance != "" {
		t.Fatal("ignored final visibility filtering")
	}
}
