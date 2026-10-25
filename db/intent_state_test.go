package db

import "testing"

// IntentTerminalState 是意图状态机的唯一事实源：存储层用它决定是否盖 completed_at，
// 工具层（planner 的 kill_work）用它判断"这条意图还需不需要终止"。两边一旦漂移，就会
// 出现"意图看起来还在跑、其实已经结束"或反过来"杀不掉"的线上问题。
func TestIntentTerminalState(t *testing.T) {
	t.Parallel()
	terminal := []string{"done", "blocked", "exhausted", "stopped"}
	for _, state := range terminal {
		if !IntentTerminalState(state) {
			t.Errorf("IntentTerminalState(%q)=false want=true", state)
		}
	}
	live := []string{"open", "running", "paused", "", "unknown"}
	for _, state := range live {
		if IntentTerminalState(state) {
			t.Errorf("IntentTerminalState(%q)=true want=false", state)
		}
	}
}
