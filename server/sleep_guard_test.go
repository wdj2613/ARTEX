package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func bashInput(command string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"command": command})
	return b
}

// 只有"过长的阻塞 sleep"才拦：短等待（等限速窗口、等文件落盘）是正常做法，拦掉反而
// 逼模型去写更差的绕圈逻辑。
func TestBlockingSleepSecondsFlagsLongBlockingWaits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cmd  string
		want float64
		hit  bool
	}{
		{"裸 sleep 115（线上最常见）", "sleep 115", 115, true},
		{"sleep 带秒单位", "sleep 120s", 120, true},
		{"分钟单位", "sleep 2m", 120, true},
		{"cd 之后 sleep", "cd /app/data/tasks/4/i722 && sleep 115; tail -1 run.out", 115, true},
		{"分号串联", "date; sleep 60", 60, true},
		{"或运算符串联", "true || sleep 90", 90, true},
		{"多次 sleep 取最大", "sleep 20; grep -c 429 log; sleep 45", 45, true},
		{"恰好到阈值", "sleep 30", 30, true},
		{"短等待放行", "sleep 5", 0, false},
		{"阈值以下放行", "sleep 29", 0, false},
		{"带抖动的短等待放行", "sleep 0.5; curl -s http://t/", 0, false},
		{"不是 sleep 命令", "grep -c 命中 run.log", 0, false},
		{"sleep 出现在参数里不算", "echo sleep 115", 0, false},
		{"行内脚本里的 sleep 不管", "python3 -c 'import time; time.sleep(300)'", 0, false},
		{"空命令", "", 0, false},
	}
	for _, c := range cases {
		got, hit := blockingSleepSeconds("Bash", bashInput(c.cmd))
		if hit != c.hit || (c.hit && got != c.want) {
			t.Errorf("%s: blockingSleepSeconds(%q)=(%v,%v) want=(%v,%v)", c.name, c.cmd, got, hit, c.want, c.hit)
		}
	}
}

// 后台调用不算阻塞：命令本身就在后台跑，sleep 不占用意图预算。
func TestBlockingSleepSecondsIgnoresBackgroundCalls(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(map[string]any{"command": "sleep 600", "run_in_background": true})
	if secs, hit := blockingSleepSeconds("Bash", raw); hit {
		t.Fatalf("run_in_background 的 sleep 不应被拦: %vs", secs)
	}
	// 非 Bash 工具一律不管（shell_send 等属于交互式会话，节奏由人控制）。
	if _, hit := blockingSleepSeconds("shell_send", bashInput("sleep 600")); hit {
		t.Fatal("非 Bash 工具不应走这条闸")
	}
	if _, hit := blockingSleepSeconds("Bash", nil); hit {
		t.Fatal("空入参不应命中")
	}
}

// 拦截提示必须同时给出"为什么"和"怎么改"，否则模型会当成目标侧防御反复换写法重试。
func TestBlockingSleepNudgeTeachesAlternative(t *testing.T) {
	t.Parallel()
	msg := blockingSleepNudge(115)
	for _, want := range []string{"sleep 115", "已被拦截", "run_in_background", "TaskOutput", "grep -c", "不超过 30 秒"} {
		if !strings.Contains(msg, want) {
			t.Errorf("提示缺少 %q: %s", want, msg)
		}
	}
}

// 闸要挂在 worker 的钩子上才算生效：这里直接驱动 steerHooks.PreToolUse，确认过长的
// sleep 被拦、且纠偏消息随拦截返回（模型据此换做法），而正常调用原样放行。
func TestSteerHooksBlocksLongSleep(t *testing.T) {
	t.Parallel()
	hooks := steerHooks{drain: func() (string, bool) { return "", false }, label: "worker-test · #1"}
	blocked, msg, _ := hooks.PreToolUse(t.Context(), "Bash", bashInput("cd /app/data/tasks/4/i722 && sleep 115; tail -1 run.out"))
	if !blocked {
		t.Fatal("长 sleep 应被拦截")
	}
	if !strings.Contains(msg, "禁止阻塞等待") || !strings.Contains(msg, "run_in_background") {
		t.Fatalf("拦截消息应给出替代做法: %q", msg)
	}
	allowed := [][2]string{
		{"Bash", "sleep 5"},
		{"Bash", `{"command":"sleep 600","run_in_background":true}`},
		{"Grep", "sleep 115"},
	}
	for _, c := range allowed {
		raw := json.RawMessage(c[1])
		if c[0] == "Bash" && !strings.HasPrefix(c[1], "{") {
			raw = bashInput(c[1])
		}
		if blocked, msg, _ := hooks.PreToolUse(t.Context(), c[0], raw); blocked {
			t.Errorf("%s %q 不应被拦: %s", c[0], c[1], msg)
		}
	}
}
