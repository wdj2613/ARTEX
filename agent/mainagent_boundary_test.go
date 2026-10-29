package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// 边界闸的判定表：这些命令是线上主 Agent 卡死那 27 分钟里反复执行的那一类（curl / DNS /
// 扫描），必须命中；而"在本任务目录里读落盘结果"必须放行，否则闸会误伤主 Agent 唯一的
// 合法文件操作。
func TestMainAgentDirectActionHead(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cmd  string
		want string // 空 = 放行
	}{
		// —— 该拦：对目标动手 ——
		{"curl", `curl -sS -m 10 https://luoye.oopb.cn/login`, "curl"},
		{"curl 带 sudo 与 proxy 前缀", `sudo -u www http_proxy=http://127.0.0.1:7890 curl -I https://x.test`, "curl"},
		{"路径形式的 curl", `/usr/bin/curl -vk https://x.test`, "curl"},
		{"串联命令里的第二个", `echo hi && wget -qO- http://x.test/a`, "wget"},
		{"管道里的扫描器", `cat urls.txt | xargs -n1 nmap -p80`, "nmap"},
		{"sqlmap", `sqlmap -u "http://x.test/?id=1" --batch`, "sqlmap"},
		{"dig", `dig +short luoye.oopb.cn`, "dig"},
		{"ping", `ping -c 3 1.1.1.1`, "ping"},
		{"openssl s_client", `openssl s_client -connect x.test:443 -servername x.test`, "openssl s_client"},
		{"python requests", `python3 -c "import requests;print(requests.get('http://x.test').status_code)"`, "python3"},
		{"node fetch", `node -e "fetch('http://x.test')"`, "node"},
		{"nuclei", `nuclei -u https://x.test -silent`, "nuclei"},

		// —— 该放行：本地只读查看 ——
		{"读文件", `cat /tmp/task6/out.json`, ""},
		{"grep 日志里的 URL", `grep -o "https://[^ \"]*" run.log`, ""},
		{"jq 解析", `jq '.findings[] | .title' out.json`, ""},
		{"python 解析本地 JSON", `python3 -c "import json;print(len(json.load(open('out.json'))))"`, ""},
		{"逐行看目录", `ls -la work/ && wc -l work/*.log`, ""},
		{"普通空命令", ``, ""},
	}

	prev := MainAgentDirectActionMode
	t.Cleanup(func() { MainAgentDirectActionMode = prev })
	MainAgentDirectActionMode = func() string { return "warn" }

	for _, c := range cases {
		if got := directActionHead(c.cmd); got != c.want {
			t.Errorf("%s: directActionHead(%q)=%q want=%q", c.name, c.cmd, got, c.want)
		}
	}
}

// 钩子行为：warn 只拦"动手"命令并回替代做法；block 额外把非白名单命令拦掉。
func TestMainAgentBoundaryHooks(t *testing.T) {
	prev := MainAgentDirectActionMode
	t.Cleanup(func() { MainAgentDirectActionMode = prev })

	tool := func(name, cmd string) ([]byte, string) {
		b, _ := json.Marshal(map[string]string{"command": cmd})
		return b, name
	}

	// off：完全不介入
	MainAgentDirectActionMode = func() string { return "off" }
	in, name := tool("Bash", "curl -sv https://x.test")
	if blocked, _, _ := (mainAgentBoundaryHooks{}).PreToolUse(context.Background(), name, in); blocked {
		t.Fatal("off 模式不应拦截")
	}

	// warn：动手命令拦下且说明里给出派活通道；本地只读命令放行
	MainAgentDirectActionMode = func() string { return "warn" }
	in, name = tool("Bash", "curl -sv https://x.test")
	blocked, msg, _ := (mainAgentBoundaryHooks{}).PreToolUse(context.Background(), name, in)
	if !blocked {
		t.Fatal("warn 模式应拦下 curl")
	}
	for _, want := range []string{"add_intent", "steer_work", "人类操作员的接口"} {
		if !strings.Contains(msg, want) {
			t.Errorf("拦下说明缺少 %q: %s", want, msg)
		}
	}
	in, name = tool("Bash", "grep -n findings out.json")
	if blocked, _, _ = (mainAgentBoundaryHooks{}).PreToolUse(context.Background(), name, in); blocked {
		t.Fatal("warn 模式不应拦本地只读命令")
	}

	// block：只放行白名单首词
	MainAgentDirectActionMode = func() string { return "block" }
	in, name = tool("Bash", "grep -n findings out.json")
	if blocked, _, _ = (mainAgentBoundaryHooks{}).PreToolUse(context.Background(), name, in); blocked {
		t.Fatal("block 模式应放行 grep")
	}
	in, name = tool("Bash", "python3 build_report.py")
	blocked, msg, _ = (mainAgentBoundaryHooks{}).PreToolUse(context.Background(), name, in)
	if !blocked || !strings.Contains(msg, "只读查看命令") {
		t.Fatalf("block 模式应拦下非白名单命令并说明白名单: blocked=%v msg=%s", blocked, msg)
	}

	// 非 shell 工具一律不介入
	MainAgentDirectActionMode = func() string { return "block" }
	if blocked, _, _ = (mainAgentBoundaryHooks{}).PreToolUse(context.Background(), "list_facts", []byte(`{}`)); blocked {
		t.Fatal("非 shell 工具不应被边界闸干预")
	}
}

// 边界规则必须由代码拥有：DB 里改过的提示词正文也删不掉它，否则一次提示词编辑就能让主
// Agent 重新变回"自己下场"（线上那次卡死的根因之一就是正文没有约束）。
func TestMainAgentSystemCarriesBoundarySpec(t *testing.T) {
	prev := PromptOverride
	t.Cleanup(func() { PromptOverride = prev })

	// 模拟一份被改坏的提示词：故意不含任何边界措辞。
	PromptOverride = func(string) (string, bool) { return "你是主 Agent。目标：{{.Goal}}", true }

	sys := mainAgentSystem("目标 luoye", "/tmp/data", "/tmp/work")
	for _, want := range []string{"人机接口边界", "回答优先", "add_intent", "set_goals", "不直接对目标动手"} {
		if !strings.Contains(sys, want) {
			t.Errorf("系统提示词缺少代码拥有的边界规则 %q", want)
		}
	}
	// 追加而不是替换：正文还在。
	if !strings.Contains(sys, "你是主 Agent。目标：目标 luoye") {
		t.Errorf("边界块不该顶掉正文: %s", sys)
	}
}

// 默认力度：没接线或写错值都必须落到 warn——闸不能因为配置缺失而变成"看不见的开"。
func TestMainAgentDirectActionModeDefault(t *testing.T) {
	prev := MainAgentDirectActionMode
	t.Cleanup(func() { MainAgentDirectActionMode = prev })

	MainAgentDirectActionMode = nil
	if got := mainAgentDirectActionMode(); got != "warn" {
		t.Errorf("未接线时应回 warn，得到 %q", got)
	}
	for _, c := range []struct{ in, want string }{
		{"off", "off"}, {"warn", "warn"}, {"BLOCK", "block"}, {"  Block  ", "block"}, {"b1ock", "warn"}, {"", "warn"},
	} {
		MainAgentDirectActionMode = func() string { return c.in }
		if got := mainAgentDirectActionMode(); got != c.want {
			t.Errorf("mode(%q)=%q want=%q", c.in, got, c.want)
		}
	}
}
