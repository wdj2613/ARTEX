package agent

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"strings"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// 主 Agent 的「人机接口边界」闸。
//
// 背景（线上实测，task 6 主会话）：人类在对话里说「继续任务，我已经设置好了全局代理」，
// 主 Agent 一个字没回，而是自己下场 27m44s / 51 轮 / 60 次 Bash 去 curl、查 DNS、验源站，
// 最后被人类手动停止——一个回合烧掉 67.8M 输入 token、零正文输出。
//
// 设计上主 Agent 是人类操作员的接口：回答问题、把人的要求转成目标/意图，执行交给 planner
// 与 worker（见 mainAgentDefaultTmpl 的角色定义）。提示词只能劝，所以这里再补一道调用点
// 闸：命中「自己直接对目标动手」的命令形态时拦下这一次调用，并把替代做法说清楚。
//
// 力度由 server 从 settings 注入（off / warn / block），nil 或未知值按 warn：
//   - off  ：不介入（保留退路）；
//   - warn ：默认。命中就拦下这一次并写回替代做法——教学式提醒，不是禁用：换成本地只读
//     命令（cat/grep/jq 读落盘结果）照样能跑；
//   - block：在 warn 之上再收紧 Bash，只放行本任务工作目录内的只读查看命令（白名单）。
//
// 为什么警告也做成"拦一次"：PreToolUse 钩子只有"拦下 + 回一段说明"这一个通道，没有
// "放行但附一句提醒"的能力。所以 warn 的语义是"拦下这条命令并把替代做法讲清楚"，而不是
// 让它跑完再抱怨——后者正好就是线上那 60 次 Bash 的形状。
var MainAgentDirectActionMode func() string

func mainAgentDirectActionMode() string {
	if MainAgentDirectActionMode == nil {
		return "warn"
	}
	switch m := strings.ToLower(strings.TrimSpace(MainAgentDirectActionMode())); m {
	case "off", "warn", "block":
		return m
	default:
		return "warn"
	}
}

// mainAgentBoundaryPrompt 是代码拥有的系统提示词尾部（段 [C]）。它追加在渲染后的正文
// 之后，所以 DB 里改过的提示词正文也删不掉它——与 artifactSpec / workerToolboxSpec 同一
// 惯例。规则分四条：回答优先、问题用只读工具回答、要求转成目标、自己不动手。
const mainAgentBoundaryPrompt = `## 人机接口边界（代码固定）

1. **回答优先**：收到人类消息，先用一到三句人话回答他问的事、或说明你打算做什么，再决定要不要调工具。不要连续调十几个工具却一个字都不说——人类看到的是"一直在跑、没有回复"。
2. **他问项目现状**（进展 / 结论 / 发现 / 资产 / 某个 worker 干了什么）→ 只用只读平台工具回答：graph_overview、list_facts、list_findings、node_detail、expand_digest、get_worker_output、get_worker_trace、search_all_worker_traces、list_assets。**不要为了回答而连目标**。
3. **他提要求 / 下指令** → 把要求翻译成项目目标，这是你的主要产出：新增最终目标用 set_goals，具体探索方向用 add_intent，战略提示用 add_hint，探索边界用 set_constraints，纠偏正在跑的意图用 steer_work。执行由 planner / worker 负责。
4. **你自己不直接对目标动手**：不发起任何针对目标的网络请求或扫描（curl、wget、nc、nmap、sqlmap、ffuf、python requests…）。Bash 只用于本任务工作目录内的文件查看与解析（读已落盘的输出、日志、JSON）。目标侧的请求一律经 add_intent / steer_work 交给 worker。`

// mainAgentBoundarySpec 供 mainAgentSystem 追加到提示词尾部。
func mainAgentBoundarySpec() string { return "\n\n" + mainAgentBoundaryPrompt }

// directActionHeads 是「自己动手」的命令首词集合：网络客户端、扫描器、DNS/连通性探测。
// 命中即拦——这些正是线上主 Agent 反复执行的那类命令。
var directActionHeads = map[string]bool{
	"curl": true, "wget": true, "http": true, "httpie": true,
	"nc": true, "ncat": true, "netcat": true, "telnet": true, "socat": true,
	"nmap": true, "masscan": true, "sqlmap": true, "ffuf": true, "nuclei": true,
	"nikto": true, "hydra": true, "dirb": true, "gobuster": true, "wfuzz": true,
	"ping": true, "traceroute": true, "mtr": true,
	"dig": true, "nslookup": true, "host": true, "whois": true,
}

// scriptHeads 是"脚本解释器"首词：只有同时出现网络库调用时才算动手，否则放行
// （主 Agent 用 python 解析落盘的 JSON 是正常操作）。
var scriptHeads = map[string]bool{
	"python": true, "python3": true, "node": true, "nodejs": true,
	"ruby": true, "perl": true, "php": true, "sh": true, "bash": true, "zsh": true,
}

// scriptNetRe 命中脚本里的出网调用。
var scriptNetRe = regexp.MustCompile(`(?i)(requests\.(get|post|put|patch|delete|head|request|session)|urllib\.request|urllib2|urlopen|http\.client|socket\.socket|httpx\.|aiohttp|fetch\(|https?\.request|net\.connect|net\.Socket)`)

// opensslClientRe 只拦 s_client（真建连），本地证书解析（x509 / req）放行。
var opensslClientRe = regexp.MustCompile(`(?i)\bopenssl\s+(?:[\w.-]+@)?s_client\b`)

// localReadHeads 是 block 模式下仍放行的本任务目录只读命令。
var localReadHeads = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "less": true, "more": true,
	"grep": true, "rg": true, "wc": true, "sort": true, "uniq": true, "jq": true,
	"find": true, "echo": true, "printf": true, "stat": true, "file": true,
	"diff": true, "md5sum": true, "sha256sum": true, "base64": true, "cut": true,
	"tr": true, "awk": true, "sed": true, "pwd": true, "tree": true, "du": true,
	"column": true, "rev": true, "nl": true, "xxd": true, "strings": true,
}

// prefixWords 是包在真命令前面的词（取首词前剥掉）。
var prefixWords = map[string]bool{"sudo": true, "time": true, "env": true, "nohup": true, "command": true, "exec": true, "nice": true, "timeout": true}

// localViewers 是"只做本地查看"的段首词。这类段里出现 curl / nmap 字样也不判动手——
// 例如 `grep -o "https://x" run.log` 是在读日志，不是在发请求。
var localViewers = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "less": true, "more": true,
	"grep": true, "rg": true, "wc": true, "sort": true, "uniq": true, "jq": true,
	"find": true, "echo": true, "printf": true, "stat": true, "file": true,
	"diff": true, "md5sum": true, "sha256sum": true, "base64": true, "cut": true,
	"tr": true, "awk": true, "sed": true, "pwd": true, "tree": true, "du": true,
	"column": true, "rev": true, "nl": true, "xxd": true, "strings": true,
	"git": true, "tar": true, "unzip": true, "zip": true, "mkdir": true, "cp": true, "mv": true,
}

// shellSegmentSplit 把一条 shell 命令切成若干"段"（按 ; && || | 换行）。
var shellSegmentSplit = regexp.MustCompile(`(?:&&|\|\||;|\||\n)`)

// shellCommandOf 取出工具参数里的命令文本。目前只有 Bash 与交互式 shell 的 open 带命令。
// 返回 ok=false 表示这个工具不是 shell 面，闸不介入。
func shellCommandOf(toolName string, input []byte) (string, bool) {
	switch toolName {
	case "Bash", "shell_open":
	default:
		return "", false
	}
	var in struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", false
	}
	return in.Command, true
}

// normalizeWord 归一化一个命令行词：去引号、去路径前缀（/usr/bin/curl → curl）、小写。
func normalizeWord(w string) string {
	w = strings.ToLower(strings.Trim(w, "\"'`"))
	if i := strings.LastIndex(w, "/"); i >= 0 && i < len(w)-1 {
		w = w[i+1:]
	}
	return w
}

// isAssignment 判断 f 是否 VAR=val 形式的赋值前缀。
func isAssignment(f string) bool {
	i := strings.Index(f, "=")
	if i <= 0 {
		return false
	}
	return !strings.ContainsAny(f[:i], "\"'$`()")
}

// segmentHead 取一段命令的首词（剥掉 sudo/env 前缀、孤立的选项、VAR=val 赋值）。
// 只用于 block 模式的白名单判断与日志，不追求 shell 语法的完整性。
func segmentHead(seg string) string {
	fields := strings.Fields(strings.TrimSpace(seg))
	for len(fields) > 0 {
		f := strings.Trim(fields[0], "\"'")
		low := strings.ToLower(f)
		switch {
		case strings.HasPrefix(low, "-"):
			fields = fields[1:] // 孤立的选项，不是首词
		case isAssignment(f):
			fields = fields[1:]
		case prefixWords[low]:
			fields = fields[1:]
			// timeout 30s curl …：前缀自带的时长参数
			if low == "timeout" && len(fields) > 0 && !strings.HasPrefix(fields[0], "-") {
				fields = fields[1:]
			}
		default:
			return normalizeWord(f)
		}
	}
	return ""
}

// commandHeads 返回每一段的首词。
func commandHeads(cmd string) []string {
	var heads []string
	for _, seg := range shellSegmentSplit.Split(cmd, -1) {
		if h := segmentHead(seg); h != "" {
			heads = append(heads, h)
		}
	}
	return heads
}

// directActionHead 判断这条命令是否属于"主 Agent 自己动手"。返回命中的词（空=没命中）。
//
// 判定方式是"按段看词"而不是只看段首：`sudo -u www curl …`、`cat urls | xargs -n1 nmap …`
// 的真命令都不在段首，只看段首会漏。为了不误伤，段首是本地查看类命令（grep/cat/jq…）的段
// 直接跳过——`grep -o "https://x" run.log` 是在读日志，不是在发请求。
func directActionHead(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if opensslClientRe.MatchString(cmd) {
		return "openssl s_client"
	}
	netInScript := scriptNetRe.MatchString(cmd)
	for _, seg := range shellSegmentSplit.Split(cmd, -1) {
		if strings.TrimSpace(seg) == "" {
			continue
		}
		if localViewers[segmentHead(seg)] {
			continue
		}
		for _, tok := range strings.Fields(seg) {
			w := normalizeWord(tok)
			if directActionHeads[w] {
				return w
			}
			if scriptHeads[w] && netInScript {
				return w
			}
		}
	}
	return ""
}

// mainAgentDirectActionNudge 是拦下时回给模型的教学式说明：既要它停手，也要给出正确通道。
func mainAgentDirectActionNudge(head, mode string) string {
	lead := "【主 Agent 边界提醒】这条命令会让主 Agent 自己直接对目标动手，已被拦下、未执行"
	if mode == "block" {
		lead = "【主 Agent 边界】这条命令会让主 Agent 自己直接对目标动手，已禁止、未执行"
	}
	return lead + "（命中命令：" + head + "）。\n\n" +
		"主 Agent 是人类操作员的接口：**回答问题 + 把人的要求转成目标**，执行交给 planner/worker。请改用：\n" +
		"- 需要探测或验证目标 → `add_intent`（写清具体方向，planner 会派给 worker）；目标已在跑 → `steer_work` 纠偏那条意图\n" +
		"- 需要新增最终目标 → `set_goals`；需要探索边界 → `set_constraints`；需要战略提示 → `add_hint`\n" +
		"- 只想看别人已经拿到的结果 → `get_worker_output` / `get_worker_trace` / `search_all_worker_traces`，或在本任务目录里用 `cat` / `grep` / `jq` 读已落盘的文件\n\n" +
		"如果你只是想查看本地落盘内容（例如 grep 日志里的 URL），换成不带网络客户端的本地只读命令即可，闸不会拦。"
}

// mainAgentLocalOnlyNudge 是 block 模式下对非白名单本地命令的说明。
func mainAgentLocalOnlyNudge(head string) string {
	return "【主 Agent 边界】当前边界闸为 block：主 Agent 的 Bash 只允许本任务工作目录内的只读查看命令" +
		"（ls / cat / head / tail / grep / rg / jq / wc / sort / uniq / find / sed / awk / base64 / md5sum …），" +
		"这条命令的首词是 `" + head + "`，已禁止执行。\n\n" +
		"要做别的事：探测/验证目标走 `add_intent` / `steer_work`，平台状态走只读工具（graph_overview / list_facts / list_findings / get_worker_output）。" +
		"如果确实需要放宽，请在「系统设置 → 主 Agent 边界闸」把力度改成「仅提醒」或「关闭」。"
}

// mainAgentBoundaryHooks 是挂在主 Agent 会话上的钩子。它只实现 PreToolUse 上的这一道闸，
// 其余钩子语义一律放行（nil inner）。
type mainAgentBoundaryHooks struct{}

func (mainAgentBoundaryHooks) PreToolUse(_ context.Context, name string, input []byte) (bool, string, []byte) {
	mode := mainAgentDirectActionMode()
	if mode == "off" {
		return false, "", nil
	}
	cmd, ok := shellCommandOf(name, input)
	if !ok || strings.TrimSpace(cmd) == "" {
		return false, "", nil
	}
	if head := directActionHead(cmd); head != "" {
		log.Printf("[mainagent] 边界闸(%s) 拦下直接对目标动手的命令 head=%s: %s", mode, head, firstLine(cmd, 120))
		return true, mainAgentDirectActionNudge(head, mode), nil
	}
	if mode == "block" {
		for _, h := range commandHeads(cmd) {
			if i := strings.LastIndex(h, "/"); i >= 0 && i < len(h)-1 {
				h = h[i+1:]
			}
			if !localReadHeads[h] {
				log.Printf("[mainagent] 边界闸(block) 拦下非白名单命令 head=%s: %s", h, firstLine(cmd, 120))
				return true, mainAgentLocalOnlyNudge(h), nil
			}
		}
	}
	return false, "", nil
}

func (mainAgentBoundaryHooks) PostToolUse(_ context.Context, _ string, _, _ []byte, _ bool) {}

func (mainAgentBoundaryHooks) Stop(_ context.Context, _ []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

// 编译期确认钩子实现了 SDK 接口。
var _ harness.HookRunner = mainAgentBoundaryHooks{}
