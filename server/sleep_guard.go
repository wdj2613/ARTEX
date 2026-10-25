package server

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

// 阻塞式等待的平台闸。
//
// 背景（线上实测）：worker 倾向用 `sleep 115` 原地等后台爆破脚本，一条意图的墙钟预算
// 只有 agents.run_seconds（默认 1200 秒），10 次这样的 sleep 就把预算睡完，意图随即
// exhausted，期间没有任何 LLM 进展。线上 2569 个工具回合里带 sleep，累计 74 小时阻塞，
// 单个任务（task#4）就占了 68 小时。
//
// SDK 早就提供了正确做法（Bash 的 run_in_background + TaskOutput 轮询，或命令自带
// nohup），所以这里不需要新能力，只要把这个坏习惯在调用点拦住并给出替代方案：超过阈值
// 的纯 sleep 直接在 PreToolUse 阶段拦下，模型会收到"改用后台执行 + 轮询"的指令。
//
// 只作用于 worker（steerHooks 是每个 work 独有的钩子）：planner/mainagent 没有一次性
// 墙钟预算，阻塞等待的代价不在同一个量级，不在这里管。

// maxBlockingSleepSeconds 是允许单次阻塞 sleep 的上限。短 sleep 仍可能有用（等限速窗口、
// 等文件落盘），所以不封死；超过这个值就是在拿意图预算换等待。
const maxBlockingSleepSeconds = 30.0

// sleepCall 匹配处于命令起始位置的 sleep 调用（含 && / ; / || 之后），捕获时长与单位。
// 刻意不匹配脚本内部的 sleep（heredoc、python -c 等）——那些属于被测逻辑，不该被拦。
var sleepCall = regexp.MustCompile(`(?:^|[;&|]|&&|\|\|)\s*sleep\s+([0-9]+(?:\.[0-9]+)?)([smhd]?)\b`)

// blockingSleepSeconds 判断一次工具调用是否是"过长的阻塞 sleep"。
// toolName 必须是 Bash；input 是工具的原始 JSON 入参。返回命中的最大时长（秒）与是否拦截。
// 带 run_in_background 的调用不算阻塞（命令本身在后台跑，sleep 不影响预算）。
func blockingSleepSeconds(toolName string, input json.RawMessage) (float64, bool) {
	if toolName != "Bash" || len(input) == 0 {
		return 0, false
	}
	var in struct {
		Command         string `json:"command"`
		RunInBackground bool   `json:"run_in_background"`
	}
	if err := json.Unmarshal(input, &in); err != nil || in.RunInBackground {
		return 0, false
	}
	var worst float64
	for _, m := range sleepCall.FindAllStringSubmatch(in.Command, -1) {
		secs := sleepSeconds(m[1], m[2])
		if secs > worst {
			worst = secs
		}
	}
	if worst < maxBlockingSleepSeconds {
		return 0, false
	}
	return worst, true
}

func sleepSeconds(value, unit string) float64 {
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	switch unit {
	case "m":
		n *= 60
	case "h":
		n *= 3600
	case "d":
		n *= 86400
	}
	return n
}

// blockingSleepNudge 是拦截时返回给模型的指令：说清为什么被拦、正确做法是什么，避免模型
// 把平台的效率管控误读成目标侧的防御而反复重试同样的写法。
func blockingSleepNudge(secs float64) string {
	return fmt.Sprintf("【ARTEX 平台管控·禁止阻塞等待】这条 `sleep %g` 已被拦截："+
		"本意图的墙钟预算是一次性的，原地阻塞等待会把预算烧光且不产生任何进展，超时后意图直接 exhausted。\n"+
		"请改用：①长跑任务后台执行——Bash 传 `run_in_background: true`（或命令自带 `nohup … > run.out 2>&1 &`）拿到 task id，再用 `TaskOutput{task_id:\"…\"}` 读增量输出；"+
		"②盯进度只取指标——`tail -n 20 run.out`、`grep -c` 命中行；"+
		"③确实需要等待时，单次 sleep 不超过 %g 秒，然后继续下一个动作。",
		secs, maxBlockingSleepSeconds)
}
