package agent

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// 意图近似去重闸。
//
// 背景（线上实测）：`add_intent` 完全没有服务端查重，规划者只能靠自查。task#4 的 395
// 条意图里 385 条（97%）是「续跑/接续」型同义意图——用同一个目标、同一个漏洞面、同一批
// 资产反复开新意图，前 6 小时 170M token 换到 5 条发现，之后 41 小时又烧 514M 只多 1 条。
// 更明确的一点：这些意图的 summary 里 79.5% 直接把上一条意图的 id 写进了正文
// （「【续跑·#1510 done、…】」），也就是说重复是显式的、机器可判的，只是没人去判。
//
// 闸用两个信号，都不需要模型配合：
//  1. 显式引用：summary 里出现 #N 且 N 是本任务已存在的意图 → 确定在同一条链上续写；
//  2. 文本近似：与新意图最像的历史意图摘要的 Dice 相似度 ≥ intentDupThreshold
//     （中文 bigram + ASCII/数字整词）。阈值在线上 395 条真意图上标定：续跑型
//     p50=0.57 / p90=0.88，而真正的新方向最大只有 0.49 —— 取 0.50 时误报为 0。
//
// 处置按"要不要停"分档，而不是一律拦：对**仍在场**（open/running/paused）的重复意图，
// 再开一条是纯浪费，可以硬拦；对**已结束**的重复意图，续跑可能是合理的（预算耗尽后要
// 接着干），只提醒、不拦——否则会把正常的续跑能力一起掐掉。

// intentDupThreshold 是近似重复的判定线，取值依据见文件头（0% 误报点）。
const intentDupThreshold = 0.50

// IntentDedupMode 由 server 从 settings 注入（off/warn/block），nil 或未知值按 warn：
//   - off  ：完全不查（保留退路）；
//   - warn ：默认。命中就照常创建，但把"你重复了哪条"写回工具结果，让模型自己收手；
//   - block：只有在重复对象仍在场时才拒绝创建；对已结束的意图仍然只提醒。
var IntentDedupMode func() string

func intentDedupMode() string {
	if IntentDedupMode == nil {
		return "warn"
	}
	m := strings.ToLower(strings.TrimSpace(IntentDedupMode()))
	switch m {
	case "off", "warn", "block":
		return m
	default:
		return "warn"
	}
}

// intentDupKind 表示命中的重复对象处于什么状态。
type intentDupKind int

const (
	intentDupLive    intentDupKind = iota // 重复对象还在场：再开一条就是纯浪费
	intentDupSettled                      // 重复对象已结束：续跑可能合理，只提醒
)

// intentDuplicate 是一次命中的结果。
type intentDuplicate struct {
	Kind     intentDupKind
	ID       int64
	State    string
	Score    float64
	Explicit bool // summary 显式引用了该意图的 id
}

// detectIntentDuplicate 在新意图落库前，判断它是否与本任务已有意图重复。
// existing 由 store.IntentDigests 按 id 倒序给出。
func detectIntentDuplicate(summary string, existing []db.IntentDigest) *intentDuplicate {
	if strings.TrimSpace(summary) == "" || len(existing) == 0 {
		return nil
	}
	byID := make(map[int64]db.IntentDigest, len(existing))
	for _, d := range existing {
		byID[d.ID] = d
	}
	// 信号 1：显式引用已有意图 id（线上 79.5% 的重复意图属于这一类）。
	for _, ref := range intentRefIDs(summary) {
		if d, ok := byID[ref]; ok {
			return &intentDuplicate{Kind: dupKindFor(d.State), ID: d.ID, State: d.State, Score: 1, Explicit: true}
		}
	}
	// 信号 2：文本近似，取最像的一条。
	cand := intentTokens(summary)
	var best *intentDuplicate
	for _, d := range existing {
		score := tokenDice(cand, intentTokens(d.Summary))
		if score < intentDupThreshold {
			continue
		}
		if best == nil || score > best.Score {
			best = &intentDuplicate{Kind: dupKindFor(d.State), ID: d.ID, State: d.State, Score: score}
		}
	}
	return best
}

func dupKindFor(state string) intentDupKind {
	switch state {
	case "open", "running", "paused":
		return intentDupLive
	default:
		return intentDupSettled
	}
}

// intentRefID 匹配 summary 里指向意图的引用：#123 形式。
var intentRefID = regexp.MustCompile(`#([0-9]+)`)

func intentRefIDs(summary string) []int64 {
	var out []int64
	for _, m := range intentRefID.FindAllStringSubmatch(summary, -1) {
		if id, err := strconv.ParseInt(m[1], 10, 64); err == nil && id > 0 {
			out = append(out, id)
		}
	}
	return out
}

// intentStopWords 是中文 bigram 里没有区分度的虚词组合，去掉可避免"的与""在了"这类组合
// 把两条无关意图的相似度抬高。
var intentStopWords = map[string]bool{
	"的了": true, "了的": true, "是和": true, "与的": true, "在的": true, "是的": true,
	"这个": true, "那个": true, "然后": true, "但是": true, "因为": true, "所以": true,
	"以及": true, "并且": true, "如果": true, "可以": true, "需要": true, "我们": true,
}

// intentTokens 把一句话拆成用于相似度比较的 token：CJK 连续段取 bigram（中文没有空格，
// bigram 无需分词词典就能表达"方向"），ASCII/数字连续串（端口、IP、用户名、文件名）整体
// 保留——它们往往决定"是不是同一个方向"。
func intentTokens(s string) []string {
	s = strings.ToLower(s)
	var out []string
	var buf []rune
	var kind int // 1=CJK 段，2=ASCII/数字段，0=空闲
	flush := func() {
		switch kind {
		case 1:
			for i := 0; i+1 < len(buf); i++ {
				if bg := string(buf[i : i+2]); !intentStopWords[bg] {
					out = append(out, bg)
				}
			}
		case 2:
			if t := string(buf); len(t) > 1 { // 单字符 ASCII 多半是标点残留
				out = append(out, t)
			}
		}
		buf = buf[:0]
		kind = 0
	}
	for _, r := range s {
		switch {
		case r >= 0x4e00 && r <= 0x9fff:
			if kind != 1 {
				flush()
				kind = 1
			}
			buf = append(buf, r)
		case isTokenRune(r):
			if kind != 2 {
				flush()
				kind = 2
			}
			buf = append(buf, r)
		default:
			flush()
		}
	}
	flush()
	return out
}

func isTokenRune(r rune) bool {
	return r == '_' || r == '-' || r == '.' || r == ':' || r == '/' ||
		(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')
}

// tokenDice 是多重集 Dice 系数：2|A∩B| / (|A|+|B|)。
func tokenDice(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	counts := make(map[string]int, len(a))
	for _, t := range a {
		counts[t]++
	}
	inter := 0
	for _, t := range b {
		if counts[t] > 0 {
			counts[t]--
			inter++
		}
	}
	return 2 * float64(inter) / float64(len(a)+len(b))
}

// intentDuplicateNote 生成写回给规划者的提示。措辞刻意区分两种情形：仍在场（别重复开）
// 与已结束（要续跑就把增量写清楚，别原样再开一条）。
func intentDuplicateNote(d *intentDuplicate) string {
	ref := fmt.Sprintf("#%d（%s）", d.ID, d.State)
	if d.Kind == intentDupLive {
		return fmt.Sprintf("【重复意图提醒】这条方向与**仍在场**的意图 %s 高度重复（相似度 %.2f）："+
			"它已经覆盖同一个方向，再开一条只会让两个 worker 打同一面。要调整方向用 steer_work 纠偏它，要放弃用 kill_work。", ref, d.Score)
	}
	why := fmt.Sprintf("文本相似度 %.2f", d.Score)
	if d.Explicit {
		why = "summary 里直接引用了它的 id"
	}
	return fmt.Sprintf("【续跑意图提醒】这条方向与**已结束**的意图 %s 高度重复（%s）。"+
		"续跑可以，但请把 summary 写成\"本轮新增什么\"（新载荷/新资产/上轮卡在哪一步+这次换什么策略），"+
		"否则就是同一件事重复烧预算——线上 task#4 有 97%% 的意图栽在这里：前 6 小时换 5 条发现，之后 41 小时只多 1 条。", ref, why)
}

// duplicateIntents 是 add_intent 的入口：按 mode 判定拒绝、提醒还是放行。
// 返回 (拒绝原因, 提醒文案)：拒绝原因非空时调用方不得建节点。
func duplicateIntents(summary string, existing []db.IntentDigest) (block string, warn string) {
	mode := intentDedupMode()
	if mode == "off" {
		return "", ""
	}
	d := detectIntentDuplicate(summary, existing)
	if d == nil {
		return "", ""
	}
	note := intentDuplicateNote(d)
	if mode == "block" && d.Kind == intentDupLive {
		return note + "\n（平台已拒绝创建这条重复意图：同一方向已有在跑的 worker，请改用 steer_work 或换方向。）", ""
	}
	return "", note
}
