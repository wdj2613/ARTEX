package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 下面两条摘要取自线上 task#4 的真实意图（#1512 / #1510），它们相似度 0.99，且后一条
// 在正文里直接引用了前一条 —— 这正是"97% 意图是续跑型同义意图"的典型形态。
const (
	realDupNew = "【续跑·#1510 done、103.45.128.43:19190 admin RFC1929 回环解锁 oracle 现【无任何 open/running intent 覆盖】（#1509 只占 .196:7000、#1500 只占 13 台+.43:7000，均不含本面）】继续 103.45.128.43:19190 的 admin RFC1929 回环解锁 oracle——全图唯一能以 127.0.0.1 源只读 .43:15432 中央 PG users 表、直接读出管理员明文/哈希的通道"
	realDupOld = "【续跑·#1497 done、103.45.128.43:19190 admin RFC1929 回环解锁 oracle 现【无任何 open/running intent 覆盖】（#1509 只占 .196:7000、#1500 只占 13 台+.43:7000，均不含本面）】继续 103.45.128.43:19190 的 admin RFC1929 回环解锁 oracle——全图唯一能以 127.0.0.1 源只读 .43:15432 中央 PG users 表、直接读出管理员明文/哈希的通道"
	// 两条真实的新方向（#559 / #558），都提到"15 台节点 7000"，但不是同一个方向。
	realNewA = "对 15 台节点做最小化端口/服务指纹（仅常用 HTTP 端口），寻找除 7000 外的弱入口：8000 用户面注册/登录、8093 代理后台、8443 VALNode、19190 SOCKS5（若认证弱口令可复用为回环源），优先找能直接拿到管理员凭据的入口"
	realNewB = "比对 15 台节点 7000 的 /admin-login、/assets/admin.js、/assets/nodes-admin.js 的哈希与差异，识别版本/变体（如 103.45.128.43 的 UDP 雷达变体），查找硬编码默认口令、调试接口或版本相关已知漏洞"
)

// 分词要能表达"方向"：中文必须切成 bigram（没有空格），端口/主机/用户名这类 ASCII 串
// 必须整体保留（常常决定是不是同一个面）。
func TestIntentTokensShape(t *testing.T) {
	t.Parallel()
	got := intentTokens("测试 103.45.129.116:8000 的 /api/cards/renew 限速桶")
	joined := strings.Join(got, "|")
	for _, want := range []string{"103.45.129.116:8000", "api", "cards", "renew", "测试", "限速"} {
		if !strings.Contains(joined, want) {
			t.Errorf("缺少 token %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "我们") || strings.Contains(joined, "以及") {
		t.Errorf("虚词应被丢弃: %s", joined)
	}
}

func TestTokenDiceEdges(t *testing.T) {
	t.Parallel()
	if got := tokenDice(nil, intentTokens("任意")); got != 0 {
		t.Errorf("空集合应为 0: %v", got)
	}
	a := intentTokens(realDupNew)
	if got := tokenDice(a, a); got < 0.999 {
		t.Errorf("自身应为 1: %v", got)
	}
	if got := tokenDice(intentTokens(realNewA), intentTokens(realNewB)); got >= intentDupThreshold {
		t.Errorf("两个不同方向不应过线: %v", got)
	}
}

// 信号 1：summary 里写了已有意图的 id —— 线上 79.5% 的重复属于这一类，必须无条件命中，
// 且按对方状态区分"仍在场"还是"已结束"。
func TestDetectIntentDuplicateExplicitReference(t *testing.T) {
	t.Parallel()
	live := detectIntentDuplicate(realDupNew, []db.IntentDigest{{ID: 1510, State: "open", Summary: realDupOld}})
	if live == nil || !live.Explicit || live.ID != 1510 || live.Kind != intentDupLive {
		t.Fatalf("显式引用在跑意图应判为 live 重复: %+v", live)
	}
	settled := detectIntentDuplicate(realDupNew, []db.IntentDigest{{ID: 1510, State: "exhausted", Summary: realDupOld}})
	if settled == nil || settled.Kind != intentDupSettled {
		t.Fatalf("显式引用已结束意图应判为 settled 重复: %+v", settled)
	}
	// 引用的 id 不在本任务里（例如提到 fact/资产 id）→ 不能当意图重复。
	if d := detectIntentDuplicate("继续 #999999 那个方向", []db.IntentDigest{{ID: 1510, State: "open", Summary: realDupOld}}); d != nil {
		t.Fatalf("引用不存在的意图 id 不应命中: %+v", d)
	}
}

// 信号 2：正文没写 #id，但换个说法讲同一件事，也要认得出来。
func TestDetectIntentDuplicateByText(t *testing.T) {
	t.Parallel()
	a := "测试 103.45.129.116:8000 的 /api/cards/renew 限速桶，验证能否绕过 /api/login 的 429 限制"
	b := "验证 103.45.129.116:8000 /api/cards/renew 的限速桶是否独立于 /api/login，从而绕过 429 限制继续爆破"
	d := detectIntentDuplicate(b, []db.IntentDigest{{ID: 7, State: "running", Summary: a}})
	if d == nil || d.Kind != intentDupLive || d.Explicit {
		t.Fatalf("换说法的同一方向应被文本命中: %+v", d)
	}
	// 真实数据反例：都提到 15 台节点 7000，但方向不同 —— 不许误判。
	if d := detectIntentDuplicate(realNewB, []db.IntentDigest{{ID: 559, State: "done", Summary: realNewA}}); d != nil {
		t.Fatalf("不同方向被误判为重复: %+v", d)
	}
	// 与更早的真实意图比对：真实续跑对必须命中。
	if d := detectIntentDuplicate(realDupNew, []db.IntentDigest{{ID: 1510, State: "done", Summary: realDupOld}}); d == nil {
		t.Fatal("真实续跑对必须命中")
	}
}

// 三种模式的行为：off 完全不查，warn 只提醒，block 只在对象仍在场时拒绝。
func TestDuplicateIntentsModes(t *testing.T) {
	old := IntentDedupMode
	t.Cleanup(func() { IntentDedupMode = old })

	liveDup := []db.IntentDigest{{ID: 1510, State: "running", Summary: realDupOld}}
	settledDup := []db.IntentDigest{{ID: 1510, State: "exhausted", Summary: realDupOld}}
	distinct := []db.IntentDigest{{ID: 559, State: "done", Summary: realNewA}}

	setMode := func(m string) { IntentDedupMode = func() string { return m } }

	setMode("off")
	if b, w := duplicateIntents(realDupNew, liveDup); b != "" || w != "" {
		t.Fatalf("off 模式不该有任何动作: block=%q warn=%q", b, w)
	}

	setMode("warn")
	if b, w := duplicateIntents(realDupNew, liveDup); b != "" || !strings.Contains(w, "仍在场") {
		t.Fatalf("warn 模式命中在场重复应只提醒: block=%q warn=%q", b, w)
	}
	if b, w := duplicateIntents(realDupNew, settledDup); b != "" || !strings.Contains(w, "已结束") {
		t.Fatalf("warn 模式命中已结束重复应只提醒: block=%q warn=%q", b, w)
	}
	if b, w := duplicateIntents(realNewB, distinct); b != "" || w != "" {
		t.Fatalf("不同方向不该有提醒: block=%q warn=%q", b, w)
	}

	setMode("block")
	if b, _ := duplicateIntents(realDupNew, liveDup); b == "" || !strings.Contains(b, "拒绝创建") {
		t.Fatalf("block 模式命中在场重复必须拒绝: %q", b)
	}
	// 已结束的重复仍然只提醒：续跑是正当能力，拦掉就把能力一起砍了。
	if b, w := duplicateIntents(realDupNew, settledDup); b != "" || !strings.Contains(w, "已结束") {
		t.Fatalf("block 模式对已结束重复只能提醒: block=%q warn=%q", b, w)
	}

	// 未知取值按 warn 处理，不能让配置写错就把闸关掉。
	setMode("BLOCK?")
	if b, w := duplicateIntents(realDupNew, liveDup); b != "" || w == "" {
		t.Fatalf("未知模式应按 warn 处理: block=%q warn=%q", b, w)
	}
}

// 端到端：走真实 store 跑 add_intent，确认 warnings 按下标回给规划者、单条模式把提醒附在
// 正文里、block 模式真的拒绝，并且"仍在场/已结束"两种口径分别触发。
func TestAddIntentSurfacesDuplicateWarning(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("intent dedup", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID = store, task.ID

	old := IntentDedupMode
	t.Cleanup(func() { IntentDedupMode = old })
	IntentDedupMode = func() string { return "warn" }

	batch := func(summaries ...string) map[string]any {
		t.Helper()
		items := make([]map[string]any, len(summaries))
		for i, sm := range summaries {
			items[i] = map[string]any{"summary": sm}
		}
		raw, _ := json.Marshal(map[string]any{"intents": items})
		res, err := ts.addIntent().Call(t.Context(), raw, nil)
		if err != nil {
			t.Fatalf("add_intent 调用失败: %v", err)
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
			t.Fatalf("解析返回失败: %v (%s)", err, res.Flatten())
		}
		return out
	}
	warningOf := func(out map[string]any) string {
		warns, ok := out["warnings"].(map[string]any)
		if !ok {
			return ""
		}
		msg, _ := warns["0"].(string)
		return msg
	}

	// 第一条：全新方向，不该提醒。它建成后是 open（仍在场）。
	first := batch(realDupNew)
	ids, _ := first["ids"].([]any)
	if len(ids) != 1 || int64(ids[0].(float64)) == 0 {
		t.Fatalf("未拿到意图 id: %v", first)
	}
	firstID := int64(ids[0].(float64))
	if msg := warningOf(first); msg != "" {
		t.Fatalf("首次创建不该有去重提醒: %s", msg)
	}
	if out := batch(realNewB); warningOf(out) != "" {
		t.Fatalf("不同方向不该提醒: %v", out)
	}

	// 换说法讲同一件事 → 提醒，且仍照常创建（warn 不拦）；对方还是 open → 口径"仍在场"。
	dup := batch(realDupOld)
	if msg := warningOf(dup); !strings.Contains(msg, "仍在场") {
		t.Fatalf("命中在跑意图应提示仍在场: %q (%v)", msg, dup)
	}
	if ids, _ := dup["ids"].([]any); len(ids) != 1 || int64(ids[0].(float64)) == 0 {
		t.Fatalf("warn 模式应照常创建: %v", dup)
	}

	// 把第一条收尾后，同样的重复改成"已结束"口径（续跑写法提醒）。
	if err := store.SetIntentState(firstID, "done"); err != nil {
		t.Fatal(err)
	}
	if msg := warningOf(batch(realDupNew)); !strings.Contains(msg, "已结束") {
		t.Fatalf("命中已结束意图应提示续跑写法: %q", msg)
	}

	// 单条模式：提醒附在正文里，保持原返回格式不变。
	raw, _ := json.Marshal(map[string]any{"summary": realDupNew})
	res, err := ts.addIntent().Call(t.Context(), raw, nil)
	if err != nil {
		t.Fatalf("单条调用失败: %v", err)
	}
	if text := res.Flatten(); !strings.Contains(text, "intent created:") || !strings.Contains(text, "意图提醒") {
		t.Fatalf("单条模式应在正文里带提醒: %s", text)
	}

	// block 模式 + 仍在场的重复 → 拒绝创建。
	live := batch("测试 10.0.0.9:8080 的 /debug 端点是否暴露环境变量")
	liveIDs, _ := live["ids"].([]any)
	if len(liveIDs) != 1 {
		t.Fatalf("未拿到意图 id: %v", live)
	}
	liveID := int64(liveIDs[0].(float64))
	IntentDedupMode = func() string { return "block" }
	raw, _ = json.Marshal(map[string]any{"intents": []map[string]any{{
		"summary": fmt.Sprintf("【续跑·#%d open】继续上面的方向", liveID),
	}}})
	res, err = ts.addIntent().Call(t.Context(), raw, nil)
	if err != nil {
		t.Fatalf("调用失败: %v", err)
	}
	if !strings.Contains(res.Flatten(), "拒绝创建") {
		t.Fatalf("block 模式应拒绝创建重复意图: %s", res.Flatten())
	}
}
