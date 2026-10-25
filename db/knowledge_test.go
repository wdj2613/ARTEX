package db

import (
	"fmt"
	"testing"
)

// 跨任务检索的核心行为：别的任务里验证过的结论能被本任务搜到，并标明来源与"是否同
// 资产"——同资产代表结论可直接复用，不同资产只代表手法可借鉴。
func TestSearchKnowledgeAcrossTasks(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	source, err := d.CreateTask("A 来源任务", "打 adminApi", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := d.CreateTask("B 同资产任务", "复测同一目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := d.CreateTask("C 无关任务", "全新目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.DeleteTask(source.ID)
		_ = d.DeleteTask(viewer.ID)
		_ = d.DeleteTask(stranger.ID)
	}()

	assets := d.Assets()
	host := fmt.Sprintf("kb-%d.invalid", source.ID)
	assetID, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: host, TaskID: source.ID})
	if err != nil {
		t.Fatal(err)
	}
	// 同一资产也属于 B（跨任务共用目标），C 完全不沾。
	if _, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: host, TaskID: viewer.ID}); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = assets.DeleteByIDs([]int64{assetID}) }()

	src := d.Exploration(source.ExplorationID)
	factID, err := src.AddNode(KindFact, map[string]any{
		"summary": "gtq 的 adminApi 验证码可用 ddddocr 破解拿到 ticket",
		"detail":  "captchaStart 泄露 captchaImg/captchaCheck，识别后按 sign=MD5(MD5(code+ip)+JING) 提交即可",
	}, 0, "confirmed", "worker", []int64{assetID})
	if err != nil {
		t.Fatal(err)
	}
	findingID, err := d.AddFinding(source.ID, 0, "captcha-bypass", "adminApi 人机验证可绕过", "high",
		"带 ticket 后 sms/send 穿过人机验证进入业务层", "evidence", "worker", []int64{assetID})
	if err != nil {
		t.Fatal(err)
	}

	// B：搜得到 A 的结论，且标为同资产（结论可直接复用）。
	vw := d.Exploration(viewer.ExplorationID)
	hits, total, err := vw.SearchKnowledge("验证", 10)
	if err != nil {
		t.Fatal(err)
	}
	if total < 2 || len(hits) < 2 {
		t.Fatalf("应同时命中事实与漏洞: total=%d hits=%d", total, len(hits))
	}
	var sawFact, sawFinding bool
	for _, h := range hits {
		if h.NodeID == factID {
			sawFact = true
			if h.Kind != KindFact || h.TaskID != source.ID || !h.SameAsset {
				t.Fatalf("事实命中字段不对: %+v", h)
			}
			if h.Summary == "" || len([]rune(h.Summary)) > knowledgeSummaryCap {
				t.Fatalf("摘要应被截断到 %d 字: %q", knowledgeSummaryCap, h.Summary)
			}
		}
		if h.FindingID == findingID {
			sawFinding = true
			if h.Kind != KindFinding || h.Severity != "high" || !h.SameAsset {
				t.Fatalf("漏洞命中字段不对: %+v", h)
			}
		}
	}
	if !sawFact || !sawFinding {
		t.Fatalf("事实/漏洞应各命中一条: fact=%v finding=%v hits=%+v", sawFact, sawFinding, hits)
	}

	// C：同样搜得到（知识是全局的），但不标同资产——结论不可直接搬，只能借手法。
	st := d.Exploration(stranger.ExplorationID)
	otherHits, _, err := st.SearchKnowledge("验证", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherHits) == 0 {
		t.Fatal("跨任务检索应覆盖所有任务")
	}
	for _, h := range otherHits {
		if h.SameAsset {
			t.Fatalf("无关任务不该被判为同资产: %+v", h)
		}
	}

	// 上限夹取：limit 超过 30 也只返回 30 条。
	if many, _, err := vw.SearchKnowledge("验证", 999); err != nil {
		t.Fatal(err)
	} else if len(many) > 30 {
		t.Fatalf("limit 应夹到 30: %d", len(many))
	}
}

// 被动展示：只给"资产有交集的其他任务"的漏洞；没有交集就什么都不给，避免把无关结论
// 塞进概览误导规划者。
func TestCrossTaskFindingsOnlySameAsset(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	source, err := d.CreateTask("KBF 来源", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := d.CreateTask("KBF 观察", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := d.CreateTask("KBF 无关", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.DeleteTask(source.ID)
		_ = d.DeleteTask(viewer.ID)
		_ = d.DeleteTask(stranger.ID)
	}()

	assets := d.Assets()
	host := fmt.Sprintf("kbf-%d.invalid", source.ID)
	assetID, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: host, TaskID: source.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: host, TaskID: viewer.ID}); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = assets.DeleteByIDs([]int64{assetID}) }()

	findingID, err := d.AddFinding(source.ID, 0, "idor", "订单接口越权读取他人卡密", "critical",
		"Order/info 直接换 id 即可读他人订单", "evidence", "worker", []int64{assetID})
	if err != nil {
		t.Fatal(err)
	}

	hits, err := d.Exploration(viewer.ExplorationID).CrossTaskFindings(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].FindingID != findingID || hits[0].Severity != "critical" || hits[0].TaskID != source.ID {
		t.Fatalf("应展示来源任务的同资产漏洞: %+v", hits)
	}

	// 来源任务自己看不到（它不是"其他任务"）；无关任务也看不到（没有资产交集）。
	if got, err := d.Exploration(source.ExplorationID).CrossTaskFindings(8); err != nil || len(got) != 0 {
		t.Fatalf("来源任务不该展示自己的漏洞: %+v %v", got, err)
	}
	if got, err := d.Exploration(stranger.ExplorationID).CrossTaskFindings(8); err != nil || len(got) != 0 {
		t.Fatalf("无资产交集不该展示: %+v %v", got, err)
	}
}

// 查询账本：记录前 seen=false，记录后 seen=true 并带回命中快照；重复记录覆盖而不是叠加。
func TestKnowledgeQueryLedger(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	task, err := d.CreateTask("KBQ 账本", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()
	store := d.Exploration(task.ExplorationID)

	seen, used, count, refs, err := store.KnowledgeQueryState("验证码")
	if err != nil {
		t.Fatal(err)
	}
	if seen || used != 0 || count != 0 || len(refs) != 0 {
		t.Fatalf("初始状态应为空: seen=%v used=%d count=%d refs=%v", seen, used, count, refs)
	}

	if err := store.RecordKnowledgeQuery("验证码", 2, []string{"n:11", "f:22"}); err != nil {
		t.Fatal(err)
	}
	seen, used, count, refs, err = store.KnowledgeQueryState("验证码")
	if err != nil {
		t.Fatal(err)
	}
	if !seen || used != 1 || count != 2 || len(refs) != 2 || refs[0] != "n:11" || refs[1] != "f:22" {
		t.Fatalf("记录后状态不对: seen=%v used=%d count=%d refs=%v", seen, used, count, refs)
	}

	// 同词再记录：覆盖快照，不新增一条（否则额度会被同一句话反复吃掉）。
	if err := store.RecordKnowledgeQuery("验证码", 3, []string{"n:33"}); err != nil {
		t.Fatal(err)
	}
	seen, used, count, refs, err = store.KnowledgeQueryState("验证码")
	if err != nil {
		t.Fatal(err)
	}
	if !seen || used != 1 || count != 3 || len(refs) != 1 || refs[0] != "n:33" {
		t.Fatalf("重复记录应覆盖: seen=%v used=%d count=%d refs=%v", seen, used, count, refs)
	}

	// 不同词各占一个额度。
	if err := store.RecordKnowledgeQuery("越权", 1, []string{"f:44"}); err != nil {
		t.Fatal(err)
	}
	if _, used, _, _, err = store.KnowledgeQueryState("越权"); err != nil || used != 2 {
		t.Fatalf("不同关键词应各自计额度: used=%d err=%v", used, err)
	}
}

// 归一化：大小写与多余空白不该被当成"换了个词再搜一遍"。
func TestNormalizeKnowledgeQuery(t *testing.T) {
	cases := map[string]string{
		"  验证码  ":     "验证码",
		"Admin API":   "admin api",
		" a\t\tb\n c ": "a b c",
		"":            "",
	}
	for in, want := range cases {
		if got := NormalizeKnowledgeQuery(in); got != want {
			t.Errorf("NormalizeKnowledgeQuery(%q)=%q want %q", in, got, want)
		}
	}
}
