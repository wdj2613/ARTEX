package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// 跨任务知识检索：让规划者复用**别的任务**已经得到的漏洞结论与探索事实。
//
// 为什么需要：任务级共享本来就有（list_findings / list_facts 覆盖本任务 + 直接关联
// 任务），但"直接关联"依赖 task_relations 表，线上只有 1 条记录 → 跨任务继承事实上不
// 存在。而同一批目标常被多个任务反复打（线上 17 个资产被 2~3 个任务共用，同一厂商的多
// 个部署分散在不同任务里），成果却互不可见：71 条事实里显式写着"与 fact 1969 同构"这类
// 交叉引用，全部是同任务内引用，没有一次跨任务引用。
//
// 设计约束（防止"反复查询"把上下文吃光）：只返回**指针**（id + 一行摘要），不返回全文；
// 关键词命中量在线上很大（"admin" 命中 709 条、摘要合计 17.8 万字符），所以调用方必须配
// 合 knowledge_queries 账本做去重与次数上限，见 KnowledgeQueryState。

// KnowledgeHit 是一条跨任务命中。只带定位与判别所需的最少信息，全文用 node_detail 取。
type KnowledgeHit struct {
	// NodeID 是探索图节点 id（node_detail 用它取全文）；漏洞节点尚未回填时为 0，
	// 此时用 FindingID 走漏洞详情。
	NodeID    int64  `json:"node_id,omitempty"`
	FindingID int64  `json:"finding_id,omitempty"`
	Kind      string `json:"kind"`
	// Severity 仅漏洞有值（critical/high/medium/low/info）。
	Severity string `json:"severity,omitempty"`
	TaskID   int64  `json:"task_id"`
	// Task 是产出该条结论的任务描述前 60 字，标明"这是哪个目标上得到的结论"——手法可
	// 迁移，结论不能直接搬，调用方必须能看到来源。
	Task    string `json:"task,omitempty"`
	Summary string `json:"summary"`
	// SameAsset 表示该条结论涉及的资产与本任务资产有交集（同一目标上验证过）。
	SameAsset bool `json:"same_asset,omitempty"`
}

// knowledgeSummaryCap 限制单条摘要长度：命中量动辄上百条，摘要长度是上下文成本的主项。
const knowledgeSummaryCap = 120

// NormalizeKnowledgeQuery 归一化查询词，作为去重账本的主键：去空白、小写、压缩连续
// 空格。大小写与多余空格不应算作"换了个词再搜一遍"。
func NormalizeKnowledgeQuery(q string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(q))), " ")
}

// likePattern 把用户输入转成安全的 ILIKE 模式：%, _, \ 一律按字面匹配。
func likePattern(q string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(q) + "%"
}

// findingAssetOverlap 判断漏洞的资产集合是否与本任务（$2）的资产有交集。漏洞有两处
// 资产来源：图节点的锚点（exploration_anchors）与 findings.asset_ids，两者都算。
const findingAssetOverlap = `EXISTS (
	SELECT 1 FROM assets a
	WHERE $2 > 0 AND $2 = ANY(a.task_ids)
	  AND (a.id IN (SELECT an.asset_id FROM exploration_anchors an WHERE an.node_id = f.node_id)
	       OR a.id IN (SELECT x::bigint FROM jsonb_array_elements_text(f.asset_ids) AS x)))`

// factAssetOverlap 判断事实的资产集合是否与本任务（$2）的资产有交集。事实的资产就是
// 它写入时锚定的资产（exploration_anchors），与资产图的锚定口径一致。
const factAssetOverlap = `EXISTS (
	SELECT 1 FROM exploration_anchors an
	JOIN assets a ON a.id = an.asset_id
	WHERE an.node_id = n.id AND $2 > 0 AND $2 = ANY(a.task_ids))`

// knowledgeSeverityScore 把漏洞严重度折算成分值，让 critical/high 排在前面。
const knowledgeSeverityScore = `CASE lower(COALESCE(%s,''))
	WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`

// knowledgeUnion 是"漏洞 + 事实"的联合检索：两者字段不同（漏洞有 severity/asset_ids，
// 事实没有），所以在 SQL 里对齐成同一形状再统一排序。$1 是 ILIKE 模式，$2 是本任务
// task id（0 = 不做同资产加权），$3 是 limit。
var knowledgeUnion = fmt.Sprintf(`
SELECT nid, finding_id, kind, severity, task_id, task, summary, same_asset, score FROM (
  SELECT COALESCE(f.node_id,0) AS nid, f.id AS finding_id, 'finding' AS kind,
         COALESCE(f.severity,'') AS severity, COALESCE(f.task_id,0) AS task_id,
         COALESCE(left(NULLIF(t.description,''),60),'') AS task,
         COALESCE(NULLIF(left(NULLIF(f.name,''),%[1]d),''), left(COALESCE(f.summary,''),%[1]d)) AS summary,
         %[2]s AS same_asset,
         (CASE WHEN f.name ILIKE $1 THEN 3 ELSE 0 END
          + CASE WHEN f.vulnclass ILIKE $1 THEN 2 ELSE 0 END
          + %[3]s
          + CASE WHEN %[2]s THEN 5 ELSE 0 END) AS score
  FROM findings f
  LEFT JOIN tasks t ON t.id=f.task_id AND t.deleted_at IS NULL
  WHERE (f.name ILIKE $1 OR f.vulnclass ILIKE $1 OR f.summary ILIKE $1 OR f.evidence ILIKE $1)
  UNION ALL
  SELECT n.id AS nid, 0 AS finding_id, 'fact' AS kind, '' AS severity, COALESCE(t.id,0) AS task_id,
         COALESCE(left(NULLIF(t.description,''),60),'') AS task,
         left(COALESCE(n.payload->>'summary',''),%[1]d) AS summary,
         %[4]s AS same_asset,
         (CASE WHEN (n.payload->>'summary') ILIKE $1 THEN 3 ELSE 0 END
          + CASE WHEN %[4]s THEN 5 ELSE 0 END) AS score
  FROM exploration_nodes n
  LEFT JOIN tasks t ON t.exploration_id=n.exploration_id AND t.deleted_at IS NULL
  WHERE n.kind='fact' AND ((n.payload->>'summary') ILIKE $1 OR (n.payload->>'detail') ILIKE $1)
) h`,
	knowledgeSummaryCap, findingAssetOverlap,
	fmt.Sprintf(knowledgeSeverityScore, "f.severity"), factAssetOverlap)

// SearchKnowledge 在所有任务里检索漏洞与探索事实，返回指针列表与命中总数。
// limit<=0 用默认值，>30 夹到 30；total 不受 limit 影响——调用方据此引导"收窄关键词"
// 而不是翻页（翻页会把上下文推高）。
func (s *ExplorationStore) SearchKnowledge(q string, limit int) ([]KnowledgeHit, int, error) {
	if limit <= 0 {
		limit = 15
	}
	if limit > 30 {
		limit = 30
	}
	pattern := likePattern(q)
	taskID, err := s.TaskID()
	if err != nil {
		return nil, 0, err
	}
	var total int
	if err := s.db.QueryRow(`SELECT count(*) FROM (`+knowledgeUnion+`) c`, pattern, taskID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT nid, finding_id, kind, severity, task_id, task, summary, same_asset
FROM (`+knowledgeUnion+`) c ORDER BY score DESC, nid DESC, finding_id DESC LIMIT $3`, pattern, taskID, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]KnowledgeHit, 0, limit)
	for rows.Next() {
		var h KnowledgeHit
		if err := rows.Scan(&h.NodeID, &h.FindingID, &h.Kind, &h.Severity, &h.TaskID, &h.Task, &h.Summary, &h.SameAsset); err != nil {
			return nil, 0, err
		}
		h.Summary = strings.TrimSpace(h.Summary)
		out = append(out, h)
	}
	return out, total, rows.Err()
}

// CrossTaskFindings 返回**其它任务**里、资产与本任务有交集的漏洞（严重度优先）。
// 供 graph_overview 被动展示：同一目标上别人已经确认过的漏洞，规划者不用查就能看到，
// 零查询成本。没有资产交集时返回空（说明这是全新目标，历史结论不适用）。
func (s *ExplorationStore) CrossTaskFindings(limit int) ([]KnowledgeHit, error) {
	if limit <= 0 {
		limit = 8
	}
	taskID, err := s.TaskID()
	if err != nil {
		return nil, err
	}
	if taskID <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`
SELECT COALESCE(f.node_id,0), f.id, 'finding', COALESCE(f.severity,''), COALESCE(f.task_id,0),
       COALESCE(left(NULLIF(t.description,''),60),''),
       COALESCE(NULLIF(left(NULLIF(f.name,''),90),''), left(COALESCE(f.summary,''),90)),
       true
FROM findings f
JOIN tasks t ON t.id=f.task_id AND t.deleted_at IS NULL
WHERE f.task_id <> $1 AND `+findingAssetOverlap+`
ORDER BY `+fmt.Sprintf(knowledgeSeverityScore, "f.severity")+` DESC, f.id DESC
LIMIT $3`, taskID, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]KnowledgeHit, 0, limit)
	for rows.Next() {
		var h KnowledgeHit
		if err := rows.Scan(&h.NodeID, &h.FindingID, &h.Kind, &h.Severity, &h.TaskID, &h.Task, &h.Summary, &h.SameAsset); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// KnowledgeQueryState 报告某个归一化查询词在本任务里是否搜过，以及本任务已用掉多少个
// 不同查询词；seen=true 时同时返回上次的命中数与命中 id（供调用方判断"结果是否变了"）。
func (s *ExplorationStore) KnowledgeQueryState(qNorm string) (seen bool, used int, hitCount int, refs []string, err error) {
	if err := s.db.QueryRow(`SELECT count(*) FROM knowledge_queries WHERE exploration_id=$1`,
		s.expID).Scan(&used); err != nil {
		return false, 0, 0, nil, err
	}
	var raw []byte
	err = s.db.QueryRow(`SELECT hit_count, hit_ids FROM knowledge_queries
WHERE exploration_id=$1 AND q_norm=$2`, s.expID, qNorm).Scan(&hitCount, &raw)
	if err == sql.ErrNoRows {
		return false, used, 0, nil, nil
	}
	if err != nil {
		return false, used, 0, nil, err
	}
	_ = json.Unmarshal(raw, &refs)
	return true, used, hitCount, refs, nil
}

// RecordKnowledgeQuery 记录（或更新）一个查询词的命中快照。命中集合变化时覆盖旧快照，
// 这样下次同词搜索能判断"结果有没有变"。
// refs 是命中条目的稳定引用（"n:节点id" / "f:漏洞id"），用于判断两次搜索的命中集合是否
// 真的变了——只比数量会把"换了一条"误判成"没变"。
func (s *ExplorationStore) RecordKnowledgeQuery(qNorm string, hitCount int, refs []string) error {
	if refs == nil {
		refs = []string{}
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO knowledge_queries(exploration_id, q_norm, hit_count, hit_ids)
VALUES ($1,$2,$3,$4)
ON CONFLICT (exploration_id, q_norm)
DO UPDATE SET hit_count=EXCLUDED.hit_count, hit_ids=EXCLUDED.hit_ids, created_at=now()`,
		s.expID, qNorm, hitCount, string(raw))
	return err
}
