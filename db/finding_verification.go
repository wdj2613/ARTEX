package db

import "strings"

// VerificationHandoff is computed from existing evidence and retest history. It
// does not change triage, start a retest, or claim that nonempty text is correct.
type VerificationHandoff struct {
	EvidencePresent            bool   `json:"evidence_present"`
	AssetLinksPresent          bool   `json:"asset_links_present"`
	ReportPresent              bool   `json:"report_present"`
	RetestCount                int    `json:"retest_count"`
	LatestRetestStatus         string `json:"latest_retest_status,omitempty"`
	LatestVerdict              string `json:"latest_verdict,omitempty"`
	LatestEvidenceVersion      *int64 `json:"latest_evidence_version,omitempty"`
	CurrentEvidenceVersion     int64  `json:"current_evidence_version"`
	EvidenceChangedSinceRetest bool   `json:"evidence_changed_since_retest"`
	NeedsReview                bool   `json:"needs_review"`
	Note                       string `json:"note"`
}

func (d *DB) FindingVerificationHandoff(f *DBFinding) (VerificationHandoff, error) {
	h := VerificationHandoff{EvidencePresent: strings.TrimSpace(f.Evidence) != "", AssetLinksPresent: len(f.AssetIDs) > 0, ReportPresent: strings.TrimSpace(f.Report) != "", CurrentEvidenceVersion: f.EvidenceVersion, NeedsReview: true, Note: "报告完成不等于复测确认。先补齐已保存的证据缺口；实际复测须由操作员明确发起并遵守当前范围，不自动执行目标请求。"}
	if err := d.QueryRow(`SELECT count(*) FROM finding_retests WHERE finding_id=$1`, f.ID).Scan(&h.RetestCount); err != nil {
		return h, err
	}
	if h.RetestCount == 0 {
		return h, nil
	}
	// Never let a prior success mask a newer inconclusive/failed attempt.
	var version *int64
	err := d.QueryRow(`SELECT status,verdict,CASE WHEN snapshot->'finding'->>'evidence_version' ~ '^[0-9]{1,18}$' THEN (snapshot->'finding'->>'evidence_version')::bigint ELSE NULL END FROM finding_retests WHERE finding_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, f.ID).Scan(&h.LatestRetestStatus, &h.LatestVerdict, &version)
	if err != nil {
		return h, err
	}
	h.LatestEvidenceVersion = version
	h.EvidenceChangedSinceRetest = version == nil || *version != f.EvidenceVersion
	h.NeedsReview = !h.EvidencePresent || !h.AssetLinksPresent || h.EvidenceChangedSinceRetest || h.LatestRetestStatus != "completed" || (h.LatestVerdict != "reproduced" && h.LatestVerdict != "fixed")
	return h, nil
}
