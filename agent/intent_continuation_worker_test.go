package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

type continuationProvider struct{ requests []llm.CompletionRequest }

func (p *continuationProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.requests = append(p.requests, req)
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "LOCAL_HANDOFF_COMPLETED"}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
	}
}
func (p *continuationProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	a := llm.NewAccumulator()
	for event, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		a.Add(event)
	}
	return a.Message(), a.StopReason, a.Usage, nil
}

// Exercise Worker.execute through the real SDK/transcript store. No remote LLM,
// tools or target requests run: the in-memory provider emits a fixed final text.
func TestWorkerContinuationUsesNewSessionAndPreservesOwnResume(t *testing.T) {
	_, ts, source := continuationFixture(t)
	id, _, err := ts.addOneIntent(intentItem{Summary: "only remaining local step; stop after reading", SourceIntentID: json.RawMessage(fmt.Sprint(source))})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ts.ts.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	provider := &continuationProvider{}
	tx := transcript.NewStore(t.TempDir())
	worker := NewWorker(provider, "local-model", t.TempDir(), tx, 200000, 3)
	for i := 0; i < 2; i++ {
		_, _, err = worker.Execute(context.Background(), "test-worker", ts.taskID, nil, ts.ts, intent, nil, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(provider.requests) != 2 {
		t.Fatalf("requests=%d", len(provider.requests))
	}
	for _, req := range provider.requests {
		sys := strings.Join(req.System, "\n")
		for _, want := range []string{"done partition", "last partition", "续跑交接使用规则", "不恢复来源会话"} {
			if !strings.Contains(sys, want) {
				t.Fatalf("worker missing %q", want)
			}
		}
	}
	first, _ := json.Marshal(provider.requests[0].Messages)
	second, _ := json.Marshal(provider.requests[1].Messages)
	if strings.Contains(string(first), "LOCAL_HANDOFF_COMPLETED") {
		t.Fatal("fresh continuation inherited previous conversation")
	}
	if !strings.Contains(string(second), "LOCAL_HANDOFF_COMPLETED") || !strings.Contains(string(second), "继续执行。") {
		t.Fatal("existing same-intent resume was lost")
	}
	if strings.Contains(string(second), "recursive_secret") || strings.Contains(string(second), "task_OLD") {
		t.Fatal("copied unrelated predecessor state")
	}
}
