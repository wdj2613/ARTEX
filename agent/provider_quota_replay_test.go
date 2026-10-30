package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// Replay the observed quota fingerprint over real loopback HTTP, for both SDK
// paths. The fake server never calls an upstream provider or spends API credit.
func TestProviderDoesNotRetryChineseQuotaOrQuotaExhaustedCode(t *testing.T) {
	for _, body := range []string{
		`{"error":{"message":"额度已用完，请充值后重试"}}`,
		`{"error":{"code":"quota_exhausted"}}`,
	} {
		for _, stream := range []bool{false, true} {
			name := "complete"
			if stream {
				name = "stream"
			}
			t.Run(body+"/"+name, func(t *testing.T) {
				var requests atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					w.Header().Set("content-type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = io.WriteString(w, body)
				}))
				defer upstream.Close()
				provider, err := ConfigFrom("openai", "test-model", upstream.URL, "test-key", "").NewProvider()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}}
				var callErr error
				if stream {
					for _, err := range provider.Stream(ctx, req) {
						if err != nil {
							callErr = err
						}
					}
				} else {
					_, _, _, callErr = provider.Complete(ctx, req)
				}
				if callErr == nil || !IsQuotaExhaustedMessage(callErr.Error()) || !strings.Contains(callErr.Error(), "status 402") {
					t.Fatalf("quota must normalize for routing: %v", callErr)
				}
				if n := requests.Load(); n != 1 {
					t.Fatalf("requests=%d want 1", n)
				}
			})
		}
	}
}
