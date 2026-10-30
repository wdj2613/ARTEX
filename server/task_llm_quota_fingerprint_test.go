package server

import (
	"errors"
	"testing"
)

func TestObservedQuotaFingerprintSkipsSameProviderRetry(t *testing.T) {
	for _, message := range []string{
		`openai: status 429: {"error":{"message":"额度已用完，请充值后重试"}}`,
		`openai: status 429: {"error":{"code":"quota_exhausted"}}`,
	} {
		err := errors.New(message)
		if !isQuotaExhaustedError(err) {
			t.Errorf("quota classifier missed %s", message)
		}
		if isRetryableStreamError(err) {
			t.Errorf("must not retry exhausted provider: %s", message)
		}
	}
	for _, message := range []string{
		`openai: status 429: rate_limit_exceeded`,
		`openai: status 429: RPM quota_exhausted`,
		`openai: status 429: TPM 额度已用完`,
	} {
		if !isRetryableStreamError(errors.New(message)) {
			t.Errorf("ordinary rate limit must remain retryable: %s", message)
		}
	}
	for _, message := range []string{
		`openai: status 401: 额度已用完`,
		`openai: status 403: quota_exhausted`,
	} {
		if isQuotaExhaustedError(errors.New(message)) {
			t.Errorf("auth failure must not become quota rotation: %s", message)
		}
		if isRetryableStreamError(errors.New(message)) {
			t.Errorf("auth failure must not retry: %s", message)
		}
	}
}
