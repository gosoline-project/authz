package authz_test

import (
	"errors"
	"testing"

	"github.com/gosoline-project/authz"
)

func TestDecisionResult(t *testing.T) {
	t.Parallel()

	errEvaluation := errors.New("evaluation failed")
	tests := []struct {
		name     string
		decision authz.Decision
		want     authz.Result
	}{
		{name: "allow", decision: authz.Decision{Allowed: true}, want: authz.ResultAllow},
		{name: "zero decision denies", decision: authz.Decision{}, want: authz.ResultDeny},
		{name: "error", decision: authz.Decision{Err: errEvaluation}, want: authz.ResultError},
		{name: "error takes precedence over allow", decision: authz.Decision{Allowed: true, Err: errEvaluation}, want: authz.ResultError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.decision.Result(); got != tt.want {
				t.Errorf("Decision.Result() = %q, want %q", got, tt.want)
			}
		})
	}
}
