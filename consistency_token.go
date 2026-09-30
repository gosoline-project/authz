package authz

import (
	"context"
	"sync"
)

type consistencyTokenContextKey struct{}

type consistencyTokenState struct {
	mu      sync.RWMutex
	initial string
	latest  string
}

// WithConsistencyToken installs an opaque token in new request-scoped state, even when token is empty.
// Descendant contexts share the state, while another call creates independent state.
// Authz does not interpret, validate, or order tokens. The evaluator defines their meaning.
func WithConsistencyToken(ctx context.Context, token string) context.Context {
	state := &consistencyTokenState{initial: token}

	return context.WithValue(ctx, consistencyTokenContextKey{}, state)
}

// ConsistencyToken returns the latest published token, or the initial token if none was published.
func ConsistencyToken(ctx context.Context) string {
	state, ok := ctx.Value(consistencyTokenContextKey{}).(*consistencyTokenState)
	if !ok {
		return ""
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	if state.latest != "" {
		return state.latest
	}

	return state.initial
}

// SetConsistencyToken publishes a non-empty token to state initialized by WithConsistencyToken.
// It does nothing when the context has no consistency-token state.
func SetConsistencyToken(ctx context.Context, token string) {
	if token == "" {
		return
	}

	state, ok := ctx.Value(consistencyTokenContextKey{}).(*consistencyTokenState)
	if !ok {
		return
	}

	state.mu.Lock()
	state.latest = token
	state.mu.Unlock()
}

// NewConsistencyToken returns the latest published token, excluding the initial token.
func NewConsistencyToken(ctx context.Context) string {
	state, ok := ctx.Value(consistencyTokenContextKey{}).(*consistencyTokenState)
	if !ok {
		return ""
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	return state.latest
}
