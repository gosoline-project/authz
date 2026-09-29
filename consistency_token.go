package authz

import (
	"context"
	"sync"
)

type consistencyTokenContextKey struct{}

type consistencyTokenHolder struct {
	mu       sync.RWMutex
	incoming string
	newToken string
}

// WithConsistencyToken installs a new request-scoped consistency token holder
// with the supplied incoming token.
func WithConsistencyToken(ctx context.Context, incoming string) context.Context {
	holder := &consistencyTokenHolder{incoming: incoming}

	return context.WithValue(ctx, consistencyTokenContextKey{}, holder)
}

// ConsistencyToken returns a newly published token when one has been set, or
// the incoming token otherwise.
func ConsistencyToken(ctx context.Context) string {
	holder, ok := consistencyTokenHolderFromContext(ctx)
	if !ok {
		return ""
	}

	holder.mu.RLock()
	defer holder.mu.RUnlock()

	if holder.newToken != "" {
		return holder.newToken
	}

	return holder.incoming
}

// SetConsistencyToken publishes a token in the request-scoped holder. It does
// nothing when token is empty or ctx has no holder.
func SetConsistencyToken(ctx context.Context, token string) {
	if token == "" {
		return
	}

	holder, ok := consistencyTokenHolderFromContext(ctx)
	if !ok {
		return
	}

	holder.mu.Lock()
	holder.newToken = token
	holder.mu.Unlock()
}

// NewConsistencyToken returns only a token explicitly published after the
// holder was created.
func NewConsistencyToken(ctx context.Context) string {
	holder, ok := consistencyTokenHolderFromContext(ctx)
	if !ok {
		return ""
	}

	holder.mu.RLock()
	defer holder.mu.RUnlock()

	return holder.newToken
}

func consistencyTokenHolderFromContext(ctx context.Context) (*consistencyTokenHolder, bool) {
	holder, ok := ctx.Value(consistencyTokenContextKey{}).(*consistencyTokenHolder)
	return holder, ok
}
