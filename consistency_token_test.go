package authz_test

import (
	"context"
	"testing"

	"github.com/gosoline-project/authz"
)

func TestConsistencyTokenHolderSeparatesIncomingAndPublishedTokens(t *testing.T) {
	ctxWithoutHolder := context.Background()
	authz.SetConsistencyToken(ctxWithoutHolder, "ignored")
	if got := authz.ConsistencyToken(ctxWithoutHolder); got != "" {
		t.Fatalf("ConsistencyToken without a holder = %q, want empty", got)
	}
	if got := authz.NewConsistencyToken(ctxWithoutHolder); got != "" {
		t.Fatalf("NewConsistencyToken without a holder = %q, want empty", got)
	}

	ctx := authz.WithConsistencyToken(ctxWithoutHolder, "incoming")
	if got := authz.ConsistencyToken(ctx); got != "incoming" {
		t.Fatalf("ConsistencyToken = %q, want incoming token", got)
	}
	if got := authz.NewConsistencyToken(ctx); got != "" {
		t.Fatalf("NewConsistencyToken = %q before publishing, want empty", got)
	}

	authz.SetConsistencyToken(ctx, "")
	if got := authz.ConsistencyToken(ctx); got != "incoming" {
		t.Fatalf("empty publish changed ConsistencyToken to %q", got)
	}

	authz.SetConsistencyToken(ctx, "published")
	if got := authz.ConsistencyToken(ctx); got != "published" {
		t.Fatalf("ConsistencyToken = %q after publishing, want published token", got)
	}
	if got := authz.NewConsistencyToken(ctx); got != "published" {
		t.Fatalf("NewConsistencyToken = %q, want published token", got)
	}

	freshCtx := authz.WithConsistencyToken(ctx, "")
	if got := authz.ConsistencyToken(freshCtx); got != "" {
		t.Fatalf("new empty holder inherited token %q", got)
	}
	if got := authz.NewConsistencyToken(freshCtx); got != "" {
		t.Fatalf("new empty holder inherited published token %q", got)
	}
	authz.SetConsistencyToken(freshCtx, "second request")
	if got := authz.ConsistencyToken(freshCtx); got != "second request" {
		t.Fatalf("new holder returned token %q, want second request token", got)
	}
	if got := authz.ConsistencyToken(ctx); got != "published" {
		t.Fatalf("new holder changed the original request token to %q", got)
	}
}
