package authz_test

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/gosoline-project/authz"
)

func TestConsistencyTokenContextState(t *testing.T) {
	t.Parallel()

	ctx := authz.WithConsistencyToken(context.Background(), "incoming")
	if got := authz.ConsistencyToken(ctx); got != "incoming" {
		t.Fatalf("ConsistencyToken returned %q, want incoming", got)
	}
	if got := authz.NewConsistencyToken(ctx); got != "" {
		t.Fatalf("NewConsistencyToken returned %q before a token was published", got)
	}

	subjectCtx := authz.WithSubject(ctx, authz.Subject{Type: "user", ID: "42"})
	if got := authz.ConsistencyToken(subjectCtx); got != "incoming" {
		t.Fatalf("WithSubject did not preserve the incoming token: got %q", got)
	}

	authz.SetConsistencyToken(subjectCtx, "published")
	if got := authz.ConsistencyToken(ctx); got != "published" {
		t.Fatalf("ConsistencyToken on the parent returned %q, want published", got)
	}
	if got := authz.NewConsistencyToken(ctx); got != "published" {
		t.Fatalf("NewConsistencyToken returned %q, want published", got)
	}

	authz.SetConsistencyToken(subjectCtx, "")
	if got := authz.ConsistencyToken(ctx); got != "published" {
		t.Fatalf("empty token replaced the published token with %q", got)
	}

	freshCtx := authz.WithConsistencyToken(subjectCtx, "")
	if got := authz.ConsistencyToken(freshCtx); got != "" {
		t.Fatalf("fresh empty-token state inherited %q", got)
	}
	if got := authz.NewConsistencyToken(freshCtx); got != "" {
		t.Fatalf("fresh empty-token state returned published token %q", got)
	}

	authz.SetConsistencyToken(freshCtx, "fresh")
	if got := authz.ConsistencyToken(freshCtx); got != "fresh" {
		t.Fatalf("fresh state returned %q, want fresh", got)
	}
	if got := authz.ConsistencyToken(subjectCtx); got != "published" {
		t.Fatalf("fresh state changed its parent token to %q", got)
	}

	authz.SetConsistencyToken(context.Background(), "orphan")
	if got := authz.ConsistencyToken(context.Background()); got != "" {
		t.Fatalf("SetConsistencyToken created state without WithConsistencyToken: %q", got)
	}
}

func TestDecoratePropagatesPublishedConsistencyToken(t *testing.T) {
	t.Parallel()

	var evaluatorTokens []string
	evaluator := evaluatorFunc(func(ctx context.Context, _ authz.Subject, _ []authz.Check) ([]authz.Decision, error) {
		evaluatorTokens = append(evaluatorTokens, authz.ConsistencyToken(ctx))

		return []authz.Decision{{Allowed: true}}, nil
	})
	authorizer, err := authz.NewAuthorization(evaluator, authz.WithMode(authz.Enforce))
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	policy := authz.Policy[testInput, string]{
		Before: func(context.Context, *testInput) ([]authz.Check, error) {
			return []authz.Check{{Resource: authz.Resource{Type: "campaign", ID: "13"}, Permission: "read"}}, nil
		},
		After: func(context.Context, *testInput, *string) ([]authz.Check, error) {
			return []authz.Check{{Resource: authz.Resource{Type: "campaign", ID: "13"}, Permission: "read"}}, nil
		},
	}

	var operationToken string
	operation := authz.Decorate(authorizer, policy, func(ctx context.Context, _ *testInput) (string, error) {
		operationToken = authz.ConsistencyToken(ctx)
		authz.SetConsistencyToken(ctx, "published")
		return "done", nil
	})

	ctx := authz.WithConsistencyToken(context.Background(), "incoming")
	ctx = authz.WithSubject(ctx, authz.Subject{Type: "user", ID: "42"})
	output, err := operation(ctx, &testInput{ID: "13"})
	if err != nil {
		t.Fatalf("decorated operation returned an error: %v", err)
	}
	if output != "done" {
		t.Fatalf("decorated operation returned %q, want done", output)
	}
	if operationToken != "incoming" {
		t.Fatalf("operation received consistency token %q, want incoming", operationToken)
	}
	if !reflect.DeepEqual(evaluatorTokens, []string{"incoming", "published"}) {
		t.Fatalf("evaluator received tokens %v, want [incoming published]", evaluatorTokens)
	}
}

func TestConsistencyTokenConcurrentReadsAndWrites(t *testing.T) {
	t.Parallel()

	ctx := authz.WithConsistencyToken(context.Background(), "incoming")
	ctx = authz.WithSubject(ctx, authz.Subject{Type: "user", ID: "42"})

	const workers = 8
	const iterations = 100
	start := make(chan struct{})
	var group sync.WaitGroup
	group.Add(workers * 2)

	for worker := range workers {
		go func(worker int) {
			defer group.Done()
			<-start
			for iteration := range iterations {
				authz.SetConsistencyToken(ctx, fmt.Sprintf("token-%d-%d", worker, iteration))
				_ = authz.ConsistencyToken(ctx)
				_ = authz.NewConsistencyToken(ctx)
			}
		}(worker)
	}
	for range workers {
		go func() {
			defer group.Done()
			for range iterations {
				_ = authz.ConsistencyToken(ctx)
				_ = authz.NewConsistencyToken(ctx)
			}
		}()
	}

	close(start)
	group.Wait()

	authz.SetConsistencyToken(ctx, "final")
	if got := authz.ConsistencyToken(ctx); got != "final" {
		t.Fatalf("ConsistencyToken after concurrent writes returned %q, want final", got)
	}
	if got := authz.NewConsistencyToken(ctx); got != "final" {
		t.Fatalf("NewConsistencyToken after concurrent writes returned %q, want final", got)
	}
}
