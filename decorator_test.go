package authz_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gosoline-project/authz"
)

type testInput struct {
	ID string
}

func (input testInput) AuthorizationResource() authz.Resource {
	return authz.Resource{Type: "campaign", ID: input.ID}
}

type testItem struct {
	ID string
}

type testCollection struct {
	Results []testItem
}

func (collection testCollection) AuthorizationResources() []authz.Resource {
	resources := make([]authz.Resource, 0, len(collection.Results))
	for _, item := range collection.Results {
		resources = append(resources, authz.Resource{Type: "campaign", ID: item.ID})
	}

	return resources
}

type evaluatorFunc func(context.Context, authz.Subject, []authz.Check) ([]authz.Decision, error)

func (f evaluatorFunc) CheckBulk(ctx context.Context, subject authz.Subject, checks []authz.Check) ([]authz.Decision, error) {
	return f(ctx, subject, checks)
}

func withTestSubject() context.Context {
	return authz.WithSubject(context.Background(), authz.Subject{Type: "user", ID: "42"})
}

func TestSubjectFromContext(t *testing.T) {
	t.Parallel()

	expected := authz.Subject{Type: "user", ID: "42"}
	actual, err := authz.SubjectFromContext(authz.WithSubject(context.Background(), expected))
	if err != nil {
		t.Fatalf("SubjectFromContext returned an error: %v", err)
	}
	if actual != expected {
		t.Fatalf("SubjectFromContext returned %+v, want %+v", actual, expected)
	}

	if _, err = authz.SubjectFromContext(context.Background()); err == nil {
		t.Fatal("SubjectFromContext returned no error for a context without a subject")
	}
}

func TestShadowModeObservesDeniedChecksAndRunsOperation(t *testing.T) {
	t.Parallel()

	var observations []authz.Observation
	evaluator := evaluatorFunc(func(_ context.Context, _ authz.Subject, checks []authz.Check) ([]authz.Decision, error) {
		if len(checks) != 1 {
			t.Fatalf("evaluator received %d checks, want 1", len(checks))
		}

		return []authz.Decision{{Allowed: false}}, nil
	})
	authorizer, err := authz.NewAuthorization(
		evaluator,
		authz.WithMode(authz.Shadow),
		authz.WithObserver(authz.ObserverFunc(func(_ context.Context, observation authz.Observation) {
			observations = append(observations, observation)
		})),
	)
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	called := false
	operation := authz.Decorate(
		authorizer,
		authz.ResourcePolicy[testInput, string]("read"),
		func(_ context.Context, input *testInput) (string, error) {
			called = true
			return "campaign " + input.ID, nil
		},
	)

	output, err := operation(withTestSubject(), &testInput{ID: "13"})
	if err != nil {
		t.Fatalf("shadow operation returned an error: %v", err)
	}
	if output != "campaign 13" {
		t.Fatalf("shadow operation returned %q, want %q", output, "campaign 13")
	}
	if !called {
		t.Fatal("shadow operation did not call the underlying operation")
	}
	if len(observations) != 1 {
		t.Fatalf("observer received %d observations, want 1", len(observations))
	}
	if observations[0].Phase != "before" {
		t.Fatalf("observation phase is %q, want before", observations[0].Phase)
	}
	if len(observations[0].Decisions) != 1 || observations[0].Decisions[0].Allowed {
		t.Fatalf("observer received unexpected decisions: %+v", observations[0].Decisions)
	}
}

func TestEnforceModeReturnsDeniedErrorAndSkipsOperation(t *testing.T) {
	t.Parallel()

	authorizer, err := authz.NewAuthorization(
		evaluatorFunc(func(_ context.Context, _ authz.Subject, _ []authz.Check) ([]authz.Decision, error) {
			return []authz.Decision{{Allowed: false}}, nil
		}),
		authz.WithMode(authz.Enforce),
	)
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	called := false
	operation := authz.Decorate(
		authorizer,
		authz.ResourcePolicy[testInput, string]("read"),
		func(context.Context, *testInput) (string, error) {
			called = true
			return "unexpected", nil
		},
	)

	_, err = operation(withTestSubject(), &testInput{ID: "13"})
	if err == nil {
		t.Fatal("enforce operation returned no error for a denied check")
	}
	if called {
		t.Fatal("enforce operation called the underlying operation after denial")
	}

	var deniedError *authz.DeniedError
	if !errors.As(err, &deniedError) {
		t.Fatalf("error %v is not a DeniedError", err)
	}
	if deniedError.Phase != "before" {
		t.Fatalf("DeniedError phase is %q, want before", deniedError.Phase)
	}
	if deniedError.Check.Permission != "read" || deniedError.Check.Resource.ID != "13" {
		t.Fatalf("DeniedError check is %+v", deniedError.Check)
	}
}

func TestFilterModeRemovesDeniedAndFailedCollectionItems(t *testing.T) {
	t.Parallel()

	var calls [][]authz.Check
	evaluator := evaluatorFunc(func(_ context.Context, _ authz.Subject, checks []authz.Check) ([]authz.Decision, error) {
		calls = append(calls, append([]authz.Check(nil), checks...))
		if len(calls) == 1 {
			return []authz.Decision{{Allowed: true}}, nil
		}

		return []authz.Decision{
			{Allowed: true},
			{Allowed: false},
			{Err: errors.New("item decision unavailable")},
		}, nil
	})
	authorizer, err := authz.NewAuthorization(evaluator, authz.WithMode(authz.Filter))
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	operation := authz.Decorate(
		authorizer,
		authz.BulkResourcePolicy[testInput, testCollection]("list", "read"),
		func(context.Context, *testInput) (testCollection, error) {
			return testCollection{Results: []testItem{{ID: "1"}, {ID: "2"}, {ID: "3"}}}, nil
		},
	)

	output, err := operation(withTestSubject(), &testInput{ID: "10"})
	if err != nil {
		t.Fatalf("filter operation returned an error: %v", err)
	}
	if expected := (testCollection{Results: []testItem{{ID: "1"}}}); !reflect.DeepEqual(output, expected) {
		t.Fatalf("filter operation returned %+v, want %+v", output, expected)
	}
	if len(calls) != 2 {
		t.Fatalf("evaluator received %d calls, want 2", len(calls))
	}
	if calls[0][0].Permission != "list" {
		t.Fatalf("general check is %+v, want list permission", calls[0][0])
	}
	if len(calls[1]) != 3 || calls[1][1].Resource.ID != "2" {
		t.Fatalf("item checks are %+v", calls[1])
	}
}

func TestFilterModeStillEnforcesDeniedBeforeChecks(t *testing.T) {
	t.Parallel()

	authorizer, err := authz.NewAuthorization(
		evaluatorFunc(func(_ context.Context, _ authz.Subject, _ []authz.Check) ([]authz.Decision, error) {
			return []authz.Decision{{Allowed: false}}, nil
		}),
		authz.WithMode(authz.Filter),
	)
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	called := false
	operation := authz.Decorate(
		authorizer,
		authz.ResourcePolicy[testInput, string]("read"),
		func(context.Context, *testInput) (string, error) {
			called = true
			return "unexpected", nil
		},
	)

	_, err = operation(withTestSubject(), &testInput{ID: "13"})
	if err == nil {
		t.Fatal("filter operation returned no error for a denied before check")
	}
	if called {
		t.Fatal("filter operation called the underlying operation after denial")
	}
	var deniedError *authz.DeniedError
	if !errors.As(err, &deniedError) {
		t.Fatalf("error %v is not a DeniedError", err)
	}
}

func TestEnforceModePropagatesEvaluatorErrors(t *testing.T) {
	t.Parallel()

	evaluatorError := errors.New("authorization service unavailable")
	authorizer, err := authz.NewAuthorization(
		evaluatorFunc(func(_ context.Context, _ authz.Subject, _ []authz.Check) ([]authz.Decision, error) {
			return nil, evaluatorError
		}),
		authz.WithMode(authz.Enforce),
	)
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	called := false
	operation := authz.Decorate(
		authorizer,
		authz.ResourcePolicy[testInput, string]("read"),
		func(context.Context, *testInput) (string, error) {
			called = true
			return "unexpected", nil
		},
	)

	_, err = operation(withTestSubject(), &testInput{ID: "13"})
	if !errors.Is(err, evaluatorError) {
		t.Fatalf("error %v does not wrap evaluator error", err)
	}
	if called {
		t.Fatal("operation ran after evaluator failure")
	}
}

func TestEnforceModeRejectsDecisionCountMismatch(t *testing.T) {
	t.Parallel()

	authorizer, err := authz.NewAuthorization(
		evaluatorFunc(func(_ context.Context, _ authz.Subject, _ []authz.Check) ([]authz.Decision, error) {
			return nil, nil
		}),
		authz.WithMode(authz.Enforce),
	)
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	operation := authz.Decorate(
		authorizer,
		authz.ResourcePolicy[testInput, string]("read"),
		func(context.Context, *testInput) (string, error) {
			return "unexpected", nil
		},
	)

	_, err = operation(withTestSubject(), &testInput{ID: "13"})
	if err == nil || !strings.Contains(err.Error(), "returned 0 decisions for 1 checks") {
		t.Fatalf("unexpected decision mismatch error: %v", err)
	}
}

func TestMissingSubjectPreventsEnforcedOperation(t *testing.T) {
	t.Parallel()

	evaluatorCalled := false
	authorizer, err := authz.NewAuthorization(
		evaluatorFunc(func(_ context.Context, _ authz.Subject, _ []authz.Check) ([]authz.Decision, error) {
			evaluatorCalled = true
			return []authz.Decision{{Allowed: true}}, nil
		}),
		authz.WithMode(authz.Enforce),
	)
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	operation := authz.Decorate(
		authorizer,
		authz.ResourcePolicy[testInput, string]("read"),
		func(context.Context, *testInput) (string, error) {
			return "unexpected", nil
		},
	)

	_, err = operation(context.Background(), &testInput{ID: "13"})
	if err == nil || !strings.Contains(err.Error(), "resolve authorization subject") {
		t.Fatalf("unexpected missing subject error: %v", err)
	}
	if evaluatorCalled {
		t.Fatal("evaluator ran without a subject")
	}
}

func TestObserverReceivesBeforeAndAfterObservations(t *testing.T) {
	t.Parallel()

	var phases []string
	authorizer, err := authz.NewAuthorization(
		evaluatorFunc(func(_ context.Context, _ authz.Subject, checks []authz.Check) ([]authz.Decision, error) {
			decisions := make([]authz.Decision, len(checks))
			for index := range decisions {
				decisions[index] = authz.Decision{Allowed: true}
			}
			return decisions, nil
		}),
		authz.WithObserver(authz.ObserverFunc(func(_ context.Context, observation authz.Observation) {
			phases = append(phases, observation.Phase)
		})),
	)
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	policy := authz.Policy[testInput, string]{
		Before: func(_ context.Context, input *testInput) ([]authz.Check, error) {
			return []authz.Check{{Resource: input.AuthorizationResource(), Permission: "read"}}, nil
		},
		After: func(_ context.Context, _ *testInput, _ *string) ([]authz.Check, error) {
			return []authz.Check{{Resource: authz.Resource{Type: "campaign", ID: "13"}, Permission: "view"}}, nil
		},
	}

	operation := authz.Decorate(
		authorizer,
		policy,
		func(context.Context, *testInput) (string, error) { return "ok", nil },
	)
	if _, err = operation(withTestSubject(), &testInput{ID: "12"}); err != nil {
		t.Fatalf("operation returned an error: %v", err)
	}
	if !reflect.DeepEqual(phases, []string{"before", "after"}) {
		t.Fatalf("observer phases are %v, want [before after]", phases)
	}
}

func TestNewAuthorizationValidatesConfiguration(t *testing.T) {
	t.Parallel()

	evaluator := evaluatorFunc(func(_ context.Context, _ authz.Subject, _ []authz.Check) ([]authz.Decision, error) {
		return nil, nil
	})

	tests := []struct {
		name    string
		options []authz.Option
		want    string
	}{
		{name: "nil option", options: []authz.Option{nil}, want: "option is nil"},
		{name: "invalid mode", options: []authz.Option{authz.WithMode(authz.Mode(99))}, want: "unsupported authorization mode"},
		{name: "nil subject resolver", options: []authz.Option{authz.WithSubjectResolver(nil)}, want: "subject resolver is required"},
		{name: "nil observer", options: []authz.Option{authz.WithObserver(nil)}, want: "observer is required"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := authz.NewAuthorization(evaluator, test.options...)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewAuthorization returned %v, want error containing %q", err, test.want)
			}
		})
	}

	if _, err := authz.NewAuthorization(nil); err == nil || !strings.Contains(err.Error(), "evaluator is required") {
		t.Fatalf("NewAuthorization(nil) returned %v", err)
	}
}

func TestDecorateWithOptionsUsesConfiguredSubjectResolver(t *testing.T) {
	t.Parallel()

	expectedSubject := authz.Subject{Type: "service", ID: "billing"}
	var actualSubject authz.Subject
	authorizer, err := authz.DecorateWithOptions(
		evaluatorFunc(func(_ context.Context, subject authz.Subject, _ []authz.Check) ([]authz.Decision, error) {
			actualSubject = subject
			return []authz.Decision{{Allowed: true}}, nil
		}),
		authz.ResourcePolicy[testInput, string]("read"),
		func(context.Context, *testInput) (string, error) { return "ok", nil },
		authz.WithSubjectResolver(func(context.Context) (authz.Subject, error) {
			return expectedSubject, nil
		}),
		authz.WithMode(authz.Enforce),
	)
	if err != nil {
		t.Fatalf("DecorateWithOptions returned an error: %v", err)
	}

	if _, err = authorizer(withTestSubject(), &testInput{ID: "13"}); err != nil {
		t.Fatalf("decorated operation returned an error: %v", err)
	}
	if actualSubject != expectedSubject {
		t.Fatalf("evaluator received subject %+v, want %+v", actualSubject, expectedSubject)
	}
}

func TestDeniedErrorHasNoHTTPStatusContract(t *testing.T) {
	t.Parallel()

	var err error = &authz.DeniedError{
		Phase: "before",
		Check: authz.Check{Resource: authz.Resource{Type: "campaign", ID: "13"}, Permission: "read"},
	}
	if got := fmt.Sprintf("%v", err); got != `permission "read" denied on campaign:13` {
		t.Fatalf("DeniedError string is %q", got)
	}

	type statusCoder interface {
		StatusCode() int
	}
	var statusError statusCoder
	if errors.As(err, &statusError) {
		t.Fatal("DeniedError unexpectedly implements an HTTP status-code contract")
	}
}
