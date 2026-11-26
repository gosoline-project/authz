package authzhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gosoline-project/authz"
	"github.com/gosoline-project/httpserver"
)

type testInput struct {
	ID     string `json:"id"`
	Header string `json:"-"`
}

type testEvaluator func(context.Context, authz.Subject, []authz.Check) ([]authz.Decision, error)

func (f testEvaluator) CheckBulk(ctx context.Context, subject authz.Subject, checks []authz.Check) ([]authz.Decision, error) {
	return f(ctx, subject, checks)
}

func testAuthorizer(t *testing.T, mode authz.Mode, evaluator testEvaluator) *authz.Authorization {
	t.Helper()
	authorizer, err := authz.NewAuthorization(evaluator, authz.WithMode(mode))
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}

func testPolicy() authz.Policy[testInput, httpserver.Response] {
	return authz.Policy[testInput, httpserver.Response]{Before: func(_ context.Context, input *testInput) ([]authz.Check, error) {
		return []authz.Check{{Resource: authz.Resource{Type: "item", ID: input.ID}, Permission: "read"}}, nil
	}}
}

func testRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(authz.WithSubject(req.Context(), authz.Subject{Type: "user", ID: "123"}))
}

func runHandler(handler gin.HandlerFunc, req *http.Request) (*httptest.ResponseRecorder, *gin.Context) {
	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = req
	handler(ctx)
	return writer, ctx
}

func TestBindPreventsWorkOnDenialAndFailure(t *testing.T) {
	failure := errors.New("evaluator failed")
	for _, tc := range []struct {
		name      string
		decisions []authz.Decision
		err       error
	}{
		{name: "denied", decisions: []authz.Decision{{Allowed: false}}},
		{name: "evaluator failure", err: failure},
		{name: "decision failure", decisions: []authz.Decision{{Err: failure}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			authorizer := testAuthorizer(t, authz.Enforce, func(context.Context, authz.Subject, []authz.Check) ([]authz.Decision, error) {
				return tc.decisions, tc.err
			})
			handler := Bind(authorizer, testPolicy(), func(context.Context, *testInput) (httpserver.Response, error) {
				called = true
				return httpserver.NewStatusResponse(http.StatusNoContent), nil
			})
			_, ctx := runHandler(handler, testRequest(`{"id":"42"}`))
			if called || len(ctx.Errors) != 1 {
				t.Fatalf("called=%v, errors=%v", called, ctx.Errors)
			}
			if tc.name == "denied" {
				var denied *authz.DeniedError
				if !errors.As(ctx.Errors[0].Err, &denied) {
					t.Fatalf("expected denial, got %v", ctx.Errors[0].Err)
				}
			} else if !errors.Is(ctx.Errors[0].Err, failure) {
				t.Fatalf("expected evaluator failure, got %v", ctx.Errors[0].Err)
			}
		})
	}
}

func TestBindTypedInputContextAndOptions(t *testing.T) {
	req := testRequest(`{"id":"42"}`)
	called, success := false, false
	authorizer := testAuthorizer(t, authz.Enforce, func(ctx context.Context, subject authz.Subject, checks []authz.Check) ([]authz.Decision, error) {
		if ctx != req.Context() || subject.ID != "123" || len(checks) != 1 || checks[0].Resource.ID != "42" {
			t.Fatalf("unexpected evaluation: context=%v subject=%+v checks=%+v", ctx == req.Context(), subject, checks)
		}
		return []authz.Decision{{Allowed: true}}, nil
	})
	handler := BindWithOptions(authorizer, testPolicy(), func(ctx context.Context, input *testInput) (httpserver.Response, error) {
		called = true
		if ctx != req.Context() || input.ID != "42" {
			t.Fatalf("unexpected operation context or input: %+v", input)
		}
		return httpserver.NewStatusResponse(http.StatusNoContent), nil
	}, []authz.OperationOption[testInput, httpserver.Response]{
		authz.OnSuccess(func(ctx context.Context, input *testInput, _ httpserver.Response) {
			success = ctx == req.Context() && input.ID == "42"
		}),
	}, binding.JSON)
	writer, ctx := runHandler(handler, req)
	if !called || !success || len(ctx.Errors) != 0 || writer.Code != http.StatusNoContent {
		t.Fatalf("called=%v success=%v status=%d errors=%v", called, success, writer.Code, ctx.Errors)
	}
}

func TestBindPreparedBindingFailureStopsPreparation(t *testing.T) {
	prepared, evaluated, called := false, false, false
	authorizer := testAuthorizer(t, authz.Enforce, func(context.Context, authz.Subject, []authz.Check) ([]authz.Decision, error) {
		evaluated = true
		return nil, nil
	})
	handler := BindPrepared(authorizer, testPolicy(), func(context.Context, *testInput) (httpserver.Response, error) {
		called = true
		return nil, nil
	}, func(*http.Request, *testInput) error {
		prepared = true
		return nil
	})
	_, ctx := runHandler(handler, testRequest(`{"id":`))
	if prepared || evaluated || called || len(ctx.Errors) != 1 {
		t.Fatalf("prepared=%v evaluated=%v called=%v errors=%v", prepared, evaluated, called, ctx.Errors)
	}
}

func TestBindPrepared(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "prepare error"}[fail], func(t *testing.T) {
			failure := errors.New("invalid headers")
			prepared, evaluated, called := false, false, false
			authorizer := testAuthorizer(t, authz.Enforce, func(_ context.Context, _ authz.Subject, checks []authz.Check) ([]authz.Decision, error) {
				evaluated = true
				if checks[0].Resource.ID != "42" || !prepared {
					t.Fatal("authorization ran before prepared input")
				}
				return []authz.Decision{{Allowed: true}}, nil
			})
			handler := BindPrepared(authorizer, testPolicy(), func(_ context.Context, input *testInput) (httpserver.Response, error) {
				called = true
				if input.Header != "first,second" {
					t.Fatalf("header = %q", input.Header)
				}
				return httpserver.NewStatusResponse(http.StatusNoContent), nil
			}, func(req *http.Request, input *testInput) error {
				prepared = true
				if fail {
					return failure
				}
				input.Header = strings.Join(req.Header.Values("X-Test"), ",")
				return nil
			})
			req := testRequest(`{"id":"42"}`)
			req.Header.Add("X-Test", "first")
			req.Header.Add("X-Test", "second")
			_, ctx := runHandler(handler, req)
			if !prepared || evaluated == fail || called == fail {
				t.Fatalf("prepared=%v evaluated=%v called=%v", prepared, evaluated, called)
			}
			if fail && (len(ctx.Errors) != 1 || !errors.Is(ctx.Errors[0].Err, failure)) {
				t.Fatalf("expected prepare error, got %v", ctx.Errors)
			}
			if !fail && len(ctx.Errors) != 0 {
				t.Fatalf("unexpected errors: %v", ctx.Errors)
			}
		})
	}
}

func TestBindN(t *testing.T) {
	req := testRequest("")
	called := false
	authorizer := testAuthorizer(t, authz.Filter, func(context.Context, authz.Subject, []authz.Check) ([]authz.Decision, error) {
		return []authz.Decision{{Allowed: true}}, nil
	})
	policy := authz.Policy[struct{}, httpserver.Response]{Before: func(ctx context.Context, input *struct{}) ([]authz.Check, error) {
		if ctx != req.Context() || input == nil {
			t.Fatal("wrong context or nil input")
		}
		return []authz.Check{{Permission: "read"}}, nil
	}}
	handler := BindN(authorizer, policy, func(ctx context.Context) (httpserver.Response, error) {
		called = ctx == req.Context()
		return httpserver.NewStatusResponse(http.StatusNoContent), nil
	})
	writer, ctx := runHandler(handler, req)
	if !called || len(ctx.Errors) != 0 || writer.Code != http.StatusNoContent {
		t.Fatalf("called=%v status=%d errors=%v", called, writer.Code, ctx.Errors)
	}
}

func TestInvalidConfigurationPanics(t *testing.T) {
	allow := func(context.Context, authz.Subject, []authz.Check) ([]authz.Decision, error) {
		return []authz.Decision{{Allowed: true}}, nil
	}
	enforce := testAuthorizer(t, authz.Enforce, allow)
	shadow := testAuthorizer(t, authz.Shadow, allow)
	operation := func(context.Context, *testInput) (httpserver.Response, error) { return nil, nil }
	for name, construct := range map[string]func(){
		"nil authorizer":  func() { Bind(nil, testPolicy(), operation) },
		"zero authorizer": func() { Bind(&authz.Authorization{}, testPolicy(), operation) },
		"shadow":          func() { Bind(shadow, testPolicy(), operation) },
		"empty policy":    func() { Bind(enforce, authz.Policy[testInput, httpserver.Response]{}, operation) },
		"nil operation":   func() { Bind(enforce, testPolicy(), nil) },
		"nil prepare":     func() { BindPrepared(enforce, testPolicy(), operation, nil) },
		"nil option": func() {
			BindWithOptions(enforce, testPolicy(), operation, []authz.OperationOption[testInput, httpserver.Response]{nil})
		},
		"nil success callback": func() {
			BindWithOptions(enforce, testPolicy(), operation, []authz.OperationOption[testInput, httpserver.Response]{authz.OnSuccess[testInput, httpserver.Response](nil)})
		},
		"nil BindN operation": func() {
			BindN(enforce, authz.Policy[struct{}, httpserver.Response]{Before: func(context.Context, *struct{}) ([]authz.Check, error) { return nil, nil }}, nil)
		},
		"blank reason":       func() { Exempt(" \t\n", func(*gin.Context) {}) },
		"nil exempt handler": func() { Exempt("public health", nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic")
				}
			}()
			construct()
		})
	}
}

func TestExemptInvokesHandler(t *testing.T) {
	called := false
	handler := Exempt("public health", func(ctx *gin.Context) {
		called = true
		ctx.Status(http.StatusNoContent)
	})
	_, ctx := runHandler(handler, testRequest(""))
	if !called || len(ctx.Errors) != 0 {
		t.Fatalf("called=%v errors=%v", called, ctx.Errors)
	}
}
