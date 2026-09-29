package authzhttp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gosoline-project/authz"
)

type consistencyTestInput struct {
	ID string
}

func (input consistencyTestInput) AuthorizationResource() authz.Resource {
	return authz.Resource{Type: "campaign", ID: input.ID}
}

type consistencyTestEvaluator func(context.Context, authz.Subject, []authz.Check) ([]authz.Decision, error)

func (f consistencyTestEvaluator) CheckBulk(ctx context.Context, subject authz.Subject, checks []authz.Check) ([]authz.Decision, error) {
	return f(ctx, subject, checks)
}

func TestConsistencyMiddlewarePropagatesIncomingTokenToPolicyEvaluator(t *testing.T) {
	incomingHeader := consistencyTokenForTest(time.Now(), "incoming-zed-token")
	var evaluatorToken string
	var evaluatorNewToken string
	authorizer, err := authz.NewAuthorization(consistencyTestEvaluator(func(ctx context.Context, _ authz.Subject, _ []authz.Check) ([]authz.Decision, error) {
		evaluatorToken = authz.ConsistencyToken(ctx)
		evaluatorNewToken = authz.NewConsistencyToken(ctx)

		return []authz.Decision{{Allowed: true}}, nil
	}))
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	engine := gin.New()
	engine.Use(ConsistencyMiddleware())
	engine.GET("/", func(c *gin.Context) {
		c.Header(accessControlExposeHeaders, "ETag, X-Request-ID")
		operation := authz.Decorate(
			authorizer,
			authz.ResourcePolicy[consistencyTestInput, string]("read"),
			func(_ context.Context, input *consistencyTestInput) (string, error) {
				return input.ID, nil
			},
		)
		result, err := operation(
			authz.WithSubject(c.Request.Context(), authz.Subject{Type: "user", ID: "42"}),
			&consistencyTestInput{ID: "13"},
		)
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}

		c.String(http.StatusOK, result)
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(consistencyTokenHeader, incomingHeader)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "13" {
		t.Fatalf("response = %d %q, want 200 and decorated operation result", response.Code, response.Body.String())
	}
	if evaluatorToken != "incoming-zed-token" {
		t.Fatalf("policy evaluator received consistency token %q, want incoming token", evaluatorToken)
	}
	if evaluatorNewToken != "" {
		t.Fatalf("policy evaluator received new consistency token %q, want empty", evaluatorNewToken)
	}
	if got := response.Header().Get(consistencyTokenHeader); got != incomingHeader {
		t.Fatalf("response consistency token = %q, want unchanged incoming header", got)
	}
	for _, name := range []string{"ETag", "X-Request-ID", consistencyTokenHeader} {
		if !hasExposedHeader(response.Header(), name) {
			t.Errorf("Access-Control-Expose-Headers does not include %q: %v", name, response.Header().Values(accessControlExposeHeaders))
		}
	}
}

func TestConsistencyMiddlewarePublishesNewTokenBeforeStatusOnlyCommit(t *testing.T) {
	incomingHeader := consistencyTokenForTest(time.Now(), "incoming-zed-token")
	var evaluatorToken string
	var evaluatorNewToken string
	authorizer, err := authz.NewAuthorization(consistencyTestEvaluator(func(ctx context.Context, _ authz.Subject, _ []authz.Check) ([]authz.Decision, error) {
		evaluatorToken = authz.ConsistencyToken(ctx)
		evaluatorNewToken = authz.NewConsistencyToken(ctx)

		return []authz.Decision{{Allowed: true}}, nil
	}))
	if err != nil {
		t.Fatalf("NewAuthorization returned an error: %v", err)
	}

	engine := gin.New()
	engine.Use(ConsistencyMiddleware())
	engine.GET("/", func(c *gin.Context) {
		c.Header(accessControlExposeHeaders, "ETag")
		authz.SetConsistencyToken(c.Request.Context(), "published-zed-token")
		operation := authz.Decorate(
			authorizer,
			authz.ResourcePolicy[consistencyTestInput, string]("read"),
			func(_ context.Context, input *consistencyTestInput) (string, error) {
				return input.ID, nil
			},
		)
		if _, err := operation(
			authz.WithSubject(c.Request.Context(), authz.Subject{Type: "user", ID: "42"}),
			&consistencyTestInput{ID: "13"},
		); err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}

		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(consistencyTokenHeader, incomingHeader)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("status-only response = %d %q, want 204 with empty body", response.Code, response.Body.String())
	}
	if evaluatorToken != "published-zed-token" || evaluatorNewToken != "published-zed-token" {
		t.Fatalf("policy evaluator saw token/new token %q/%q, want published token", evaluatorToken, evaluatorNewToken)
	}
	outgoingHeader := response.Header().Get(consistencyTokenHeader)
	if outgoingHeader == incomingHeader {
		t.Fatal("response echoed the incoming token instead of the published token")
	}
	outgoingToken, valid := parseConsistencyToken(outgoingHeader, time.Now())
	if !valid || outgoingToken != "published-zed-token" {
		t.Fatalf("response consistency token %q parsed as %q, valid=%t", outgoingHeader, outgoingToken, valid)
	}
	if !hasExposedHeader(response.Header(), "ETag") || !hasExposedHeader(response.Header(), consistencyTokenHeader) {
		t.Fatalf("Access-Control-Expose-Headers did not preserve existing headers and expose the token: %v", response.Header().Values(accessControlExposeHeaders))
	}
}

func TestConsistencyMiddlewareHandlesExplicitWriteHeaderNow(t *testing.T) {
	engine := gin.New()
	engine.Use(ConsistencyMiddleware())
	engine.GET("/", func(c *gin.Context) {
		authz.SetConsistencyToken(c.Request.Context(), "explicit-zed-token")
		c.Status(http.StatusNoContent)
		c.Writer.WriteHeaderNow()
	})

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("status-only response = %d %q, want 204 with empty body", response.Code, response.Body.String())
	}
	if token, valid := parseConsistencyToken(response.Header().Get(consistencyTokenHeader), time.Now()); !valid || token != "explicit-zed-token" {
		t.Fatalf("response consistency token parsed as %q, valid=%t", token, valid)
	}
}

func TestConsistencyMiddlewareIgnoresInvalidExpiredAndFutureTokens(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		header string
	}{
		{name: "absent"},
		{name: "malformed", header: "not-a-consistency-token"},
		{name: "wrong version", header: "v2." + base64.StdEncoding.EncodeToString([]byte(strconv.FormatInt(now.UnixMilli(), 10)+"|zed-token"))},
		{name: "invalid base64", header: "v1.!?"},
		{name: "invalid payload", header: "v1." + base64.StdEncoding.EncodeToString([]byte("missing-separator"))},
		{name: "expired", header: consistencyTokenForTest(now.Add(-31*time.Second), "expired-token")},
		{name: "future", header: consistencyTokenForTest(now.Add(time.Second), "future-token")},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			engine := gin.New()
			engine.Use(ConsistencyMiddleware())
			engine.GET("/", func(c *gin.Context) {
				if got := authz.ConsistencyToken(c.Request.Context()); got != "" {
					t.Errorf("ConsistencyToken = %q, want empty", got)
				}
				if got := authz.NewConsistencyToken(c.Request.Context()); got != "" {
					t.Errorf("NewConsistencyToken = %q, want empty", got)
				}

				c.Status(http.StatusAccepted)
			})

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if testCase.header != "" {
				request.Header.Set(consistencyTokenHeader, testCase.header)
			}
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)

			if response.Code != http.StatusAccepted || response.Body.Len() != 0 {
				t.Fatalf("status-only response = %d %q, want 202 with empty body", response.Code, response.Body.String())
			}
			if got := response.Header().Get(consistencyTokenHeader); got != "" {
				t.Fatalf("response contains consistency token %q for ignored input", got)
			}
			if got := response.Header().Get(accessControlExposeHeaders); got != "" {
				t.Fatalf("response exposes consistency tokens without returning one: %q", got)
			}
		})
	}
}

func consistencyTokenForTest(issuedAt time.Time, token string) string {
	payload := strconv.FormatInt(issuedAt.UnixMilli(), 10) + "|" + token

	return "v1." + base64.StdEncoding.EncodeToString([]byte(payload))
}

func hasExposedHeader(header http.Header, name string) bool {
	for _, value := range header.Values(accessControlExposeHeaders) {
		for _, exposed := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(exposed), name) {
				return true
			}
		}
	}

	return false
}
