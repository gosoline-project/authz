package authzhttp

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gosoline-project/authz"
	"github.com/gosoline-project/httpserver"
)

// Bind binds a typed request and applies an enforcing authorization policy.
// Invalid configuration panics during route construction. The policy and
// operation receive the HTTP request context, not the pooled Gin context.
func Bind[I, O any](authorizer *authz.Authorization, policy authz.Policy[I, O], handler authz.Operation[I, O], binders ...binding.Binding) gin.HandlerFunc {
	return BindWithOptions(authorizer, policy, handler, nil, binders...)
}

// BindWithOptions is Bind with per-operation options such as authz.OnSuccess.
func BindWithOptions[I, O any](authorizer *authz.Authorization, policy authz.Policy[I, O], handler authz.Operation[I, O], options []authz.OperationOption[I, O], binders ...binding.Binding) gin.HandlerFunc {
	return bind(authorizer, policy, handler, options, nil, binders...)
}

// BindPrepared runs prepare after binding and before authorization, allowing
// request metadata to be validated and added to the typed input. A preparation
// error prevents both authorization and the operation. Prepare must not be nil.
func BindPrepared[I, O any](authorizer *authz.Authorization, policy authz.Policy[I, O], handler authz.Operation[I, O], prepare func(*http.Request, *I) error, binders ...binding.Binding) gin.HandlerFunc {
	if prepare == nil {
		panic("authorization request preparation is required")
	}
	return bind(authorizer, policy, handler, nil, prepare, binders...)
}

func bind[I, O any](authorizer *authz.Authorization, policy authz.Policy[I, O], handler authz.Operation[I, O], options []authz.OperationOption[I, O], prepare func(*http.Request, *I) error, binders ...binding.Binding) gin.HandlerFunc {
	if err := authz.ValidateEnforcingPolicy(authorizer, policy); err != nil {
		panic(err)
	}
	operation := authz.Decorate(authorizer, policy, handler, options...)
	return httpserver.BindR(func(_ context.Context, request *http.Request, input *I) (O, error) {
		if prepare != nil {
			if err := prepare(request, input); err != nil {
				var zero O
				return zero, err
			}
		}
		return operation(request.Context(), input)
	}, binders...)
}

// BindN adapts an operation without typed request binding. Its policy receives
// an empty struct and its operation receives the HTTP request context.
func BindN[O any](authorizer *authz.Authorization, policy authz.Policy[struct{}, O], handler func(context.Context) (O, error)) gin.HandlerFunc {
	if err := authz.ValidateEnforcingPolicy(authorizer, policy); err != nil {
		panic(err)
	}
	if handler == nil {
		panic("next operation is required")
	}
	operation := authz.Decorate(authorizer, policy, func(ctx context.Context, _ *struct{}) (O, error) {
		return handler(ctx)
	})
	return httpserver.BindNR(func(_ context.Context, request *http.Request) (O, error) {
		return operation(request.Context(), &struct{}{})
	})
}

// Exempt marks a Gin handler as intentionally outside authorization. The reason
// must describe the exemption and cannot be blank; the handler must not be nil.
// Exempt performs no authentication or authorization itself.
func Exempt(reason string, handler gin.HandlerFunc) gin.HandlerFunc {
	if strings.TrimSpace(reason) == "" {
		panic("authorization exemption reason is required")
	}
	if handler == nil {
		panic("authorization exemption handler is required")
	}
	return handler
}
