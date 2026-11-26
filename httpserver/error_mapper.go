// Package authzhttp integrates typed authorization with HTTP routes.
//
// Bind, BindPrepared, BindWithOptions, and BindN reject Shadow mode and
// policies without Before or After functions when routes are constructed.
// Policies must return the checks appropriate to the request; an empty check
// list performs no authorization. Use Before checks to prevent an operation
// from running: After checks run only after the operation has completed.
//
// Authentication middleware should place the subject in the HTTP request
// context with authz.WithSubject. These binders pass that request context to
// policies and operations. Configure ErrorMapper with the HTTP server's error
// handling middleware to map authorization denials to HTTP 403.
package authzhttp

import (
	"errors"
	"net/http"

	"github.com/gosoline-project/authz"
)

// ErrorMapper maps authorization errors to HTTP status codes for use with an
// HTTP server's generic error-mapping hook.
func ErrorMapper(err error) (statusCode int, handled bool) {
	var deniedError *authz.DeniedError
	if errors.As(err, &deniedError) {
		return http.StatusForbidden, true
	}

	return 0, false
}
