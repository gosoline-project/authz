// Package authzhttp provides HTTP integration for authz errors.
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
