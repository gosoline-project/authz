package authzhttp

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/gosoline-project/authz"
)

func TestErrorMapperMapsDeniedError(t *testing.T) {
	err := &authz.DeniedError{
		Phase: "before",
		Check: authz.Check{
			Resource:   authz.Resource{Type: "campaign", ID: "13"},
			Permission: "read",
		},
	}

	statusCode, handled := ErrorMapper(err)

	if statusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, statusCode)
	}
	if !handled {
		t.Fatal("expected denied error to be handled")
	}
}

func TestErrorMapperMapsWrappedDeniedError(t *testing.T) {
	err := fmt.Errorf("handler failed: %w", &authz.DeniedError{})

	statusCode, handled := ErrorMapper(err)

	if statusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, statusCode)
	}
	if !handled {
		t.Fatal("expected wrapped denied error to be handled")
	}
}

func TestErrorMapperIgnoresOtherErrors(t *testing.T) {
	statusCode, handled := ErrorMapper(errors.New("other error"))

	if statusCode != 0 {
		t.Fatalf("expected status 0, got %d", statusCode)
	}
	if handled {
		t.Fatal("expected other error not to be handled")
	}
}
