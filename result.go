package authz

// Result describes the outcome of an authorization evaluation.
type Result string

const (
	// ResultAllow indicates that access is allowed.
	ResultAllow Result = "allow"
	// ResultDeny indicates that access is denied.
	ResultDeny Result = "deny"
	// ResultError indicates that evaluation failed.
	ResultError Result = "error"
	// ResultNotEvaluated indicates that evaluation did not occur.
	ResultNotEvaluated Result = "not_evaluated"
)

// Result returns the decision's outcome. An error takes precedence over Allowed;
// a zero-value Decision is denied.
func (d Decision) Result() Result {
	if d.Err != nil {
		return ResultError
	}
	if d.Allowed {
		return ResultAllow
	}

	return ResultDeny
}
