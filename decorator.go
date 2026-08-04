package authz

import (
	"context"
	"errors"
	"fmt"
	"reflect"
)

// Subject identifies the authenticated principal used for permission checks.
type Subject struct {
	Type string
	ID   string
}

type subjectContextKey struct{}

// WithSubject stores an authenticated subject in a request context.
func WithSubject(ctx context.Context, subject Subject) context.Context {
	return context.WithValue(ctx, subjectContextKey{}, subject)
}

// SubjectFromContext resolves the subject installed by authentication middleware.
func SubjectFromContext(ctx context.Context) (Subject, error) {
	subject, ok := ctx.Value(subjectContextKey{}).(Subject)
	if !ok || subject.Type == "" || subject.ID == "" {
		return Subject{}, errors.New("authorization subject is missing from context")
	}

	return subject, nil
}

// Resource identifies an object in the authorization graph.
type Resource struct {
	Type string
	ID   string
}

// ResourceIdentity identifies the authorization resource represented by an
// input or entity.
type ResourceIdentity interface {
	AuthorizationResource() Resource
}

// ResourceCollection exposes the authorization resources represented by a list
// result. It allows one generic bulk policy to evaluate all returned items at
// one consistency point and filter them internally in Filter mode. Filter mode
// expects the output to be a slice or a struct with a Results slice in the same
// order as the resources.
type ResourceCollection interface {
	AuthorizationResources() []Resource
}

// Check is one permission requirement for a subject and resource.
type Check struct {
	Resource   Resource
	Permission string
}

// Decision is the result of one check. Err is set when the evaluator could not
// evaluate that item; Allowed is false in that case.
type Decision struct {
	Allowed bool
	Err     error
}

// Evaluator is the framework-neutral seam for the authorization-service client.
// The decorator always uses the bulk operation, including for one check, so a
// list policy can evaluate all returned items at one consistency point.
type Evaluator interface {
	CheckBulk(context.Context, Subject, []Check) ([]Decision, error)
}

// Observation contains the data needed for shadow comparison logging.
type Observation struct {
	Phase     string
	Subject   Subject
	Checks    []Check
	Decisions []Decision
	Err       error
}

// Observer receives one observation for each non-empty policy phase.
type Observer interface {
	Observe(context.Context, Observation)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(context.Context, Observation)

func (f ObserverFunc) Observe(ctx context.Context, observation Observation) {
	f(ctx, observation)
}

// Mode controls whether a failed check changes the endpoint result.
type Mode uint8

const (
	// Shadow records denied and failed checks but never blocks the endpoint.
	Shadow Mode = iota
	// Enforce returns an authorization error for denied or failed checks.
	Enforce
	// Filter enforces before-operation checks and removes denied or failed
	// resources from bulk after-operation results.
	Filter
)

// SubjectResolver resolves the authenticated principal for one request.
type SubjectResolver func(context.Context) (Subject, error)

// Option customizes the behavior of a decorated operation.
type Option func(*decoratorOptions)

type decoratorOptions struct {
	subject  SubjectResolver
	mode     Mode
	observer Observer
}

// WithSubjectResolver overrides the default context subject resolver.
func WithSubjectResolver(subject SubjectResolver) Option {
	return func(options *decoratorOptions) {
		options.subject = subject
	}
}

// WithMode overrides the default Shadow mode.
func WithMode(mode Mode) Option {
	return func(options *decoratorOptions) {
		options.mode = mode
	}
}

// WithObserver configures the observer used for shadow comparison events.
func WithObserver(observer Observer) Option {
	return func(options *decoratorOptions) {
		options.observer = observer
	}
}

func defaultDecoratorOptions() decoratorOptions {
	return decoratorOptions{
		subject: SubjectFromContext,
		mode:    Shadow,
		observer: ObserverFunc(func(context.Context, Observation) {
		}),
	}
}

func resolveDecoratorOptions(options []Option) (decoratorOptions, error) {
	resolved := defaultDecoratorOptions()
	for _, option := range options {
		if option == nil {
			return decoratorOptions{}, errors.New("authorization option is nil")
		}

		option(&resolved)
	}

	if resolved.subject == nil {
		return decoratorOptions{}, errors.New("authorization subject resolver is required")
	}
	if resolved.mode != Shadow && resolved.mode != Enforce && resolved.mode != Filter {
		return decoratorOptions{}, fmt.Errorf("unsupported authorization mode %d", resolved.mode)
	}
	if resolved.observer == nil {
		return decoratorOptions{}, errors.New("authorization observer is required")
	}

	return resolved, nil
}

// Policy contains optional checks before an operation and after its typed
// result. After checks are useful for collection or batch shadow validation. A
// mutating operation should normally put all enforcing checks in Before.
type Policy[I, O any] struct {
	Before func(context.Context, *I) ([]Check, error)
	After  func(context.Context, *I, *O) ([]Check, error)

	filter func(*O, []Decision) error
}

// ResourcePolicy creates the standard policy for an input that identifies one
// resource. The check runs before the operation so Enforce mode can prevent the
// operation from running when the subject lacks the supplied permission.
func ResourcePolicy[I ResourceIdentity, O any](permission string) Policy[I, O] {
	return Policy[I, O]{
		Before: func(_ context.Context, input *I) ([]Check, error) {
			if input == nil {
				return nil, errors.New("authorization resource policy input is nil")
			}

			return []Check{{
				Resource:   (*input).AuthorizationResource(),
				Permission: permission,
			}}, nil
		},
	}
}

// BulkResourcePolicy creates a policy for an operation with a general resource
// check before execution and individual resource checks after execution. It is
// suitable for list, search, batch, or any other operation returning a resource
// collection. The bulk evaluator receives all item checks together. In Filter
// mode, denied or failed items are removed from the returned collection by the
// decorator; the collection exposes no filtering method.
func BulkResourcePolicy[I ResourceIdentity, O ResourceCollection](generalPermission string, itemPermission string) Policy[I, O] {
	return Policy[I, O]{
		Before: func(_ context.Context, input *I) ([]Check, error) {
			if input == nil {
				return nil, errors.New("authorization bulk resource policy input is nil")
			}

			return []Check{{
				Resource:   (*input).AuthorizationResource(),
				Permission: generalPermission,
			}}, nil
		},
		After: func(_ context.Context, _ *I, output *O) ([]Check, error) {
			if output == nil {
				return nil, errors.New("authorization bulk resource policy output is nil")
			}

			resources := (*output).AuthorizationResources()
			checks := make([]Check, 0, len(resources))
			for _, resource := range resources {
				checks = append(checks, Check{
					Resource:   resource,
					Permission: itemPermission,
				})
			}

			return checks, nil
		},
		filter: filterResourceCollection[O],
	}
}

// filterResourceCollection is intentionally internal. BulkResourcePolicy uses
// it in Filter mode so resource collection types do not need to expose a
// filtering method. The resource order must match the decision order. A
// collection output is either a slice or a struct with a settable Results slice.
func filterResourceCollection[O ResourceCollection](output *O, decisions []Decision) error {
	if output == nil {
		return errors.New("authorization bulk resource policy output is nil")
	}

	resources := (*output).AuthorizationResources()
	if len(resources) != len(decisions) {
		return fmt.Errorf("authorization evaluator returned %d decisions for %d resources", len(decisions), len(resources))
	}

	allowed := make([]bool, len(decisions))
	for index, decision := range decisions {
		allowed[index] = decision.Err == nil && decision.Allowed
	}

	return filterResourceCollectionOutput(output, allowed)
}

func filterResourceCollectionOutput(output any, allowed []bool) error {
	value := reflect.ValueOf(output)
	for value.IsValid() && value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return errors.New("authorization collection output is nil")
		}

		value = value.Elem()
	}
	if !value.IsValid() {
		return errors.New("authorization collection output is invalid")
	}

	if value.Kind() == reflect.Struct {
		value = value.FieldByName("Results")
	}
	if !value.IsValid() || value.Kind() != reflect.Slice {
		return errors.New("authorization collection output must be a slice or contain a Results slice")
	}
	if !value.CanSet() {
		return errors.New("authorization collection output slice cannot be changed")
	}
	if value.Len() != len(allowed) {
		return fmt.Errorf("authorization collection output has %d items for %d decisions", value.Len(), len(allowed))
	}

	filtered := reflect.MakeSlice(value.Type(), 0, value.Len())
	for index, keep := range allowed {
		if keep {
			filtered = reflect.Append(filtered, value.Index(index))
		}
	}

	value.Set(filtered)

	return nil
}

// Operation is the typed application operation that runs between binding and
// HTTP response presentation.
type Operation[I, O any] func(context.Context, *I) (O, error)

type decorator[I, O any] struct {
	evaluator Evaluator
	policy    Policy[I, O]
	next      Operation[I, O]
	subject   SubjectResolver
	mode      Mode
	observer  Observer
}

// Authorization stores an evaluator and resolved options shared by any
// number of typed decorated operations. The operation input/output types are
// inferred by the generic Decorate function instead of being fixed here.
type Authorization struct {
	evaluator Evaluator
	options   decoratorOptions
}

// NewAuthorization creates a configured authorizer with the supplied evaluator
// and functional options. SubjectFromContext, Shadow mode, and a no-op observer
// are used when the corresponding options are omitted. Create one instance for
// each evaluator/options configuration and reuse it across operations.
func NewAuthorization(evaluator Evaluator, options ...Option) (*Authorization, error) {
	if evaluator == nil {
		return nil, errors.New("authorization evaluator is required")
	}

	resolved, err := resolveDecoratorOptions(options)
	if err != nil {
		return nil, err
	}

	return &Authorization{
		evaluator: evaluator,
		options:   resolved,
	}, nil
}

// Decorate applies a configured authorizer to a typed policy and operation.
// The generic input/output types are inferred independently for every call,
// so one Authorization can be reused for multiple operation shapes. Invalid
// decorator configuration is a programming error and causes a panic during
// route construction, which keeps the successful path convenient to compose.
func Decorate[I, O any](authorizer *Authorization, policy Policy[I, O], next Operation[I, O]) Operation[I, O] {
	if authorizer == nil {
		panic("authorization authorizer is required")
	}
	if next == nil {
		panic("next operation is required")
	}

	wrapped := &decorator[I, O]{
		evaluator: authorizer.evaluator,
		policy:    policy,
		next:      next,
		subject:   authorizer.options.subject,
		mode:      authorizer.options.mode,
		observer:  authorizer.options.observer,
	}

	return wrapped.Handle
}

// DecorateWithOptions is the one-shot form for operations that need unique
// authorization options. It creates a configured authorizer and delegates to
// Decorate.
func DecorateWithOptions[I, O any](evaluator Evaluator, policy Policy[I, O], next Operation[I, O], options ...Option) (Operation[I, O], error) {
	authorizer, err := NewAuthorization(evaluator, options...)
	if err != nil {
		return nil, err
	}

	return Decorate(authorizer, policy, next), nil
}

func (d *decorator[I, O]) Handle(ctx context.Context, input *I) (output O, err error) {
	if checks, policyErr := d.before(ctx, input); policyErr != nil {
		if d.mode == Shadow {
			d.observe(ctx, "before", Subject{}, nil, nil, policyErr)
		} else {
			return output, fmt.Errorf("build authorization checks: %w", policyErr)
		}
	} else if _, err = d.evaluate(ctx, "before", checks); err != nil {
		return output, err
	}

	output, err = d.next(ctx, input)
	if err != nil {
		return output, err
	}

	if checks, policyErr := d.after(ctx, input, &output); policyErr != nil {
		if d.mode == Shadow {
			d.observe(ctx, "after", Subject{}, nil, nil, policyErr)
		} else {
			return output, fmt.Errorf("build result authorization checks: %w", policyErr)
		}
	} else if decisions, evaluationErr := d.evaluate(ctx, "after", checks); evaluationErr != nil {
		return output, evaluationErr
	} else if d.mode == Filter && len(checks) > 0 {
		if err = d.filter(&output, decisions); err != nil {
			return output, fmt.Errorf("filter authorization results: %w", err)
		}
	}

	return output, nil
}

func (d *decorator[I, O]) before(ctx context.Context, input *I) ([]Check, error) {
	if d.policy.Before == nil {
		return nil, nil
	}

	return d.policy.Before(ctx, input)
}

func (d *decorator[I, O]) after(ctx context.Context, input *I, output *O) ([]Check, error) {
	if d.policy.After == nil {
		return nil, nil
	}

	return d.policy.After(ctx, input, output)
}

func (d *decorator[I, O]) filter(output *O, decisions []Decision) error {
	if d.policy.filter == nil {
		for _, decision := range decisions {
			if decision.Err != nil || !decision.Allowed {
				return errors.New("authorization filter mode requires a bulk resource policy")
			}
		}

		return nil
	}

	return d.policy.filter(output, decisions)
}

func (d *decorator[I, O]) evaluate(ctx context.Context, phase string, checks []Check) ([]Decision, error) {
	if len(checks) == 0 {
		return nil, nil
	}

	subject, err := d.subject(ctx)
	if err != nil {
		d.observe(ctx, phase, Subject{}, checks, nil, err)
		if d.mode == Shadow {
			return nil, nil
		}

		return nil, fmt.Errorf("resolve authorization subject: %w", err)
	}

	decisions, err := d.evaluator.CheckBulk(ctx, subject, checks)
	d.observe(ctx, phase, subject, checks, decisions, err)
	if err != nil {
		if d.mode == Shadow {
			return nil, nil
		}

		return nil, fmt.Errorf("evaluate %s authorization checks: %w", phase, err)
	}
	if len(decisions) != len(checks) {
		err = fmt.Errorf("authorization evaluator returned %d decisions for %d checks", len(decisions), len(checks))
		if d.mode == Shadow {
			return nil, nil
		}

		return nil, err
	}

	for index, decision := range decisions {
		if decision.Err != nil {
			if d.mode == Shadow || (d.mode == Filter && phase == "after") {
				continue
			}

			return decisions, fmt.Errorf("evaluate authorization check %d: %w", index, decision.Err)
		}
		if !decision.Allowed {
			if d.mode == Shadow || (d.mode == Filter && phase == "after") {
				continue
			}

			return decisions, &DeniedError{Phase: phase, Check: checks[index]}
		}
	}

	return decisions, nil
}

func (d *decorator[I, O]) observe(ctx context.Context, phase string, subject Subject, checks []Check, decisions []Decision, err error) {
	// The evaluator can return per-item errors. Those are included in Decisions;
	// this field is reserved for a request-level failure such as a timeout.
	d.observer.Observe(ctx, Observation{
		Phase:     phase,
		Subject:   subject,
		Checks:    checks,
		Decisions: decisions,
		Err:       err,
	})
}

// DeniedError is returned in Enforce mode, or for a denied before-operation
// check in Filter mode.
type DeniedError struct {
	Phase string
	Check Check
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("permission %q denied on %s:%s", e.Check.Permission, e.Check.Resource.Type, e.Check.Resource.ID)
}
