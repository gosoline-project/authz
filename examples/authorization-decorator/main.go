package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gosoline-project/authz"
	authzhttp "github.com/gosoline-project/authz/httpserver"
	"github.com/gosoline-project/httpserver"
	"github.com/justtrackio/gosoline/pkg/application"
	"github.com/justtrackio/gosoline/pkg/cfg"
	gosoLog "github.com/justtrackio/gosoline/pkg/log"
)

//go:embed config.dist.yml
var configDist []byte

func main() {
	httpserver.RunServers(map[string]httpserver.ServerDefinition{
		"default": {
			RouterFactory: func(ctx context.Context, config cfg.Config, logger gosoLog.Logger, router *httpserver.Router) error {
				authorizer, err := newAuthorizer()
				if err != nil {
					return err
				}

				router.Use(withDemoSubject())
				router.HandleWith(httpserver.With(NewHandler, func(router *httpserver.Router, handler *Handler) {
					registerRoutes(router, handler, authorizer)
				}))
				router.HandleWith(newCampaignCrud(authorizer))

				return nil
			},
			Options: []httpserver.ServerOption{
				httpserver.WithErrorMapper(authzhttp.ErrorMapper),
			},
		},
	}, application.WithConfigBytes(configDist, "yml"))
}

// Handler contains ordinary typed application operations. Authorization is
// applied next to route registration, after this handler has been constructed.
type Handler struct{}

type ListCampaignsInput struct {
	BusinessUnitID string `form:"business_unit_id" binding:"required"`
}

type Campaign struct {
	ID           int    `json:"id"`
	BusinessUnit string `json:"business_unit_id"`
	Name         string `json:"name"`
}

type CampaignList struct {
	Results []Campaign `json:"results"`
}

func NewHandler(ctx context.Context, config cfg.Config, logger gosoLog.Logger) (*Handler, error) {
	return &Handler{}, nil
}

func newAuthorizer() (*authz.Authorization, error) {
	evaluator := demoEvaluator{}
	observer := authz.WithObserver(authz.ObserverFunc(logAuthorizationObservation))

	authorizer, err := authz.NewAuthorization(
		evaluator,
		observer,
		authz.WithMode(authz.Filter),
	)
	if err != nil {
		return nil, fmt.Errorf("create authorization authorizer: %w", err)
	}

	return authorizer, nil
}

func registerRoutes(router *httpserver.Router, handler *Handler, authorizer *authz.Authorization) {
	router.GET(
		"/campaigns",
		httpserver.Bind(
			authz.Decorate(
				authorizer,
				authz.BulkResourcePolicy[ListCampaignsInput, CampaignList]("list_campaigns", "read"),
				handler.listCampaigns,
			),
		),
	)
}

func (*Handler) listCampaigns(ctx context.Context, input *ListCampaignsInput) (CampaignList, error) {
	return CampaignList{
		Results: []Campaign{
			{ID: 12, BusinessUnit: input.BusinessUnitID, Name: "Visible campaign"},
			{ID: 13, BusinessUnit: input.BusinessUnitID, Name: "Shadow-denied campaign"},
		},
	}, nil
}

func (input ListCampaignsInput) AuthorizationResource() authz.Resource {
	return authz.Resource{Type: "account", ID: input.BusinessUnitID}
}

func (campaign Campaign) AuthorizationResource() authz.Resource {
	return authz.Resource{Type: "campaign", ID: strconv.Itoa(campaign.ID)}
}

func (campaigns CampaignList) AuthorizationResources() []authz.Resource {
	resources := make([]authz.Resource, 0, len(campaigns.Results))
	for _, campaign := range campaigns.Results {
		resources = append(resources, campaign.AuthorizationResource())
	}

	return resources
}

// demoEvaluator stands in for the authorization-service client. It deliberately
// denies campaign 13 so the list endpoint demonstrates after-result bulk
// filtering in Filter mode.
type demoEvaluator struct{}

func (demoEvaluator) CheckBulk(ctx context.Context, subject authz.Subject, checks []authz.Check) ([]authz.Decision, error) {
	decisions := make([]authz.Decision, 0, len(checks))
	for _, check := range checks {
		allowed := check.Resource.ID != "13"
		decisions = append(decisions, authz.Decision{Allowed: allowed})
	}

	return decisions, nil
}

func logAuthorizationObservation(ctx context.Context, observation authz.Observation) {
	for index, check := range observation.Checks {
		decision := "unknown"
		if index < len(observation.Decisions) {
			if observation.Decisions[index].Err != nil {
				decision = "error"
			} else if observation.Decisions[index].Allowed {
				decision = "allow"
			} else {
				decision = "deny"
			}
		}

		log.Printf(
			"authorization phase=%s subject=%s:%s resource=%s:%s permission=%s decision=%s error=%v",
			observation.Phase,
			observation.Subject.Type,
			observation.Subject.ID,
			check.Resource.Type,
			check.Resource.ID,
			check.Permission,
			decision,
			observation.Err,
		)
	}
}

func withDemoSubject() gin.HandlerFunc {
	return func(ginCtx *gin.Context) {
		ctx := authz.WithSubject(ginCtx.Request.Context(), authz.Subject{
			Type: "user",
			ID:   strconv.Itoa(42),
		})
		ginCtx.Request = ginCtx.Request.WithContext(ctx)
		ginCtx.Next()
	}
}
