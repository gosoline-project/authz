package main

import (
	"context"
	"errors"
	"strconv"

	"github.com/gosoline-project/authz"
	"github.com/gosoline-project/httpserver"
	"github.com/gosoline-project/sqlh"
	"github.com/gosoline-project/sqlr"
)

type CreateCampaignInput struct {
	BusinessUnit string `json:"business_unit_id" binding:"required"`
	Name         string `json:"name" binding:"required"`
}

type UpdateCampaignInput struct {
	sqlh.InputById[int]
	BusinessUnit string `json:"business_unit_id" binding:"required"`
	Name         string `json:"name" binding:"required"`
}

type StoredCampaign struct {
	sqlr.Entity[int]
	BusinessUnit string `db:"business_unit"`
	Name         string
}

type CampaignCrud = sqlh.CrudHandler[int, StoredCampaign, int, CreateCampaignInput, UpdateCampaignInput, sqlh.ListInput, Campaign]

func newCampaignCrud(authorizer *authz.Authorization) httpserver.RegisterFactoryFunc {
	transformer := &CampaignTransformer{}
	definition := sqlh.NewCrudDefinition(
		transformer.TransformCreateInput,
		transformer.TransformUpdateInput,
		transformer.TransformPatchInputFromEntity,
		transformer.TransformOutput,
	)

	return httpserver.With(
		sqlh.NewCrudHandler(sqlh.SimpleCrudDefinition(definition)),
		func(router *httpserver.Router, handler *CampaignCrud) {
			router.POST(
				"/campaigns",
				httpserver.Bind(authz.Decorate(
					authorizer,
					authz.ResourcePolicy[CreateCampaignInput, Campaign]("create_campaign"),
					handler.Create,
				)),
			)
			router.GET(
				"/campaigns/:id",
				httpserver.Bind(
					authz.Decorate(authorizer, readCampaignPolicy(), handler.Read),
					httpserver.NoBodyBinding{},
				),
			)
		},
	)
}

func (input CreateCampaignInput) AuthorizationResource() authz.Resource {
	return authz.Resource{Type: "account", ID: input.BusinessUnit}
}

func readCampaignPolicy() authz.Policy[sqlh.InputById[int], Campaign] {
	return authz.Policy[sqlh.InputById[int], Campaign]{
		Before: func(_ context.Context, input *sqlh.InputById[int]) ([]authz.Check, error) {
			if input == nil {
				return nil, errors.New("campaign read input is nil")
			}

			return []authz.Check{{
				Resource:   authz.Resource{Type: "campaign", ID: strconv.Itoa(input.Id)},
				Permission: "read",
			}}, nil
		},
	}
}

type CampaignTransformer struct{}

func (*CampaignTransformer) TransformCreateInput(_ context.Context, input *CreateCampaignInput) (*StoredCampaign, error) {
	return &StoredCampaign{
		BusinessUnit: input.BusinessUnit,
		Name:         input.Name,
	}, nil
}

func (*CampaignTransformer) TransformUpdateInput(_ context.Context, campaign *StoredCampaign, input *UpdateCampaignInput) (*StoredCampaign, error) {
	campaign.BusinessUnit = input.BusinessUnit
	campaign.Name = input.Name

	return campaign, nil
}

func (*CampaignTransformer) TransformPatchInputFromEntity(_ context.Context, campaign *StoredCampaign) (*UpdateCampaignInput, error) {
	return &UpdateCampaignInput{
		InputById:    sqlh.InputById[int]{Id: campaign.Id},
		BusinessUnit: campaign.BusinessUnit,
		Name:         campaign.Name,
	}, nil
}

func (*CampaignTransformer) TransformOutput(_ context.Context, campaign *StoredCampaign) (Campaign, error) {
	return Campaign{
		ID:           campaign.Id,
		BusinessUnit: campaign.BusinessUnit,
		Name:         campaign.Name,
	}, nil
}
