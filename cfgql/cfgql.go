package cfgql

import "context"

type GQLClient interface {
	RunGQL(ctx context.Context, req *GQLRequest, dest any) error
}

type GQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}
