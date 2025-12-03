package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	cfGraphQLEndpoint = "https://api.cloudflare.com/client/v4/graphql/"
	gqlQueryLimit     = 9999
	cfgraphqlreqlimit = 10 // 10 is the maximum amount of zones you can request at once
)

type GraphQL struct {
	httpClient *http.Client
	headers    http.Header
	reqTimeout time.Duration
}

type GraphQLRequest struct {
	Query string         `json:"query"`
	Vars  map[string]any `json:"variables"`
}

type GraphQLResponse struct {
	Data   any             `json:"data"`
	Errors []*GraphQLError `json:"errors"`
}

type GraphQLError struct {
	Message string `json:"message"`
}

func (e *GraphQLError) Error() string {
	return e.Message
}

var _ error = (*GraphQLError)(nil)

func NewGraphQLClient(headers http.Header, reqTimeout time.Duration) *GraphQL {
	return &GraphQL{
		httpClient: http.DefaultClient,
		headers:    headers,
		reqTimeout: reqTimeout,
	}
}

func (g *GraphQL) Run(ctx context.Context, gReq *GraphQLRequest, repStruct any) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, g.reqTimeout)
	defer cancel()

	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(gReq); err != nil {
		return fmt.Errorf("failed to marshal query body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfGraphQLEndpoint, &body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json; charset=utf-8")
	for k, vs := range g.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	rep, err := g.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer rep.Body.Close()

	gRep := GraphQLResponse{Data: repStruct}
	if err := json.NewDecoder(rep.Body).Decode(&gRep); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	errs := make([]error, len(gRep.Errors))
	for _, e := range gRep.Errors {
		errs = append(errs, e)
	}
	return errors.Join(errs...)
}

func NewGraphQLRequest(query string) *GraphQLRequest {
	return &GraphQLRequest{
		Query: query,
		Vars:  map[string]any{},
	}
}

func (r *GraphQLRequest) Var(key string, val any) {
	r.Vars[key] = val
}
