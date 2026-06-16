package cfgql

import (
	"context"
	"slices"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/lablabs/cloudflare-exporter/converge"
)

const MaxZonesPerQuery = 10

type GQLClient interface {
	RunGQL(ctx context.Context, req *GQLRequest, dest any) error
}

type GQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// FetchZones chunks zones into batches, calls chunkFetcher for each, and
// collects observations. Errors per chunk are logged as warnings and skipped.
func FetchZones(
	ctx context.Context,
	zones []cfzones.Zone,
	warnTag string,
	chunkFetcher func(ctx context.Context, chunk []cfzones.Zone, ids []string) ([]converge.Observation, error),
) ([]converge.Observation, error) {
	var allObs []converge.Observation
	l := converge.LoggerFromContext(ctx)
	for chunk := range slices.Chunk(zones, MaxZonesPerQuery) {
		obs, err := chunkFetcher(ctx, chunk, ZoneIDs(chunk))
		if err != nil {
			l.WithError(err).Warnf("%s: skipping chunk", warnTag)
			continue
		}
		allObs = append(allObs, obs...)
	}
	return allObs, nil
}

func ZoneIDs(zones []cfzones.Zone) []string {
	ids := make([]string, len(zones))
	for i, z := range zones {
		ids[i] = z.ID
	}
	return ids
}

func FindZoneName(zones []cfzones.Zone, id string) string {
	for _, z := range zones {
		if z.ID == id {
			return z.Name
		}
	}
	return id
}
