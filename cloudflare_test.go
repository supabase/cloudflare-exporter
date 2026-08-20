package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	cf "github.com/cloudflare/cloudflare-go/v7"
	cfoption "github.com/cloudflare/cloudflare-go/v7/option"
	cfzones "github.com/cloudflare/cloudflare-go/v7/zones"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serveCloudflareAPI points the package level cfclient at a test server that
// answers every request with body, restoring the original client when the test
// ends. It returns a pointer to the path of the most recent request.
func serveCloudflareAPI(t *testing.T, body string) *string {
	t.Helper()

	var lastPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	original := cfclient
	t.Cleanup(func() { cfclient = original })

	cfclient = cf.NewClient(
		cfoption.WithAPIToken("test-token"),
		cfoption.WithBaseURL(srv.URL+"/"),
	)

	return &lastPath
}

func TestFetchCustomHostnamesQuota(t *testing.T) {
	t.Run("decodes quota via the generic client helper", func(t *testing.T) {
		path := serveCloudflareAPI(t, `{"success":true,"errors":[],"messages":[],"result":{"allocated":100,"used":7}}`)

		quota, err := fetchCustomHostnamesQuota(context.Background(), "zone-id")
		require.NoError(t, err)

		assert.Equal(t, 100, quota.Allocated)
		assert.Equal(t, 7, quota.Used)
		assert.Equal(t, "/zones/zone-id/custom_hostnames/quota", *path)
	})

	t.Run("surfaces API errors", func(t *testing.T) {
		serveCloudflareAPI(t, `{"success":false,"errors":[{"message":"insufficient permissions"}],"result":null}`)

		_, err := fetchCustomHostnamesQuota(context.Background(), "zone-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient permissions")
	})
}

func TestFilterNonFreePlanZones(t *testing.T) {
	zones := []cfzones.Zone{
		//nolint:staticcheck // constructing the same deprecated-for-writes field the real API populates on reads
		{ID: "free-zone", Plan: cfzones.ZonePlan{ID: freePlanID}},
		//nolint:staticcheck // constructing the same deprecated-for-writes field the real API populates on reads
		{ID: "paid-zone", Plan: cfzones.ZonePlan{ID: "some-paid-plan-id"}},
	}

	got := filterNonFreePlanZones(zones)

	require.Len(t, got, 1, "free-plan zones should be filtered out, paid ones kept")
	assert.Equal(t, "paid-zone", got[0].ID)
}
