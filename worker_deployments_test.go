package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	cf "github.com/cloudflare/cloudflare-go/v7"
	cfoption "github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetWorkerDeployments(t *testing.T) {
	responses := map[string]string{
		"/accounts/acc/workers/scripts":                       `{"success":true,"errors":[],"messages":[],"result":[{"id":"no-deploy"},{"id":"deployed"}]}`,
		"/accounts/acc/workers/scripts/no-deploy/deployments": `{"success":true,"errors":[],"messages":[],"result":{"deployments":[]}}`,
		"/accounts/acc/workers/scripts/deployed/deployments":  `{"success":true,"errors":[],"messages":[],"result":{"deployments":[{"id":"d1","created_on":"2026-01-01T00:00:00Z","source":"api","strategy":"percentage","versions":[{"percentage":100,"version_id":"v1"}]}]}}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := responses[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	original := cfclient
	t.Cleanup(func() { cfclient = original })
	cfclient = cf.NewClient(cfoption.WithAPIToken("test-token"), cfoption.WithBaseURL(srv.URL+"/"))

	versions, err := getWorkerDeployments(context.Background(), "acc")
	require.NoError(t, err)

	assert.Equal(t, []DeployedVersion{{ID: "deployed", VersionID: "v1", Percentage: 100}}, versions)
}

func TestGoSafe(t *testing.T) {
	var wg sync.WaitGroup
	ran := false

	goSafe(&wg, "boom", func() { panic("boom") })
	goSafe(&wg, "ok", func() { ran = true })
	wg.Wait()

	assert.True(t, ran)
	assert.Equal(t, 1.0, testutil.ToFloat64(exporterErrors.WithLabelValues("panic_boom")))
}
