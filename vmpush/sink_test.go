package vmpush

import (
	"testing"

	"github.com/lablabs/cloudflare-exporter/converge"
	"github.com/stretchr/testify/assert"
)

func TestKeyStringSimple(t *testing.T) {
	k := converge.NewKey("cloudflare_zone_requests_total", "zone", "example.com")
	assert.Equal(t, "cloudflare_zone_requests_total", k.Name)
	assert.Equal(t, `cloudflare_zone_requests_total{zone="example.com"}`, k.String())
}

func TestKeyStringMultipleLabels(t *testing.T) {
	k := converge.NewKey("cloudflare_zone_requests_country", "zone", "example.com", "country", "US")
	assert.Equal(t, "cloudflare_zone_requests_country", k.Name)
	assert.Equal(t, []converge.Label{
		{Name: "zone", Value: "example.com"},
		{Name: "country", Value: "US"},
	}, k.Labels)
}

func TestKeyStringNoLabels(t *testing.T) {
	k := converge.NewKey("cloudflare_zone_requests_total")
	assert.Equal(t, "cloudflare_zone_requests_total", k.String())
	assert.Nil(t, k.Labels)
}
