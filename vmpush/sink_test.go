package vmpush

import (
	"testing"

	"github.com/lablabs/cloudflare-exporter/converge"
	"github.com/lablabs/cloudflare-exporter/metricnames"
	"github.com/stretchr/testify/assert"
)

func TestKeyStringSimple(t *testing.T) {
	k := converge.NewKey(metricnames.ZoneRequestsTotal, "zone", "example.com")
	assert.Equal(t, metricnames.ZoneRequestsTotal, k.Name)
	assert.Equal(t, metricnames.ZoneRequestsTotal+`{zone="example.com"}`, k.String())
}

func TestKeyStringMultipleLabels(t *testing.T) {
	k := converge.NewKey(metricnames.ZoneRequestsCountry, "zone", "example.com", "country", "US")
	assert.Equal(t, metricnames.ZoneRequestsCountry, k.Name)
	assert.Equal(t, []converge.Label{
		{Name: "zone", Value: "example.com"},
		{Name: "country", Value: "US"},
	}, k.Labels)
}

func TestKeyStringNoLabels(t *testing.T) {
	k := converge.NewKey(metricnames.ZoneRequestsTotal)
	assert.Equal(t, metricnames.ZoneRequestsTotal, k.String())
	assert.Nil(t, k.Labels)
}
