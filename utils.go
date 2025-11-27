package main

import (
	"encoding/json"
	"time"

	"github.com/spf13/viper"
)

func GetTimeRange() (now time.Time, now1mAgo time.Time) {
	scrapeInterval := viper.GetInt("scrape_interval")
	if scrapeInterval == 0 {
		scrapeInterval = 60 // Default to 60 seconds if not set
	}

	now = time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()

	// Truncate to the scrape interval to ensure we query distinct time windows
	s := time.Duration(scrapeInterval) * time.Second
	now = now.Truncate(s)
	now1mAgo = now.Add(-s)

	return now, now1mAgo
}

func jsonStringToMap(fields string) (map[string]interface{}, error) {
	var extraFields map[string]interface{}
	err := json.Unmarshal([]byte(fields), &extraFields)
	return extraFields, err
}
