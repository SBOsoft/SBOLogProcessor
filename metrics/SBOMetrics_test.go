package metrics

import (
	"log/slog"
	"testing"
	"time"
)

func TestSBOMetricTimeWindow(t *testing.T) {
	timest := time.Date(2025, 11, 17, 20, 34, 58, 651387237, time.UTC)
	metricManager := NewSBOMetricsManager()
	sbom := NewSBOMetric(SBO_METRIC_REQ_COUNT, "aaa", metricManager)
	sbom.addValue("unittest", timest, 100)

	slog.Warn("Values", "values", sbom.Values)

}
