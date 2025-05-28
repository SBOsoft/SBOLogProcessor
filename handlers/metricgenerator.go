package handlers

import (
	"fmt"

	"github.com/SBOsoft/SBOLogProcessor/logparsers"
	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

func PrintMetrics(filePath string) {
	fmt.Printf("%v", metrics.GetAllMetricsForFile(filePath))
}

func ProcessMetricsForRequestLogEntry(filePath string, parseResult *logparsers.SBOHttpRequestLog) {
	metrics.AddMetric(filePath, metrics.SBO_METRIC_REQ_COUNT, "", parseResult.Timestamp, 1)
	metrics.AddMetric(filePath, metrics.SBO_METRIC_BYTES_SENT, "", parseResult.Timestamp, int64(parseResult.BytesSent))
	metrics.AddMetric(filePath, metrics.SBO_METRIC_HTTP_STATUS, parseResult.Status, parseResult.Timestamp, 1)
	metrics.AddMetric(filePath, metrics.SBO_METRIC_UNIQUE_IP, parseResult.ClientIP, parseResult.Timestamp, 1)
	metrics.AddMetric(filePath, metrics.SBO_METRIC_METHOD, parseResult.Method, parseResult.Timestamp, 1)

}
