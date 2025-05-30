package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/SBOsoft/SBOLogProcessor/logparsers"
	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

const (
	METRIC_GENERATOR_HANDLER_NAME string = "METRICS"
)

type MetricGeneratorHandler struct {
	filePath string
}

func NewMetricGeneratorHandler(filePath string) *MetricGeneratorHandler {
	var rv = MetricGeneratorHandler{
		filePath: filePath}

	return &rv
}

func (handler *MetricGeneratorHandler) Name() string {
	return METRIC_GENERATOR_HANDLER_NAME
}

func (handler *MetricGeneratorHandler) Begin() error {
	//nothing for now?
	return nil
}

func PrintMetrics(filePath string) {
	jsonBytes, _ := json.MarshalIndent(metrics.GetAllMetricsForFile(filePath), "", "    ")
	str := string(jsonBytes)
	fmt.Print(str)
}

func (handler *MetricGeneratorHandler) HandleEntry(parsedLogEntry *logparsers.SBOHttpRequestLog) (bool, error) {
	metrics.AddMetric(handler.filePath, metrics.SBO_METRIC_REQ_COUNT, "", parsedLogEntry.Timestamp, 1)
	metrics.AddMetric(handler.filePath, metrics.SBO_METRIC_BYTES_SENT, "", parsedLogEntry.Timestamp, int64(parsedLogEntry.BytesSent))
	metrics.AddMetric(handler.filePath, metrics.SBO_METRIC_HTTP_STATUS, parsedLogEntry.Status, parsedLogEntry.Timestamp, 1)
	metrics.AddMetric(handler.filePath, metrics.SBO_METRIC_UNIQUE_IP, parsedLogEntry.ClientIP, parsedLogEntry.Timestamp, 1)
	metrics.AddMetric(handler.filePath, metrics.SBO_METRIC_METHOD, parsedLogEntry.Method, parsedLogEntry.Timestamp, 1)
	if len(parsedLogEntry.Referer) > 0 {
		metrics.AddMetric(handler.filePath, metrics.SBO_METRIC_REFERER, parsedLogEntry.Referer, parsedLogEntry.Timestamp, 1)
	}

	metrics.AddMetric(handler.filePath, metrics.SBO_METRIC_UA_FAMILY, strconv.Itoa(parsedLogEntry.UserAgent.Family), parsedLogEntry.Timestamp, 1)
	metrics.AddMetric(handler.filePath, metrics.SBO_METRIC_OS_FAMILY, strconv.Itoa(parsedLogEntry.UserAgent.OS), parsedLogEntry.Timestamp, 1)
	metrics.AddMetric(handler.filePath, metrics.SBO_METRIC_DEVICE_TYPE, strconv.Itoa(parsedLogEntry.UserAgent.DeviceType), parsedLogEntry.Timestamp, 1)
	metrics.AddMetric(handler.filePath, metrics.SBO_METRIC_IS_HUMAN, strconv.Itoa(parsedLogEntry.UserAgent.Human), parsedLogEntry.Timestamp, 1)

	return true, nil
}

func (handler *MetricGeneratorHandler) End() bool {
	PrintMetrics(handler.filePath)
	return true
}
