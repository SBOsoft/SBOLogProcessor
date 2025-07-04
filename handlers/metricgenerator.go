package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/SBOsoft/SBOLogProcessor/logparsers"
	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

const (
	METRIC_GENERATOR_HANDLER_NAME       string = "METRICS"
	METRIC_GENERATOR_LAST_N_WINDOW_SIZE        = 50
)

type MetricGeneratorHandler struct {
	filePath             string
	lastNEntries         []*logparsers.SBOHttpRequestLog
	lastNPosition        int
	handledEntryCounter  int
	dataToBeSavedChannel chan *metrics.SBOMetricWindowDataToBeSaved
	metricsManager       *metrics.SBOMetricsManager
}

func NewMetricGeneratorHandler(filePath string, metricsManager *metrics.SBOMetricsManager) *MetricGeneratorHandler {
	lastN := make([]*logparsers.SBOHttpRequestLog, METRIC_GENERATOR_LAST_N_WINDOW_SIZE)
	var rv = MetricGeneratorHandler{
		filePath:       filePath,
		lastNEntries:   lastN,
		lastNPosition:  0,
		metricsManager: metricsManager}

	return &rv
}

func (handler *MetricGeneratorHandler) Name() string {
	return METRIC_GENERATOR_HANDLER_NAME
}

func (handler *MetricGeneratorHandler) Begin(dataToSaveChan chan *metrics.SBOMetricWindowDataToBeSaved) error {
	handler.dataToBeSavedChannel = dataToSaveChan
	return nil
}

// TODO implement lastN window processing, e.g to check if we received invalid requests from a client repeatedly -> malicious
func (handler *MetricGeneratorHandler) addToLastN(parsedLogEntry *logparsers.SBOHttpRequestLog) {
	handler.lastNEntries[handler.lastNPosition] = parsedLogEntry
	handler.lastNPosition++
}

func (handler *MetricGeneratorHandler) PrintMetrics(filePath string) {
	jsonBytes, _ := json.MarshalIndent(handler.metricsManager.GetAllMetricsForFile(filePath), "", "    ")
	str := string(jsonBytes)
	fmt.Print(str)
}

// TODO decide how we will save generated metrics
func (handler *MetricGeneratorHandler) HandleEntry(parsedLogEntry *logparsers.SBOHttpRequestLog) (bool, error) {
	handler.handledEntryCounter++
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_REQ_COUNT, "", 1)
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_BYTES_SENT, "", int64(parsedLogEntry.BytesSent))
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_HTTP_STATUS, parsedLogEntry.Status, 1)

	//TODO consider adding IPs or not. adding client IPs will create a metric entry for each IP address and would lead to excessive data
	/*
		handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_CLIENT_IP, parsedLogEntry.ClientIP, 1)
		if handler.handledEntryCounter%50 == 0 {
			handler.metricsManager.CleanUpAllProcessKeyedValueTimeWindowTracking(handler.filePath, metrics.SBO_METRIC_CLIENT_IP, handler.dataToBeSavedChannel)
		}
	*/

	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_METHOD, parsedLogEntry.Method, 1)

	if len(parsedLogEntry.Referer) > 0 {
		handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_REFERER, parsedLogEntry.Referer, 1)
	}

	//add metrics for paths that return 2xx only. Ignoring others to save space, e.g scanners sending hundreds of paths
	if len(parsedLogEntry.Status) > 0 && strings.HasPrefix(parsedLogEntry.Status, "2") {
		//add metrics for the first 3 levels, e.g /a/b/c/d/f/x.html will generate 1 for /a 1 for /a/b and 1 for /a/b/c
		// we don't add the full path as they may be too long and too many
		handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_PATH, parsedLogEntry.Path1, 1)
		if len(parsedLogEntry.Path2) > 0 {
			handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_PATH, parsedLogEntry.Path2, 1)
		}
		if len(parsedLogEntry.Path3) > 0 {
			handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_PATH, parsedLogEntry.Path3, 1)
		}
	}

	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_UA_FAMILY, parsedLogEntry.UserAgent.Family, 1)
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_OS_FAMILY, parsedLogEntry.UserAgent.OS, 1)
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_DEVICE_TYPE, parsedLogEntry.UserAgent.DeviceType, 1)
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_IS_HUMAN, parsedLogEntry.UserAgent.Human, 1)
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_REQUEST_INTENT, parsedLogEntry.UserAgent.Intent, 1)

	return true, nil
}

func (handler *MetricGeneratorHandler) handleSingleMetric(parsedLogEntry *logparsers.SBOHttpRequestLog, metricType int, keyValue string, valueToAdd int64) {
	dataToBeSaved := handler.metricsManager.AddMetric(handler.filePath, metricType, keyValue, parsedLogEntry.Timestamp, valueToAdd)
	if dataToBeSaved != nil {
		slog.Debug("Data to be saved", "data", dataToBeSaved)
		handler.dataToBeSavedChannel <- dataToBeSaved
	}
}

func (handler *MetricGeneratorHandler) End() bool {
	remainingMetrics := handler.metricsManager.GetAllMetricsForFile(handler.filePath)
	for metricType, metricData := range remainingMetrics {
		for keyValue, values := range metricData {
			for timeWindow, metricValue := range values.Values {
				theData := metrics.NewSBOMetricWindowDataToBeSaved(handler.filePath, metricType, keyValue, timeWindow, metricValue)
				handler.dataToBeSavedChannel <- theData
			}
		}
	}
	handler.PrintMetrics(handler.filePath)
	return true
}
