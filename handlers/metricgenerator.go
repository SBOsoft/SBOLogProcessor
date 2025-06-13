package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"

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
}

func NewMetricGeneratorHandler(filePath string) *MetricGeneratorHandler {
	lastN := make([]*logparsers.SBOHttpRequestLog, METRIC_GENERATOR_LAST_N_WINDOW_SIZE)
	var rv = MetricGeneratorHandler{
		filePath:      filePath,
		lastNEntries:  lastN,
		lastNPosition: 0}

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

func PrintMetrics(filePath string) {
	jsonBytes, _ := json.MarshalIndent(metrics.GetAllMetricsForFile(filePath), "", "    ")
	str := string(jsonBytes)
	fmt.Print(str)
}

// TODO decide how we will save generated metrics
func (handler *MetricGeneratorHandler) HandleEntry(parsedLogEntry *logparsers.SBOHttpRequestLog) (bool, error) {
	handler.handledEntryCounter++
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_REQ_COUNT, "", 1)
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_BYTES_SENT, "", int64(parsedLogEntry.BytesSent))
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_HTTP_STATUS, parsedLogEntry.Status, 1)

	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_UNIQUE_IP, parsedLogEntry.ClientIP, 1)

	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_METHOD, parsedLogEntry.Method, 1)

	if len(parsedLogEntry.Referer) > 0 {
		handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_REFERER, parsedLogEntry.Referer, 1)
	}
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_UA_FAMILY, strconv.Itoa(parsedLogEntry.UserAgent.Family), 1)
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_OS_FAMILY, strconv.Itoa(parsedLogEntry.UserAgent.OS), 1)
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_DEVICE_TYPE, strconv.Itoa(parsedLogEntry.UserAgent.DeviceType), 1)
	handler.handleSingleMetric(parsedLogEntry, metrics.SBO_METRIC_IS_HUMAN, strconv.Itoa(parsedLogEntry.UserAgent.Human), 1)

	if handler.handledEntryCounter%50 == 0 {
		metrics.CleanUpAllProcessKeyedValueTimeWindowTracking(handler.filePath, metrics.SBO_METRIC_UNIQUE_IP, handler.dataToBeSavedChannel)
	}
	return true, nil
}

func (handler *MetricGeneratorHandler) handleSingleMetric(parsedLogEntry *logparsers.SBOHttpRequestLog, metricType int, keyValue string, valueToAdd int64) {
	dataToBeSaved := metrics.AddMetric(handler.filePath, metricType, keyValue, parsedLogEntry.Timestamp, valueToAdd)
	if dataToBeSaved != nil {
		fmt.Printf("Data to save: %v", dataToBeSaved)
		handler.dataToBeSavedChannel <- dataToBeSaved
	}
}

func (handler *MetricGeneratorHandler) End() bool {
	PrintMetrics(handler.filePath)
	return true
}
