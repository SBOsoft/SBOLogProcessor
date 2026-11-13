/*
Copyright (C) 2025 SBOSOFT, Serkan Özkan

This file is part of, SBOLogProcessor, https://github.com/SBOsoft/SBOLogProcessor/

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/SBOsoft/SBOLogProcessor/logparsers"
	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

const (
	METRIC_GENERATOR_HANDLER_NAME       string = "METRICS"
	METRIC_GENERATOR_LAST_N_WINDOW_SIZE        = 50
	//minimum interval between log messages about log entries for closed time windows
	LATE_ENTRIES_REPORT_INTERVAL time.Duration = 5 * time.Minute
)

var nonNumericRegex = regexp.MustCompile(`[^0-9]+`)

type MetricGeneratorHandler struct {
	filePath             string
	lastNEntries         []*logparsers.SBOHttpRequestLog
	lastNPosition        int
	handledEntryCounter  int
	dataToBeSavedChannel metrics.DataToBeSavedChannel
	metricsManager       *metrics.SBOMetricsManager
	//log entries for already closed time windows since the last report, see reportLateEntries
	lateEntryCount     int
	rejectedEntryCount int
	lastLateEntryCheck time.Time
}

func NewMetricGeneratorHandler(filePath string, metricsManager *metrics.SBOMetricsManager) *MetricGeneratorHandler {
	lastN := make([]*logparsers.SBOHttpRequestLog, METRIC_GENERATOR_LAST_N_WINDOW_SIZE)
	var rv = MetricGeneratorHandler{
		filePath:           filePath,
		lastNEntries:       lastN,
		lastNPosition:      0,
		metricsManager:     metricsManager,
		lastLateEntryCheck: time.Now()}

	return &rv
}

func (handler *MetricGeneratorHandler) Name() string {
	return METRIC_GENERATOR_HANDLER_NAME
}

func (handler *MetricGeneratorHandler) Begin(dataToSaveChan metrics.DataToBeSavedChannel) error {
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

func (handler *MetricGeneratorHandler) HandleEntry(parsedLogEntry *logparsers.SBOHttpRequestLog) (bool, error) {
	handler.handledEntryCounter++
	//a newer timestamp may close older time windows, their values must be saved
	timeWindow, status, closedData := handler.metricsManager.OpenTimeWindow(handler.filePath, parsedLogEntry.Timestamp)
	handler.sendDataToBeSaved(closedData)
	switch status {
	case metrics.TIME_WINDOW_REJECTED:
		//metrics for this time window were already saved and would be replaced, see ReplaceExistingMetrics and MetricsWindowSize config options
		handler.rejectedEntryCount++
		handler.reportLateEntries(false)
		return false, nil
	case metrics.TIME_WINDOW_REOPENED:
		//metrics for this time window were already saved, values for this entry will be added to the saved values
		handler.lateEntryCount++
		handler.reportLateEntries(false)
	}

	handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_REQ_COUNT, "", 1)
	handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_BYTES_SENT, "", int64(parsedLogEntry.BytesSent))
	handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_HTTP_STATUS, parsedLogEntry.Status, 1)

	//TODO consider adding IPs or not. adding client IPs will create a metric entry for each IP address and would lead to excessive data
	/*
		handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_CLIENT_IP, parsedLogEntry.ClientIP, 1)
	*/

	handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_METHOD, parsedLogEntry.Method, 1)

	if len(parsedLogEntry.Referer) > 0 {
		handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_REFERER, parsedLogEntry.Referer, 1)
	}

	//add metrics for paths that return 2xx only. Ignoring others to save space, e.g scanners sending hundreds of paths
	if len(parsedLogEntry.Status) > 0 && strings.HasPrefix(parsedLogEntry.Status, "2") {
		//add metrics for the first 3 levels, e.g /a/b/c/d/f/x.html will generate 1 for /a 1 for /a/b and 1 for /a/b/c
		// we don't add the full path as they may be too long and too many
		handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_PATH, parsedLogEntry.Path1, 1)
		if len(parsedLogEntry.Path2) > 0 {
			handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_PATH, parsedLogEntry.Path2, 1)
		}
		if len(parsedLogEntry.Path3) > 0 {
			handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_PATH, parsedLogEntry.Path3, 1)
		}
	}

	handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_UA_FAMILY, parsedLogEntry.UserAgent.Family, 1)
	handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_OS_FAMILY, parsedLogEntry.UserAgent.OS, 1)
	handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_DEVICE_TYPE, parsedLogEntry.UserAgent.DeviceType, 1)
	handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_IS_HUMAN, parsedLogEntry.UserAgent.Human, 1)
	handler.handleSingleMetric(timeWindow, metrics.SBO_METRIC_REQUEST_INTENT, parsedLogEntry.UserAgent.Intent, 1)

	return true, nil
}

func (handler *MetricGeneratorHandler) handleSingleMetric(timeWindow int64, metricType int, keyValue string, valueToAdd int64) {
	handler.metricsManager.AddMetric(handler.filePath, metricType, keyValue, timeWindow, valueToAdd)
}

// sends the data as a single batch
func (handler *MetricGeneratorHandler) sendDataToBeSaved(data []*metrics.SBOMetricWindowDataToBeSaved) {
	if len(data) < 1 {
		return
	}
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		for _, dataToBeSaved := range data {
			slog.Debug("Data to be saved", "data", dataToBeSaved)
		}
	}
	handler.dataToBeSavedChannel <- data
}

/*
Called periodically, see MetricsFlushIntervalSeconds config option. Saves values that changed since the last flush,
so that metrics for the current time windows are available without waiting for the time windows to be closed
*/
func (handler *MetricGeneratorHandler) Flush() {
	handler.sendDataToBeSaved(handler.metricsManager.CollectDataToBeSaved(handler.filePath))
	handler.reportLateEntries(false)
}

// log entries for closed time windows are logged at most once every LATE_ENTRIES_REPORT_INTERVAL, unless force is true
func (handler *MetricGeneratorHandler) reportLateEntries(force bool) {
	if !force && time.Since(handler.lastLateEntryCheck) < LATE_ENTRIES_REPORT_INTERVAL {
		return
	}
	if handler.lateEntryCount > 0 || handler.rejectedEntryCount > 0 {
		slog.Info("Received log entries for time windows that were already closed and saved",
			"filePath", handler.filePath,
			"addedToSavedMetrics", handler.lateEntryCount,
			"ignoredForMetrics", handler.rejectedEntryCount,
			"since", handler.lastLateEntryCheck.Format(time.RFC3339))
	}
	handler.lateEntryCount = 0
	handler.rejectedEntryCount = 0
	handler.lastLateEntryCheck = time.Now()
}

func (handler *MetricGeneratorHandler) End() bool {
	handler.PrintMetrics(handler.filePath)
	//save values for all time windows that are still open
	handler.sendDataToBeSaved(handler.metricsManager.FlushAll(handler.filePath))
	handler.reportLateEntries(true)
	return true
}
