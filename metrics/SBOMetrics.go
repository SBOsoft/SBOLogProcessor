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

package metrics

import (
	"log/slog"
	"slices"
)

type SBOMetricMap map[int]map[string]*SBOMetric

/*
SBOMetricsManager aggregates metric values per (file, metricType, keyValue, timeWindow).

For each file it keeps up to windowSize most recent time windows "open". When a log entry with a newer
time window arrives and there are already windowSize open time windows, the oldest one is closed:
values of ALL metrics (all types, all keys) for the closed time window are removed and returned to the caller
to be saved. A time window is closed only once, so every (metricType, keyValue, timeWindow) value is returned
at most once during the lifetime of the manager. Entries arriving after their time window was closed are rejected.
*/
type SBOMetricsManager struct {
	allMetrics map[string]SBOMetricMap
	//per file: open time windows in ascending order, at most windowSize entries
	openTimeWindows map[string][]int64
	//per file: the most recent time window that was closed (and returned to be saved), 0 if none
	lastClosedTimeWindow map[string]int64
	windowSize           int
}

const SBO_METRIC_REQ_COUNT int = 1
const SBO_METRIC_BYTES_SENT int = 2
const SBO_METRIC_HTTP_STATUS int = 3
const SBO_METRIC_CLIENT_IP int = 4
const SBO_METRIC_METHOD int = 5
const SBO_METRIC_REFERER int = 6
const SBO_METRIC_PATH int = 7

const SBO_METRIC_UA_FAMILY int = 11
const SBO_METRIC_OS_FAMILY int = 12
const SBO_METRIC_DEVICE_TYPE int = 13
const SBO_METRIC_IS_HUMAN int = 14
const SBO_METRIC_REQUEST_INTENT int = 15

type SBOMetric struct {
	//time window => metric value
	Values map[int64]int64
}

type SBOMetricWindowDataToBeSaved struct {
	DomainName  string
	FilePath    string
	MetricType  int
	KeyValue    string
	TimeWindow  int64
	MetricValue int64
}

func NewSBOMetricWindowDataToBeSaved(filePath string, metricType int, keyValue string, timeWindow int64, metricValue int64) *SBOMetricWindowDataToBeSaved {
	//set DomainName later
	rv := SBOMetricWindowDataToBeSaved{
		FilePath:   filePath,
		MetricType: metricType, KeyValue: keyValue,
		TimeWindow: timeWindow, MetricValue: metricValue}
	return &rv
}

func NewSBOMetricsManager(timeWindowSize int) *SBOMetricsManager {
	if timeWindowSize < 1 {
		timeWindowSize = 1
	}
	manager := SBOMetricsManager{
		allMetrics:           make(map[string]SBOMetricMap),
		openTimeWindows:      make(map[string][]int64),
		lastClosedTimeWindow: make(map[string]int64),
		windowSize:           timeWindowSize}

	return &manager
}

func (manager *SBOMetricsManager) GetAllMetrics() map[string]SBOMetricMap {
	return manager.allMetrics
}

func (manager *SBOMetricsManager) GetAllMetricsForFile(filePath string) SBOMetricMap {
	return manager.allMetrics[filePath]
}

func NewSBOMetric() *SBOMetric {
	return &SBOMetric{Values: make(map[int64]int64)}
}

/*
OpenTimeWindow must be called with the time window of a log entry before adding metrics for that entry.

Returns accepted=false when the time window was already closed, e.g a log entry that arrived too late and is
older than all open time windows. Metrics for such entries must not be added, they would never be saved.

When opening a new time window causes the oldest open time window to be closed, the values of all metrics
for the closed time window are returned so that the caller can save them.
*/
func (manager *SBOMetricsManager) OpenTimeWindow(filePath string, timeWindow int64) (bool, []*SBOMetricWindowDataToBeSaved) {
	open := manager.openTimeWindows[filePath]
	idx, found := slices.BinarySearch(open, timeWindow)
	if found {
		return true, nil
	}
	if timeWindow <= manager.lastClosedTimeWindow[filePath] || (len(open) >= manager.windowSize && idx == 0) {
		//older than all open time windows and there is no room for it
		return false, nil
	}
	open = slices.Insert(open, idx, timeWindow)

	var closedData []*SBOMetricWindowDataToBeSaved
	for len(open) > manager.windowSize {
		closedData = append(closedData, manager.removeTimeWindow(filePath, open[0])...)
		manager.lastClosedTimeWindow[filePath] = open[0]
		open = open[1:]
	}
	manager.openTimeWindows[filePath] = open
	slog.Debug("OpenTimeWindow", "filePath", filePath, "openTimeWindows", open, "closedDataCount", len(closedData))
	return true, closedData
}

/*
AddMetric adds valueToAdd to the metric value for the given time window.
OpenTimeWindow must have been called, and must have returned true, for the time window before calling this method.
*/
func (manager *SBOMetricsManager) AddMetric(filePath string, metricType int, keyValue string, timeWindow int64, valueToAdd int64) {
	mapForFile, ok := manager.allMetrics[filePath]
	if !ok {
		mapForFile = make(SBOMetricMap)
		manager.allMetrics[filePath] = mapForFile
	}
	keyMap, ok := mapForFile[metricType]
	if !ok {
		keyMap = make(map[string]*SBOMetric)
		mapForFile[metricType] = keyMap
	}
	sbom, ok := keyMap[keyValue]
	if !ok {
		sbom = NewSBOMetric()
		keyMap[keyValue] = sbom
	}
	sbom.Values[timeWindow] += valueToAdd
}

/*
FlushAll closes all open time windows for the file and returns all remaining metric values, e.g when processing ends.
*/
func (manager *SBOMetricsManager) FlushAll(filePath string) []*SBOMetricWindowDataToBeSaved {
	var rv []*SBOMetricWindowDataToBeSaved
	open := manager.openTimeWindows[filePath]
	for _, tw := range open {
		rv = append(rv, manager.removeTimeWindow(filePath, tw)...)
	}
	if len(open) > 0 {
		manager.lastClosedTimeWindow[filePath] = open[len(open)-1]
	}
	manager.openTimeWindows[filePath] = nil
	return rv
}

// removes values for the time window from all metrics of the file and returns them. Keys left without values are removed
func (manager *SBOMetricsManager) removeTimeWindow(filePath string, timeWindow int64) []*SBOMetricWindowDataToBeSaved {
	var rv []*SBOMetricWindowDataToBeSaved
	for metricType, keyMap := range manager.allMetrics[filePath] {
		for keyValue, sbom := range keyMap {
			metricValue, ok := sbom.Values[timeWindow]
			if !ok {
				continue
			}
			rv = append(rv, NewSBOMetricWindowDataToBeSaved(filePath, metricType, keyValue, timeWindow, metricValue))
			delete(sbom.Values, timeWindow)
			if len(sbom.Values) == 0 {
				delete(keyMap, keyValue)
			}
		}
	}
	return rv
}
