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

type SBOMetricsManager struct {
	allMetrics            map[string]SBOMetricMap
	timeWindowTrackingMap map[string][]int64
	windowSize            int
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
	//for keeping track of keys in sorted order
	keys       []int64 `json:"-"`
	Values     map[int64]int64
	keyCounter int
	manager    *SBOMetricsManager `json:"-"`
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

	m := make(map[string]SBOMetricMap)
	t := make(map[string][]int64, timeWindowSize+1)

	manager := SBOMetricsManager{
		allMetrics:            m,
		timeWindowTrackingMap: t,
		windowSize:            timeWindowSize}

	return &manager
}

func (manager *SBOMetricsManager) GetAllMetrics() map[string]SBOMetricMap {
	return manager.allMetrics
}

func (manager *SBOMetricsManager) GetAllMetricsForFile(filePath string) SBOMetricMap {
	return manager.allMetrics[filePath]
}

func NewSBOMetric(metricType int, key string, manager *SBOMetricsManager) *SBOMetric {
	keys := make([]int64, manager.windowSize)
	values := make(map[int64]int64, manager.windowSize)
	return &SBOMetric{ /* metricType, key, */ keys, values, 0, manager}
}

func (manager *SBOMetricsManager) AddMetric(filePath string, metricType int, keyValue string, timeWindow int64, valueToAdd int64) *SBOMetricWindowDataToBeSaved {
	mapForFile, ok := manager.allMetrics[filePath]
	if !ok {
		mapForFile = make(map[int]map[string]*SBOMetric)
		manager.allMetrics[filePath] = mapForFile
	}
	keyMap, ok := mapForFile[metricType]
	if !ok {
		keyMap = make(map[string]*SBOMetric)
		mapForFile[metricType] = keyMap
	}
	sbom, ok := keyMap[keyValue]

	if !ok {
		sbom = NewSBOMetric(metricType, keyValue, manager)
		keyMap[keyValue] = sbom
	}
	//note this is a bit weird. addValue returns the timewindow and metric value that is moved out of scope when the new value is added
	// we have a fixed size window, when a new value is added oldest one is removed and returned by addValue
	timeWindowToBeSavedAsItMovedOutOfScope, metricValueToBeSaved := sbom.addValue(filePath, timeWindow, valueToAdd)

	if timeWindowToBeSavedAsItMovedOutOfScope > 0 {
		return NewSBOMetricWindowDataToBeSaved(filePath, metricType, keyValue, timeWindowToBeSavedAsItMovedOutOfScope, metricValueToBeSaved)
	} else {
		return nil
	}
}

func (sbm *SBOMetric) IncrementKeyCounter() {
	sbm.keyCounter++
}

func (manager *SBOMetricsManager) CleanUpAllProcessKeyedValueTimeWindowTracking(filePath string, metricType int, dataToBeSavedChannel chan *SBOMetricWindowDataToBeSaved) {
	for k, _ := range manager.allMetrics[filePath][metricType] {
		manager.ProcessKeyedValueTimeWindowTracking(filePath, k, metricType, dataToBeSavedChannel)
	}
}

func (manager *SBOMetricsManager) ProcessKeyedValueTimeWindowTracking(filePath string, keyValue string, metricType int, dataToBeSavedChannel chan *SBOMetricWindowDataToBeSaved) {
	found := false
	for _, tw := range manager.timeWindowTrackingMap[filePath] {
		tw64 := int64(tw)
		if manager.allMetrics[filePath][metricType][keyValue].Values[tw64] > 0 {
			found = true
			break
		}
	}

	//this key value does not have an entry for one of the current timewindow values
	//so move it out of scope
	if !found {
		//remove the keyed value
		delete(manager.allMetrics[filePath][metricType], keyValue)
		slog.Debug("Remove key value with no children in processKeyedValueTimeWindowTracking", "keyValue", keyValue, "metricType", metricType)
	}
}

func (manager *SBOMetricsManager) doTimeWindowTracking(filePath string, timeWindow int64) {
	if manager.timeWindowTrackingMap[filePath] == nil {
		manager.timeWindowTrackingMap[filePath] = make([]int64, manager.windowSize+1)
	}

	if slices.Contains(manager.timeWindowTrackingMap[filePath], timeWindow) {
		//nothing to do, it's already in
		return
	}
	manager.timeWindowTrackingMap[filePath] = append(manager.timeWindowTrackingMap[filePath], timeWindow)
	if len(manager.timeWindowTrackingMap[filePath]) >= manager.windowSize {
		slices.Sort(manager.timeWindowTrackingMap[filePath])

		//oldestTimewindow := timeWindowTrackingMap[filePath][0]
		manager.timeWindowTrackingMap[filePath] = manager.timeWindowTrackingMap[filePath][1:]
	}
	slog.Debug("doTimeWindowTracking", "timeWindowTrackingMap[filePath]", manager.timeWindowTrackingMap[filePath])

}

/*
return timeWindow and the metric value for that timeWindow when the timeWindow is removed out of scope
the caller may want to save the removed timeWindow and the metric value
*/
func (sbm *SBOMetric) addValue(filePath string, timeWindow int64, valueToAdd int64) (int64, int64) {
	sbm.manager.doTimeWindowTracking(filePath, timeWindow)
	var timeWindowToBeSaved int64 = 0
	var metricValue int64 = 0
	//	slog.Warn("timeWindow for timestamp", "timestamp", eventTimestamp, "timeWindow", timeWindow, "error", err)
	if sbm.Values[timeWindow] < 1 {
		sbm.keys[0] = timeWindow
		slices.Sort(sbm.keys)
		//after this sort, [0] will always be the smallest key value
		if sbm.keyCounter >= sbm.manager.windowSize {
			if sbm.keys[0] == timeWindow {
				//don't add or save as the new timeWindow is less than existing items. e.g we received an old entry unexpectedly
				//TODO report?
				return 0, 0
			} else {
				//now remove the smallest item which is at keys[0]
				metricValue = sbm.Values[sbm.keys[0]]
				delete(sbm.Values, sbm.keys[0])
				timeWindowToBeSaved = sbm.keys[0]
			}
		}
		sbm.Values[timeWindow] = valueToAdd
		sbm.IncrementKeyCounter()
	} else {
		sbm.Values[timeWindow] = sbm.Values[timeWindow] + valueToAdd
	}
	return timeWindowToBeSaved, metricValue
}
