package metrics

import (
	"regexp"
	"strconv"
	"time"
)

var nonNumericRegex = regexp.MustCompile(`[^0-9]+`)

type SBOMetricMap map[int]map[string]SBOMetric

var allMetrics map[string]SBOMetricMap = make(map[string]SBOMetricMap)

const SBO_METRIC_REQ_COUNT int = 1
const SBO_METRIC_BYTES_SENT int = 2
const SBO_METRIC_HTTP_STATUS int = 3
const SBO_METRIC_UNIQUE_IP int = 4
const SBO_METRIC_METHOD int = 5

type SBOMetric struct {
	//e.g path
	MetricType int
	//e.g path value like /index.php
	Key string
	//time window => value, e.g 202505261130 => 4
	Values map[int64]int64
}

func GetAllMetrics() map[string]SBOMetricMap {
	return allMetrics
}

func GetAllMetricsForFile(filePath string) SBOMetricMap {
	return allMetrics[filePath]
}

func NewSBOMetric(metricType int, key string) *SBOMetric {
	m := make(map[int64]int64)
	rv := &SBOMetric{metricType, key, m}
	return rv
}

func AddMetric(filePath string, metricType int, keyValue string, eventTimestamp time.Time, valueToAdd int64) {
	mapForFile, ok := allMetrics[filePath]
	if !ok {
		mapForFile = make(map[int]map[string]SBOMetric)
		allMetrics[filePath] = mapForFile
	}
	keyMap, ok := mapForFile[metricType]
	if !ok {
		keyMap = make(map[string]SBOMetric)
		mapForFile[metricType] = keyMap
	}
	sbom, ok := keyMap[keyValue]

	if !ok {
		sbom = *NewSBOMetric(metricType, keyValue)
		keyMap[keyValue] = sbom
	}
	sbom.AddValue(eventTimestamp, valueToAdd)
}

func (sbm *SBOMetric) AddValue(eventTimestamp time.Time, valueToAdd int64) {
	formattedTs := eventTimestamp.Format(time.RFC3339)
	cleanTs := nonNumericRegex.ReplaceAllString(formattedTs[0:17], "")
	timeWindow, _ := strconv.ParseInt(cleanTs, 10, 64)

	//	slog.Warn("timeWindow for timestamp", "timestamp", eventTimestamp, "timeWindow", timeWindow, "error", err)
	if sbm.Values[timeWindow] < 1 {
		sbm.Values[timeWindow] = valueToAdd
	} else {
		sbm.Values[timeWindow] = sbm.Values[timeWindow] + valueToAdd
	}

}
