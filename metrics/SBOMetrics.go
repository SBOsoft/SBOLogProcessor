package metrics

import (
	"regexp"
	"slices"
	"strconv"
	"time"
)

/*
Keep the most recent 5 time windows
*/
const SBO_METRIC_VALUES_WINDOW_SIZE int = 5

var nonNumericRegex = regexp.MustCompile(`[^0-9]+`)

type SBOMetricMap map[int]map[string]*SBOMetric

var allMetrics map[string]SBOMetricMap = make(map[string]SBOMetricMap)

const SBO_METRIC_REQ_COUNT int = 1
const SBO_METRIC_BYTES_SENT int = 2
const SBO_METRIC_HTTP_STATUS int = 3
const SBO_METRIC_UNIQUE_IP int = 4
const SBO_METRIC_METHOD int = 5
const SBO_METRIC_REFERER int = 6

const SBO_METRIC_UA_FAMILY int = 11
const SBO_METRIC_OS_FAMILY int = 12
const SBO_METRIC_DEVICE_TYPE int = 13
const SBO_METRIC_IS_HUMAN int = 14

type SBOMetric struct {
	//for keeping track of keys in sorted order
	keys       []int64 `json:"-"`
	Values     map[int64]int64
	keyCounter int
}

func GetAllMetrics() map[string]SBOMetricMap {
	return allMetrics
}

func GetAllMetricsForFile(filePath string) SBOMetricMap {
	return allMetrics[filePath]
}

func NewSBOMetric(metricType int, key string) *SBOMetric {
	keys := make([]int64, SBO_METRIC_VALUES_WINDOW_SIZE)
	values := make(map[int64]int64, SBO_METRIC_VALUES_WINDOW_SIZE)
	return &SBOMetric{ /* metricType, key, */ keys, values, 0}
}

func AddMetric(filePath string, metricType int, keyValue string, eventTimestamp time.Time, valueToAdd int64) (int64, int64) {
	mapForFile, ok := allMetrics[filePath]
	if !ok {
		mapForFile = make(map[int]map[string]*SBOMetric)
		allMetrics[filePath] = mapForFile
	}
	keyMap, ok := mapForFile[metricType]
	if !ok {
		keyMap = make(map[string]*SBOMetric)
		mapForFile[metricType] = keyMap
	}
	sbom, ok := keyMap[keyValue]

	if !ok {
		sbom = NewSBOMetric(metricType, keyValue)
		keyMap[keyValue] = sbom
	}
	return sbom.AddValue(eventTimestamp, valueToAdd)
}

func (sbm *SBOMetric) IncrementKeyCounter() {
	sbm.keyCounter++
}

/*
return timeWindow and the metric value for that timeWindow when the timeWindow is removed out of scope
the caller may want to save the removed timeWindow and the metric value
*/
func (sbm *SBOMetric) AddValue(eventTimestamp time.Time, valueToAdd int64) (int64, int64) {
	formattedTs := eventTimestamp.Format(time.RFC3339)
	cleanTs := nonNumericRegex.ReplaceAllString(formattedTs[0:17], "")
	timeWindow, _ := strconv.ParseInt(cleanTs, 10, 64)
	var rv1 int64 = 0
	var rv2 int64 = 0
	//	slog.Warn("timeWindow for timestamp", "timestamp", eventTimestamp, "timeWindow", timeWindow, "error", err)
	if sbm.Values[timeWindow] < 1 {
		sbm.keys[0] = timeWindow
		slices.Sort(sbm.keys)
		//after this sort, [0] will always be the smallest key value
		if sbm.keyCounter >= SBO_METRIC_VALUES_WINDOW_SIZE {
			if sbm.keys[0] == timeWindow {
				//don't add as the new timeWindow is less than existing items
				return 0, 0
			} else {
				//now remove the smallest item which is at keys[0]
				rv2 = sbm.Values[sbm.keys[0]]
				delete(sbm.Values, sbm.keys[0])
				rv1 = sbm.keys[0]
			}
		}
		sbm.Values[timeWindow] = valueToAdd
		sbm.IncrementKeyCounter()
	} else {
		sbm.Values[timeWindow] = sbm.Values[timeWindow] + valueToAdd
	}
	return rv1, rv2
}
