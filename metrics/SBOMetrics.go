package metrics

import (
	"log/slog"
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
var timeWindowTrackingMap map[string][]int64 = make(map[string][]int64, SBO_METRIC_VALUES_WINDOW_SIZE+1)

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

func AddMetric(filePath string, metricType int, keyValue string, eventTimestamp time.Time, valueToAdd int64) *SBOMetricWindowDataToBeSaved {
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
	timeWindow, metricValue := sbom.addValue(filePath, eventTimestamp, valueToAdd)

	if timeWindow > 0 {
		return NewSBOMetricWindowDataToBeSaved(filePath, metricType, keyValue, timeWindow, metricValue)
	} else {
		return nil
	}
}

func (sbm *SBOMetric) IncrementKeyCounter() {
	sbm.keyCounter++
}

func CleanUpAllProcessKeyedValueTimeWindowTracking(filePath string, metricType int, dataToBeSavedChannel chan *SBOMetricWindowDataToBeSaved) {
	for k, _ := range allMetrics[filePath][metricType] {
		ProcessKeyedValueTimeWindowTracking(filePath, k, metricType, dataToBeSavedChannel)
	}
}

func ProcessKeyedValueTimeWindowTracking(filePath string, keyValue string, metricType int, dataToBeSavedChannel chan *SBOMetricWindowDataToBeSaved) {
	found := false
	for _, tw := range timeWindowTrackingMap[filePath] {
		tw64 := int64(tw)
		if allMetrics[filePath][metricType][keyValue].Values[tw64] > 0 {
			found = true
		} else {
			//remove timewindow entries and save if necessary
			dataToBeSavedChannel <- NewSBOMetricWindowDataToBeSaved(filePath, metricType, keyValue, tw64, allMetrics[filePath][metricType][keyValue].Values[tw64])
			delete(allMetrics[filePath][metricType][keyValue].Values, tw64)
			slog.Debug("Remove expired entry in processKeyedValueTimeWindowTracking", "keyValue", keyValue, "metricType", metricType, "timeWindow", tw64)
		}
	}

	//this key value does not have an entry for one of the current timewindow values
	//so move it out of scope
	if !found {
		//remove the keyed value
		delete(allMetrics[filePath][metricType], keyValue)
		slog.Debug("Remove key value with no children in processKeyedValueTimeWindowTracking", "keyValue", keyValue, "metricType", metricType)
	}
}

func doTimeWindowTracking(filePath string, timeWindow int64) {
	if timeWindowTrackingMap[filePath] == nil {
		timeWindowTrackingMap[filePath] = make([]int64, SBO_METRIC_VALUES_WINDOW_SIZE+1)
	}

	if slices.Contains(timeWindowTrackingMap[filePath], timeWindow) {
		//nothing to do, it's already in
		return
	}
	timeWindowTrackingMap[filePath] = append(timeWindowTrackingMap[filePath], timeWindow)
	if len(timeWindowTrackingMap[filePath]) >= SBO_METRIC_VALUES_WINDOW_SIZE {
		slices.Sort(timeWindowTrackingMap[filePath])

		//oldestTimewindow := timeWindowTrackingMap[filePath][0]
		timeWindowTrackingMap[filePath] = timeWindowTrackingMap[filePath][1:]
	}
	slog.Debug("doTimeWindowTracking", "timeWindowTrackingMap[filePath]", timeWindowTrackingMap[filePath])

}

/*
return timeWindow and the metric value for that timeWindow when the timeWindow is removed out of scope
the caller may want to save the removed timeWindow and the metric value
*/
func (sbm *SBOMetric) addValue(filePath string, eventTimestamp time.Time, valueToAdd int64) (int64, int64) {
	formattedTs := eventTimestamp.Format(time.RFC3339)
	cleanTs := nonNumericRegex.ReplaceAllString(formattedTs[0:17], "")
	timeWindow, _ := strconv.ParseInt(cleanTs, 10, 64)
	doTimeWindowTracking(filePath, timeWindow)
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
