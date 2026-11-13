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
	"time"
)

/*
SBOMetricsManager aggregates metric values per (file, time window, metricType, keyValue).

Everything is based on timestamps read from the logs, never on the current clock, so that old log files can be processed
in bulk exactly like live logs. The current clock is only used by callers to decide when to call CollectDataToBeSaved.

The watermark is the latest log timestamp seen. A time window is closed when the watermark passes the end of the time window
plus allowedLateness, then values not saved yet are returned to be saved and the time window is removed from memory.
Values are also returned periodically, see CollectDataToBeSaved, and when processing ends, see FlushAll.

When replaceExistingMetrics is false (the normal case) the returned values are increments since the last time the
value was returned, i.e every value added to the manager is returned exactly once and must be added to the saved values.
Log entries arriving after their time window was closed (late entries) open the time window again and their values
are returned as increments.

When replaceExistingMetrics is true the returned values are totals that must replace the saved values.
Late entries for time windows that were closed are rejected, their totals would replace the complete totals saved earlier.

Log timestamps more than JUMP_THRESHOLD ahead of the watermark move the watermark only when JUMP_CONFIRMATION_LINES
consecutive lines are that far ahead (e.g a gap in traffic), so that a few log lines with wrong timestamps can't close current
time windows. Time windows opened by unconfirmed jumps and late entries are "flagged" and closed early (see FLAGGED_TIME_WINDOW_GRACE),
so that they don't stay in memory. The number of open time windows is limited, see maxOpenTimeWindows.
*/
type SBOMetricsManager struct {
	files map[string]*fileMetrics

	timeWindowSizeMinutes  int
	allowedLateness        time.Duration
	maxOpenTimeWindows     int
	replaceExistingMetrics bool
	maxKeysPerWindow       int
}

type SBOMetricsManagerOptions struct {
	//time windows are kept open for max((MetricsWindowSize-1) time window durations, MIN_ALLOWED_LATENESS) after the end of the time window
	MetricsWindowSize      int
	TimeWindowSizeMinutes  int
	ReplaceExistingMetrics bool
	//when > 0, keys exceeding this number for a metric type and a time window are counted under SBO_METRIC_KEY_OTHER
	MaxKeysPerWindow int
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

// key used for values of keys exceeding MaxKeysPerWindow
const SBO_METRIC_KEY_OTHER string = "--other--"

const TIME_WINDOW_SIZE_MINUTES_DEFAULT int = 10

// time windows are kept open at least this long after they end (log time)
const MIN_ALLOWED_LATENESS time.Duration = 10 * time.Minute

// log timestamps more than this ahead of the watermark are treated as a possible jump, see JUMP_CONFIRMATION_LINES.
// Must be less than MIN_ALLOWED_LATENESS so that an unconfirmed jump can't close time windows that are still in use
const JUMP_THRESHOLD time.Duration = 5 * time.Minute

// number of consecutive log lines that must be more than JUMP_THRESHOLD ahead of the watermark to move it
const JUMP_CONFIRMATION_LINES int = 3

// flagged time windows (late entries, unconfirmed jumps) are closed when the watermark moves this much (log time)
// after they were flagged, or on the next CollectDataToBeSaved call, whichever is first
const FLAGGED_TIME_WINDOW_GRACE time.Duration = 1 * time.Minute

type TimeWindowStatus int

const (
	TIME_WINDOW_ACCEPTED TimeWindowStatus = iota
	//late entry, the time window was already closed or expired. The entry is accepted and its values will be added to saved values
	TIME_WINDOW_REOPENED
	//late entry, the time window was already closed and saved. The entry must be ignored for metrics. Only when replaceExistingMetrics is true
	TIME_WINDOW_REJECTED
)

// channel for passing data to be saved, each message is a batch
type DataToBeSavedChannel = chan []*SBOMetricWindowDataToBeSaved

/*
MetricValue is an increment to be added to the saved value or, when ReplaceExistingMetrics is true, the total value
that must replace the saved value
*/
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

type SBOMetricValue struct {
	//total value since the time window was opened
	Value int64
	//value added since the last time it was returned to be saved
	unsaved int64
	//changed since the last time it was returned to be saved
	dirty bool
}

// a value that changed since it was last returned to be saved
type dirtyMetricValue struct {
	metricType int
	keyValue   string
	value      *SBOMetricValue
}

type openTimeWindow struct {
	timeWindow int64
	end        time.Time
	//closed when the watermark reaches this, unless flagged
	closeAt time.Time
	//opened by a late entry (only when replaceExistingMetrics is false)
	reopened bool
	//opened by a log entry that is part of an unconfirmed jump
	outlier bool
	//when flagged (reopened or outlier, only when replaceExistingMetrics is false) closed when the watermark reaches this
	flaggedCloseAt time.Time
	//metric type => key => value
	values map[int]map[string]*SBOMetricValue
	//metric type => number of keys, used only when maxKeysPerWindow > 0
	keyCounts map[int]int
	//values that changed since they were last returned, in the order they changed
	dirty []dirtyMetricValue
}

type fileMetrics struct {
	openTimeWindows map[int64]*openTimeWindow
	//time windows closed recently => end of the time window. Used to reject late entries in replace mode
	closedTimeWindows map[int64]time.Time
	//latest log timestamp seen, zero until the first log entry
	watermark time.Time
	//consecutive log entries more than JUMP_THRESHOLD ahead of the watermark and the earliest of their timestamps
	pendingJumpCount    int
	pendingJumpEarliest time.Time
	//the earliest time (watermark) at which an open time window must be closed, zero if there are no open time windows
	nextCloseCheck time.Time
}

// returns true if the time window size is supported, i.e 1, 5, 10, 15, 30, 60 minutes
func IsSupportedTimeWindowSizeMinutes(minutes int) bool {
	switch minutes {
	case 1, 5, 10, 15, 30, 60:
		return true
	}
	return false
}

// returns TIME_WINDOW_SIZE_MINUTES_DEFAULT for unsupported values
func NormalizeTimeWindowSizeMinutes(minutes int) int {
	if IsSupportedTimeWindowSizeMinutes(minutes) {
		return minutes
	}
	return TIME_WINDOW_SIZE_MINUTES_DEFAULT
}

// returns the time window as a yyyyMMddHHmm number, e.g 202507061130, using the local time of the timestamp as it appears in the log
func timeWindowNumber(timestamp time.Time, sizeMinutes int) (int64, int) {
	year, month, day := timestamp.Date()
	hour, minute, _ := timestamp.Clock()
	minuteStart := minute - (minute % sizeMinutes)
	return int64(year)*100000000 + int64(month)*1000000 + int64(day)*10000 + int64(hour)*100 + int64(minuteStart), minuteStart
}

func timeWindowEnd(timestamp time.Time, minuteStart int, sizeMinutes int) time.Time {
	year, month, day := timestamp.Date()
	return time.Date(year, month, day, timestamp.Hour(), minuteStart, 0, 0, timestamp.Location()).Add(time.Duration(sizeMinutes) * time.Minute)
}

/*
Returns the time window for the timestamp as a yyyyMMddHHmm number, e.g 202507061130, and the end of the time window.
Time windows use the local time of the timestamp (i.e as it appears in the log line).
*/
func CalculateTimeWindow(timestamp time.Time, timeWindowSizeMinutes int) (int64, time.Time) {
	sizeMinutes := NormalizeTimeWindowSizeMinutes(timeWindowSizeMinutes)
	tw, minuteStart := timeWindowNumber(timestamp, sizeMinutes)
	return tw, timeWindowEnd(timestamp, minuteStart, sizeMinutes)
}

func NewSBOMetricsManager(options SBOMetricsManagerOptions) *SBOMetricsManager {
	windowSize := max(options.MetricsWindowSize, 1)
	sizeMinutes := NormalizeTimeWindowSizeMinutes(options.TimeWindowSizeMinutes)
	sizeDuration := time.Duration(sizeMinutes) * time.Minute
	allowedLateness := max(time.Duration(windowSize-1)*sizeDuration, MIN_ALLOWED_LATENESS)
	manager := SBOMetricsManager{
		files:                  make(map[string]*fileMetrics),
		timeWindowSizeMinutes:  sizeMinutes,
		allowedLateness:        allowedLateness,
		maxOpenTimeWindows:     int(allowedLateness/sizeDuration) + 4,
		replaceExistingMetrics: options.ReplaceExistingMetrics,
		maxKeysPerWindow:       options.MaxKeysPerWindow}

	return &manager
}

func (manager *SBOMetricsManager) fileMetricsFor(filePath string) *fileMetrics {
	fm := manager.files[filePath]
	if fm == nil {
		fm = &fileMetrics{
			openTimeWindows:   make(map[int64]*openTimeWindow),
			closedTimeWindows: make(map[int64]time.Time)}
		manager.files[filePath] = fm
	}
	return fm
}

/*
Returns current values of open time windows as metricType => keyValue => SBOMetric{timeWindow => value}, e.g for printing
*/
func (manager *SBOMetricsManager) GetAllMetricsForFile(filePath string) SBOMetricMap {
	rv := make(SBOMetricMap)
	fm := manager.files[filePath]
	if fm == nil {
		return rv
	}
	for timeWindow, tw := range fm.openTimeWindows {
		for metricType, keys := range tw.values {
			if rv[metricType] == nil {
				rv[metricType] = make(map[string]*SBOMetric)
			}
			for keyValue, value := range keys {
				if rv[metricType][keyValue] == nil {
					rv[metricType][keyValue] = &SBOMetric{Values: make(map[int64]int64)}
				}
				rv[metricType][keyValue].Values[timeWindow] = value.Value
			}
		}
	}
	return rv
}

type SBOMetricMap map[int]map[string]*SBOMetric

type SBOMetric struct {
	//time window => value
	Values map[int64]int64
}

/*
OpenTimeWindow must be called with the timestamp of a log entry before adding metrics for that entry.
Returns the time window for the timestamp, the status of the time window and values to be saved for
time windows that were closed. Metrics must not be added when the status is TIME_WINDOW_REJECTED.
*/
func (manager *SBOMetricsManager) OpenTimeWindow(filePath string, timestamp time.Time) (int64, TimeWindowStatus, []*SBOMetricWindowDataToBeSaved) {
	fm := manager.fileMetricsFor(filePath)
	timeWindow, minuteStart := timeWindowNumber(timestamp, manager.timeWindowSizeMinutes)
	isOutlier := manager.advanceWatermark(fm, timestamp)

	var closedData []*SBOMetricWindowDataToBeSaved
	if !fm.nextCloseCheck.IsZero() && !fm.watermark.Before(fm.nextCloseCheck) {
		closedData = manager.closeDueTimeWindows(filePath, fm, false)
	}

	if _, isOpen := fm.openTimeWindows[timeWindow]; isOpen {
		return timeWindow, TIME_WINDOW_ACCEPTED, closedData
	}

	end := timeWindowEnd(timestamp, minuteStart, manager.timeWindowSizeMinutes)
	status := TIME_WINDOW_ACCEPTED
	_, wasClosed := fm.closedTimeWindows[timeWindow]
	expired := !end.Add(manager.allowedLateness).After(fm.watermark)
	if wasClosed || expired {
		if manager.replaceExistingMetrics {
			//a time window that expired long ago may have been closed and saved, closedTimeWindows keeps recently closed ones only
			beyondHorizon := !end.Add(2 * manager.allowedLateness).After(fm.watermark)
			if wasClosed || beyondHorizon {
				return timeWindow, TIME_WINDOW_REJECTED, closedData
			}
			//never saved, its total can be saved. It will be closed in the next check
		} else if expired {
			status = TIME_WINDOW_REOPENED
		}
		//else: closed early (flagged or too many open time windows) but still current, open it again as a normal time window
	}

	tw := &openTimeWindow{
		timeWindow: timeWindow,
		end:        end,
		closeAt:    end.Add(manager.allowedLateness),
		values:     make(map[int]map[string]*SBOMetricValue)}
	if !manager.replaceExistingMetrics && (status == TIME_WINDOW_REOPENED || isOutlier) {
		tw.reopened = status == TIME_WINDOW_REOPENED
		tw.outlier = isOutlier
		tw.flaggedCloseAt = fm.watermark.Add(FLAGGED_TIME_WINDOW_GRACE)
	} else if isOutlier {
		//replace mode, close normally, but it is preferred when the open time window limit is exceeded
		tw.outlier = true
	}
	fm.openTimeWindows[timeWindow] = tw
	manager.updateNextCloseCheck(fm, tw)
	if len(fm.openTimeWindows) > manager.maxOpenTimeWindows {
		closedData = append(closedData, manager.closeExcessTimeWindows(filePath, fm, timeWindow)...)
	}
	return timeWindow, status, closedData
}

// returns true if the timestamp is part of an unconfirmed jump, i.e it did not move the watermark
func (manager *SBOMetricsManager) advanceWatermark(fm *fileMetrics, timestamp time.Time) bool {
	if fm.watermark.IsZero() {
		fm.watermark = timestamp
		return false
	}
	if !timestamp.After(fm.watermark.Add(JUMP_THRESHOLD)) {
		fm.pendingJumpCount = 0
		if timestamp.After(fm.watermark) {
			fm.watermark = timestamp
		}
		return false
	}
	if fm.pendingJumpCount == 0 || timestamp.Before(fm.pendingJumpEarliest) {
		fm.pendingJumpEarliest = timestamp
	}
	fm.pendingJumpCount++
	if fm.pendingJumpCount < JUMP_CONFIRMATION_LINES {
		return true
	}
	//confirmed, e.g a gap in traffic. Time windows opened by the jump are normal time windows now
	slog.Debug("Log timestamps jumped forward", "from", fm.watermark, "to", fm.pendingJumpEarliest)
	fm.watermark = fm.pendingJumpEarliest
	fm.pendingJumpCount = 0
	for _, tw := range fm.openTimeWindows {
		if tw.outlier {
			tw.outlier = false
			tw.flaggedCloseAt = time.Time{}
		}
	}
	fm.nextCloseCheck = time.Time{}
	for _, tw := range fm.openTimeWindows {
		manager.updateNextCloseCheck(fm, tw)
	}
	return false
}

func (manager *SBOMetricsManager) isFlagged(tw *openTimeWindow) bool {
	return !tw.flaggedCloseAt.IsZero()
}

// flagged time windows are closed at flaggedCloseAt: for late entries closeAt has already passed and for outliers it is too far
func (manager *SBOMetricsManager) closeTimeFor(tw *openTimeWindow) time.Time {
	if manager.isFlagged(tw) {
		return tw.flaggedCloseAt
	}
	return tw.closeAt
}

func (manager *SBOMetricsManager) updateNextCloseCheck(fm *fileMetrics, tw *openTimeWindow) {
	closeAt := manager.closeTimeFor(tw)
	if fm.nextCloseCheck.IsZero() || closeAt.Before(fm.nextCloseCheck) {
		fm.nextCloseCheck = closeAt
	}
}

/*
AddMetric adds valueToAdd to the metric value for the given time window.
The time window must have been returned by OpenTimeWindow, with a status other than TIME_WINDOW_REJECTED, for the current log entry.
*/
func (manager *SBOMetricsManager) AddMetric(filePath string, metricType int, keyValue string, timeWindow int64, valueToAdd int64) {
	fm := manager.fileMetricsFor(filePath)
	tw := fm.openTimeWindows[timeWindow]
	if tw == nil {
		slog.Debug("AddMetric called for a time window that is not open, OpenTimeWindow must be called first", "filePath", filePath, "timeWindow", timeWindow)
		return
	}
	keys := tw.values[metricType]
	if keys == nil {
		keys = make(map[string]*SBOMetricValue)
		tw.values[metricType] = keys
	}
	value := keys[keyValue]
	if value == nil {
		if manager.maxKeysPerWindow > 0 && len(keyValue) > 0 && keyValue != SBO_METRIC_KEY_OTHER {
			if tw.keyCounts == nil {
				tw.keyCounts = make(map[int]int)
			}
			if tw.keyCounts[metricType] >= manager.maxKeysPerWindow {
				keyValue = SBO_METRIC_KEY_OTHER
				value = keys[keyValue]
			} else {
				tw.keyCounts[metricType]++
			}
		}
		if value == nil {
			value = &SBOMetricValue{}
			keys[keyValue] = value
		}
	}
	value.Value += valueToAdd
	value.unsaved += valueToAdd
	if !value.dirty {
		value.dirty = true
		tw.dirty = append(tw.dirty, dirtyMetricValue{metricType: metricType, keyValue: keyValue, value: value})
	}
}

/*
Returns values that changed since they were last returned (for all open time windows) and values of time windows that were closed.
Flagged time windows (late entries, unconfirmed jumps) are closed. Call periodically to save metrics before time windows are closed.
*/
func (manager *SBOMetricsManager) CollectDataToBeSaved(filePath string) []*SBOMetricWindowDataToBeSaved {
	fm := manager.files[filePath]
	if fm == nil {
		return nil
	}
	rv := manager.closeDueTimeWindows(filePath, fm, true)
	for _, tw := range fm.openTimeWindows {
		rv = manager.appendDirtyValues(rv, filePath, tw)
	}
	return rv
}

/*
FlushAll closes all open time windows for the file and returns all values that were not returned before, e.g when processing ends.
*/
func (manager *SBOMetricsManager) FlushAll(filePath string) []*SBOMetricWindowDataToBeSaved {
	fm := manager.files[filePath]
	if fm == nil {
		return nil
	}
	var rv []*SBOMetricWindowDataToBeSaved
	for _, tw := range fm.openTimeWindows {
		rv = append(rv, manager.closeTimeWindow(filePath, fm, tw)...)
	}
	fm.nextCloseCheck = time.Time{}
	return rv
}

// closes time windows that are due according to the watermark, and all flagged time windows if includeFlagged is true
func (manager *SBOMetricsManager) closeDueTimeWindows(filePath string, fm *fileMetrics, includeFlagged bool) []*SBOMetricWindowDataToBeSaved {
	var rv []*SBOMetricWindowDataToBeSaved
	fm.nextCloseCheck = time.Time{}
	for _, tw := range fm.openTimeWindows {
		if !manager.closeTimeFor(tw).After(fm.watermark) || (includeFlagged && manager.isFlagged(tw)) {
			rv = append(rv, manager.closeTimeWindow(filePath, fm, tw)...)
		} else {
			manager.updateNextCloseCheck(fm, tw)
		}
	}
	//forget closed time windows that are too old to matter, see OpenTimeWindow
	for timeWindow, end := range fm.closedTimeWindows {
		if !end.Add(2 * manager.allowedLateness).After(fm.watermark) {
			delete(fm.closedTimeWindows, timeWindow)
		}
	}
	return rv
}

// called when there are too many open time windows: closes outliers first, then late entries, then the oldest. Never closes keepTimeWindow
func (manager *SBOMetricsManager) closeExcessTimeWindows(filePath string, fm *fileMetrics, keepTimeWindow int64) []*SBOMetricWindowDataToBeSaved {
	var rv []*SBOMetricWindowDataToBeSaved
	for len(fm.openTimeWindows) > manager.maxOpenTimeWindows {
		var victim *openTimeWindow
		victimRank := 3
		for _, tw := range fm.openTimeWindows {
			if tw.timeWindow == keepTimeWindow {
				continue
			}
			rank := 2
			if tw.outlier {
				rank = 0
			} else if tw.reopened {
				rank = 1
			}
			if victim == nil || rank < victimRank || (rank == victimRank && tw.timeWindow < victim.timeWindow) {
				victim = tw
				victimRank = rank
			}
		}
		if victim == nil {
			break
		}
		slog.Debug("Too many open time windows, closing one", "filePath", filePath, "timeWindow", victim.timeWindow, "rank", victimRank)
		rv = append(rv, manager.closeTimeWindow(filePath, fm, victim)...)
	}
	fm.nextCloseCheck = time.Time{}
	for _, tw := range fm.openTimeWindows {
		manager.updateNextCloseCheck(fm, tw)
	}
	return rv
}

// removes the time window and returns its values that were not returned before
func (manager *SBOMetricsManager) closeTimeWindow(filePath string, fm *fileMetrics, tw *openTimeWindow) []*SBOMetricWindowDataToBeSaved {
	rv := manager.appendDirtyValues(nil, filePath, tw)
	delete(fm.openTimeWindows, tw.timeWindow)
	fm.closedTimeWindows[tw.timeWindow] = tw.end
	return rv
}

// appends values that changed since they were last returned, in the order they changed, and marks them as returned
func (manager *SBOMetricsManager) appendDirtyValues(rv []*SBOMetricWindowDataToBeSaved, filePath string, tw *openTimeWindow) []*SBOMetricWindowDataToBeSaved {
	for _, d := range tw.dirty {
		valueToSave := d.value.unsaved
		if manager.replaceExistingMetrics {
			valueToSave = d.value.Value
		}
		d.value.unsaved = 0
		d.value.dirty = false
		rv = append(rv, NewSBOMetricWindowDataToBeSaved(filePath, d.metricType, d.keyValue, tw.timeWindow, valueToSave))
	}
	tw.dirty = tw.dirty[:0]
	return rv
}
