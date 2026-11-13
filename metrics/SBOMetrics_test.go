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
	"fmt"
	"testing"
	"time"
)

const testFile = "unittest"

var testLocation = time.FixedZone("+0300", 3*60*60)

// 2026-11-13 hh:mm +0300
func ts(hour int, minute int) time.Time {
	return time.Date(2026, 11, 13, hour, minute, 0, 0, testLocation)
}

func tw(timestamp time.Time, sizeMinutes int) int64 {
	rv, _ := CalculateTimeWindow(timestamp, sizeMinutes)
	return rv
}

func newTestManager(windowSize int, replace bool) *SBOMetricsManager {
	return NewSBOMetricsManager(SBOMetricsManagerOptions{MetricsWindowSize: windowSize, TimeWindowSizeMinutes: 10, ReplaceExistingMetrics: replace})
}

// collects saved values. additive: values are summed, replace: the last value wins. Also counts rows per metric
type savedValues struct {
	replace bool
	values  map[string]int64
	rows    map[string]int
}

func newSavedValues(replace bool) *savedValues {
	return &savedValues{replace: replace, values: make(map[string]int64), rows: make(map[string]int)}
}

func (s *savedValues) save(data []*SBOMetricWindowDataToBeSaved) {
	for _, d := range data {
		k := savedKey(d.MetricType, d.KeyValue, d.TimeWindow)
		s.rows[k]++
		if s.replace {
			s.values[k] = d.MetricValue
		} else {
			s.values[k] += d.MetricValue
		}
	}
}

func savedKey(metricType int, key string, tw int64) string {
	return fmt.Sprintf("%d|%s|%d", metricType, key, tw)
}

// adds the value as a log entry would. Returns the status of the time window
func addEntry(m *SBOMetricsManager, saved *savedValues, metricType int, key string, timestamp time.Time, value int64) TimeWindowStatus {
	timeWindow, status, closed := m.OpenTimeWindow(testFile, timestamp)
	saved.save(closed)
	if status != TIME_WINDOW_REJECTED {
		m.AddMetric(testFile, metricType, key, timeWindow, value)
	}
	return status
}

func TestCalculateTimeWindow(t *testing.T) {
	//10:47:33 +0300 is 07:47:33 UTC, time windows are in UTC
	timestamp := time.Date(2026, 11, 13, 10, 47, 33, 0, testLocation)
	tests := []struct {
		size        int
		expectedTw  int64
		expectedEnd time.Time
	}{
		{1, 202611130747, ts(10, 48)},
		{5, 202611130745, ts(10, 50)},
		{10, 202611130740, ts(10, 50)},
		{15, 202611130745, ts(11, 0)},
		{30, 202611130730, ts(11, 0)},
		{60, 202611130700, ts(11, 0)},
		//unsupported, default 10
		{20, 202611130740, ts(10, 50)},
		{0, 202611130740, ts(10, 50)},
	}
	for _, test := range tests {
		timeWindow, end := CalculateTimeWindow(timestamp, test.size)
		if timeWindow != test.expectedTw || !end.Equal(test.expectedEnd) {
			t.Errorf("size=%d expected %d %v got %d %v", test.size, test.expectedTw, test.expectedEnd, timeWindow, end)
		}
	}
}

// the same moment logged in different time zones must be in the same (UTC) time window
func TestCalculateTimeWindowTimeZones(t *testing.T) {
	utc := time.Date(2026, 11, 13, 5, 17, 0, 0, time.UTC)
	zones := []*time.Location{time.UTC, testLocation, time.FixedZone("-0500", -5*60*60), time.FixedZone("+0530", 5*60*60+30*60)}
	for _, size := range []int{1, 5, 10, 15, 30, 60} {
		expectedTw, expectedEnd := CalculateTimeWindow(utc, size)
		for _, zone := range zones {
			timeWindow, end := CalculateTimeWindow(utc.In(zone), size)
			if timeWindow != expectedTw || !end.Equal(expectedEnd) || end.Location() != time.UTC {
				t.Errorf("size=%d zone=%v expected %d %v got %d %v", size, zone, expectedTw, expectedEnd, timeWindow, end)
			}
		}
	}
	if tw, _ := CalculateTimeWindow(utc.In(time.FixedZone("+0530", 5*60*60+30*60)), 60); tw != 202611130500 {
		t.Errorf("expected the 05:00 UTC hour, got %d", tw)
	}
	//metrics from log files in different time zones end up in the same time windows
	m := newTestManager(3, false)
	saved := newSavedValues(false)
	for _, zone := range zones {
		addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", utc.In(zone), 1)
	}
	saved.save(m.FlushAll(testFile))
	if saved.values[savedKey(SBO_METRIC_REQ_COUNT, "", 202611130510)] != int64(len(zones)) || len(saved.values) != 1 {
		t.Errorf("expected all entries in the 05:10 UTC time window, got %v", saved.values)
	}
}

// every value must be saved exactly once in additive mode and the last saved value must be the total in replace mode,
// regardless of when periodic flushes happen
func TestSBOMetricEveryValueSavedOnce(t *testing.T) {
	for _, replace := range []bool{false, true} {
		for windowSize := 2; windowSize <= 10; windowSize++ {
			m := newTestManager(windowSize, replace)
			saved := newSavedValues(replace)
			entryCount := 0
			for minute := 0; minute < 60; minute += 2 {
				for i := 0; i < 3; i++ {
					addEntry(m, saved, SBO_METRIC_REFERER, "google.com", ts(10, minute), 1)
					entryCount++
					if entryCount%4 == 0 {
						saved.save(m.CollectDataToBeSaved(testFile))
					}
				}
			}
			saved.save(m.FlushAll(testFile))
			for minute := 0; minute < 60; minute += 10 {
				//5 timestamps per 10 minutes, 3 entries each
				if v := saved.values[savedKey(SBO_METRIC_REFERER, "google.com", tw(ts(10, minute), 10))]; v != 15 {
					t.Errorf("replace=%v windowSize=%d minute=%d expected 15 got %d", replace, windowSize, minute, v)
				}
			}
			if len(saved.values) != 6 {
				t.Errorf("replace=%v windowSize=%d unexpected saved values %v", replace, windowSize, saved.values)
			}
		}
	}
}

func TestSBOMetricPeriodicFlush(t *testing.T) {
	for _, replace := range []bool{false, true} {
		m := newTestManager(3, replace)
		for i := 0; i < 5; i++ {
			addEntry(m, newSavedValues(replace), SBO_METRIC_REQ_COUNT, "", ts(10, 1), 1)
		}
		data := m.CollectDataToBeSaved(testFile)
		if len(data) != 1 || data[0].MetricValue != 5 {
			t.Errorf("replace=%v expected one value of 5, got %v", replace, data)
		}
		for i := 0; i < 3; i++ {
			addEntry(m, newSavedValues(replace), SBO_METRIC_REQ_COUNT, "", ts(10, 2), 1)
		}
		data = m.CollectDataToBeSaved(testFile)
		expected := int64(3)
		if replace {
			expected = 8
		}
		if len(data) != 1 || data[0].MetricValue != expected {
			t.Errorf("replace=%v expected one value of %d, got %v", replace, expected, data)
		}
		if data = m.CollectDataToBeSaved(testFile); len(data) != 0 {
			t.Errorf("replace=%v nothing changed, nothing should be returned, got %v", replace, data)
		}
		if data = m.FlushAll(testFile); len(data) != 0 {
			t.Errorf("replace=%v everything was saved, nothing should be returned, got %v", replace, data)
		}
	}
}

// normal traffic: one log entry per minute after from, until to (inclusive). Counted under SBO_METRIC_METHOD
// so that assertions on other metrics are not affected
func traffic(m *SBOMetricsManager, saved *savedValues, from time.Time, to time.Time) {
	for timestamp := from.Add(time.Minute); !timestamp.After(to); timestamp = timestamp.Add(time.Minute) {
		addEntry(m, saved, SBO_METRIC_METHOD, "GET", timestamp, 1)
	}
}

// a key seen in a single time window must be saved when the time window closes, even if the key is never seen again
func TestSBOMetricSparseKeySavedWhenWindowCloses(t *testing.T) {
	//allowed lateness 20 minutes, time window 10:00-10:10 closes at 10:30
	m := newTestManager(3, false)
	saved := newSavedValues(false)
	addEntry(m, saved, SBO_METRIC_REFERER, "rare.com", ts(10, 0), 1)
	traffic(m, saved, ts(10, 0), ts(10, 29))
	if len(saved.values) != 0 {
		t.Errorf("nothing should be saved before the time window closes, got %v", saved.values)
	}
	traffic(m, saved, ts(10, 29), ts(10, 30))
	if saved.values[savedKey(SBO_METRIC_REFERER, "rare.com", tw(ts(10, 0), 10))] != 1 {
		t.Errorf("rare.com should have been saved when its time window closed, got %v", saved.values)
	}
	if _, stillThere := m.GetAllMetricsForFile(testFile)[SBO_METRIC_REFERER]["rare.com"]; stillThere {
		t.Error("closed time window should have been removed")
	}
}

// allowed lateness is at least MIN_ALLOWED_LATENESS even for small time windows
func TestSBOMetricMinAllowedLateness(t *testing.T) {
	m := NewSBOMetricsManager(SBOMetricsManagerOptions{MetricsWindowSize: 2, TimeWindowSizeMinutes: 1})
	saved := newSavedValues(false)
	addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 0), 1)
	//time window 10:00-10:01 closes at 10:11
	traffic(m, saved, ts(10, 0), ts(10, 10))
	if status := addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 0), 1); status != TIME_WINDOW_ACCEPTED {
		t.Errorf("a 10 minute late entry must be accepted normally, got %v", status)
	}
	traffic(m, saved, ts(10, 10), ts(10, 11))
	k := savedKey(SBO_METRIC_REQ_COUNT, "", tw(ts(10, 0), 1))
	if saved.values[k] != 2 || saved.rows[k] != 1 {
		t.Errorf("expected a single row with value 2, got values %v rows %v", saved.values, saved.rows)
	}
}

func TestSBOMetricLateEntries(t *testing.T) {
	k := savedKey(SBO_METRIC_REQ_COUNT, "", tw(ts(10, 0), 10))
	for _, replace := range []bool{false, true} {
		//allowed lateness 10 minutes, time window 10:00-10:10 closes at 10:20
		m := newTestManager(2, replace)
		saved := newSavedValues(replace)
		addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 0), 1)
		traffic(m, saved, ts(10, 0), ts(10, 15))
		//out of order but its time window is open
		if status := addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 5), 1); status != TIME_WINDOW_ACCEPTED {
			t.Errorf("replace=%v expected accepted, got %v", replace, status)
		}
		traffic(m, saved, ts(10, 15), ts(10, 20)) //closes 10:00
		if saved.values[k] != 2 {
			t.Errorf("replace=%v expected 2 saved for the closed time window, got %v", replace, saved.values)
		}

		status := addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 7), 1)
		traffic(m, saved, ts(10, 20), ts(10, 21)) //closes the reopened time window, 1 minute (log time) after it was reopened
		if !replace && saved.rows[k] != 2 {
			t.Errorf("reopened time window must be closed 1 minute after it was reopened, rows %v", saved.rows)
		}
		saved.save(m.FlushAll(testFile))
		if replace {
			if status != TIME_WINDOW_REJECTED {
				t.Errorf("late entry must be rejected in replace mode, got %v", status)
			}
			if saved.values[k] != 2 {
				t.Errorf("rejected entry must not change the saved value, got %v", saved.values)
			}
		} else {
			if status != TIME_WINDOW_REOPENED {
				t.Errorf("late entry must reopen the time window in additive mode, got %v", status)
			}
			if saved.values[k] != 3 {
				t.Errorf("late entry must be added to the saved value, got %v", saved.values)
			}
		}
	}
}

// a burst of late entries must result in a single row, not one row per entry
func TestSBOMetricLateEntriesBurst(t *testing.T) {
	tw1000 := tw(ts(10, 0), 10)
	k := savedKey(SBO_METRIC_REQ_COUNT, "", tw1000)
	m := newTestManager(2, false)
	saved := newSavedValues(false)
	addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 0), 1)
	traffic(m, saved, ts(10, 0), ts(10, 20)) //closes 10:00
	for i := 0; i < 5; i++ {
		addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 5), 1)
		addEntry(m, saved, SBO_METRIC_METHOD, "GET", ts(10, 20).Add(time.Duration(i)*time.Second), 1)
	}
	if saved.rows[k] != 1 {
		t.Errorf("reopened time window must stay open until the next flush, rows: %v", saved.rows)
	}
	saved.save(m.CollectDataToBeSaved(testFile))
	if saved.rows[k] != 2 || saved.values[k] != 6 {
		t.Errorf("expected late entries in a single additional row, rows: %v values: %v", saved.rows, saved.values)
	}
	if _, open := m.files[testFile].openTimeWindows[tw1000]; open {
		t.Error("reopened time window must be closed by CollectDataToBeSaved")
	}
}

// a quiet site: every log entry is more than JUMP_THRESHOLD after the previous one. Nothing may be lost or closed too early
func TestSBOMetricQuietSite(t *testing.T) {
	for _, replace := range []bool{false, true} {
		m := newTestManager(3, replace)
		saved := newSavedValues(replace)
		expected := make(map[int64]int64)
		for i := 0; i < 30; i++ {
			timestamp := ts(10, 0).Add(time.Duration(i*7) * time.Minute)
			if status := addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", timestamp, 1); status == TIME_WINDOW_REJECTED {
				t.Errorf("replace=%v entry %v rejected", replace, timestamp)
			}
			expected[tw(timestamp, 10)]++
			if i%4 == 0 {
				saved.save(m.CollectDataToBeSaved(testFile))
			}
		}
		saved.save(m.FlushAll(testFile))
		for timeWindow, count := range expected {
			if v := saved.values[savedKey(SBO_METRIC_REQ_COUNT, "", timeWindow)]; v != count {
				t.Errorf("replace=%v tw=%d expected %d got %d", replace, timeWindow, count, v)
			}
		}
	}
}

// log entries with wrong timestamps in the future must not close current time windows, with small time windows too
func TestSBOMetricFutureTimestamps(t *testing.T) {
	for _, replace := range []bool{false, true} {
		m := NewSBOMetricsManager(SBOMetricsManagerOptions{MetricsWindowSize: 3, TimeWindowSizeMinutes: 1, ReplaceExistingMetrics: replace})
		saved := newSavedValues(replace)
		current := ts(10, 0).Add(30 * time.Second)
		addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", current, 1)
		for _, ahead := range []time.Duration{9 * time.Minute, 4 * time.Minute, 2 * 365 * 24 * time.Hour, 6 * time.Minute} {
			addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", current.Add(ahead), 1)
			if status := addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", current, 1); status != TIME_WINDOW_ACCEPTED {
				t.Errorf("replace=%v ahead=%v current time window must still be open, got %v", replace, ahead, status)
			}
		}
		if saved.rows[savedKey(SBO_METRIC_REQ_COUNT, "", tw(current, 1))] != 0 {
			t.Errorf("replace=%v current time window must not be closed, rows %v", replace, saved.rows)
		}
		saved.save(m.FlushAll(testFile))
		if saved.values[savedKey(SBO_METRIC_REQ_COUNT, "", tw(current, 1))] != 5 {
			t.Errorf("replace=%v expected 5 for the current time window, got %v", replace, saved.values)
		}
		//each entry with a wrong timestamp is still counted once, in its own time window
		for _, ahead := range []time.Duration{9 * time.Minute, 4 * time.Minute, 2 * 365 * 24 * time.Hour, 6 * time.Minute} {
			if saved.values[savedKey(SBO_METRIC_REQ_COUNT, "", tw(current.Add(ahead), 1))] != 1 {
				t.Errorf("replace=%v ahead=%v expected 1, got %v", replace, ahead, saved.values)
			}
		}
	}
}

// bulk processing of old logs: everything is based on log timestamps. A gap in traffic is confirmed after a few lines
// and must not cause time windows to be saved more than once
func TestSBOMetricBulkOldLogsWithGap(t *testing.T) {
	start := time.Date(2020, 3, 1, 0, 0, 0, 0, testLocation)
	m := newTestManager(3, false)
	saved := newSavedValues(false)
	expected := make(map[int64]int64)
	add := func(from time.Duration, to time.Duration) {
		for offset := from; offset < to; offset += 30 * time.Second {
			timestamp := start.Add(offset)
			if status := addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", timestamp, 1); status != TIME_WINDOW_ACCEPTED {
				t.Errorf("unexpected status %v for %v", status, timestamp)
			}
			expected[tw(timestamp, 10)]++
		}
	}
	add(0, 3*time.Hour)
	add(8*time.Hour, 9*time.Hour) //5 hour gap
	closedBeforeEnd := len(saved.rows)
	saved.save(m.FlushAll(testFile))
	if closedBeforeEnd < 18 {
		t.Errorf("time windows before the gap must be closed based on log time, only %d were", closedBeforeEnd)
	}
	for timeWindow, count := range expected {
		k := savedKey(SBO_METRIC_REQ_COUNT, "", timeWindow)
		if saved.values[k] != count || saved.rows[k] != 1 {
			t.Errorf("tw=%d expected %d in a single row, got %d in %d rows", timeWindow, count, saved.values[k], saved.rows[k])
		}
	}
}

// the number of open time windows is limited, outliers are closed first and the current time window is kept
func TestSBOMetricOpenTimeWindowLimit(t *testing.T) {
	for _, replace := range []bool{false, true} {
		m := newTestManager(3, replace) //allowed lateness 20 minutes, max 6 open time windows
		saved := newSavedValues(replace)
		current := ts(10, 1)
		for i := 0; i < 50; i++ {
			addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", current, 1)
			//a different wrong timestamp each time, never confirmed as a jump
			addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", current.Add(24*time.Hour+time.Duration(i)*10*time.Minute), 1)
			if open := len(m.files[testFile].openTimeWindows); open > m.maxOpenTimeWindows {
				t.Fatalf("replace=%v too many open time windows: %d", replace, open)
			}
		}
		if saved.rows[savedKey(SBO_METRIC_REQ_COUNT, "", tw(current, 10))] != 0 {
			t.Errorf("replace=%v current time window must not be closed", replace)
		}
		saved.save(m.FlushAll(testFile))
		if saved.values[savedKey(SBO_METRIC_REQ_COUNT, "", tw(current, 10))] != 50 {
			t.Errorf("replace=%v expected 50 for the current time window, got %v", replace, saved.values[savedKey(SBO_METRIC_REQ_COUNT, "", tw(current, 10))])
		}
	}
}

// in replace mode a late entry for a time window that was never saved can be saved, one that was saved must be rejected
func TestSBOMetricReplaceModeLateEntryForUnsavedTimeWindow(t *testing.T) {
	m := newTestManager(2, true) //allowed lateness 10 minutes
	saved := newSavedValues(true)
	addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 0), 1)
	traffic(m, saved, ts(10, 0), ts(10, 9))
	//no traffic in 10:10-10:20, confirmed as a jump after 3 entries
	traffic(m, saved, ts(10, 20).Add(-time.Minute), ts(10, 31)) //closes 10:00
	if saved.values[savedKey(SBO_METRIC_REQ_COUNT, "", tw(ts(10, 0), 10))] != 1 {
		t.Errorf("expected 10:00 to be saved, got %v", saved.values)
	}
	//10:10-10:20 expired at 10:30 but was never opened
	if status := addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 12), 1); status != TIME_WINDOW_ACCEPTED {
		t.Errorf("late entry for a time window that was never saved must be accepted, got %v", status)
	}
	traffic(m, saved, ts(10, 31), ts(10, 32)) //closes 10:10
	if saved.values[savedKey(SBO_METRIC_REQ_COUNT, "", tw(ts(10, 10), 10))] != 1 {
		t.Errorf("expected 1 saved for 10:10, got %v", saved.values)
	}
	if status := addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 13), 1); status != TIME_WINDOW_REJECTED {
		t.Errorf("late entry for a saved time window must be rejected, got %v", status)
	}
	if status := addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 1), 1); status != TIME_WINDOW_REJECTED {
		t.Errorf("late entry for a saved time window must be rejected, got %v", status)
	}
}

func TestSBOMetricMaxKeysPerWindow(t *testing.T) {
	m := NewSBOMetricsManager(SBOMetricsManagerOptions{MetricsWindowSize: 3, TimeWindowSizeMinutes: 10, MaxKeysPerWindow: 2})
	saved := newSavedValues(false)
	for _, key := range []string{"a", "b", "c", "a", "d"} {
		addEntry(m, saved, SBO_METRIC_REFERER, key, ts(10, 1), 1)
		addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", ts(10, 1), 1)
	}
	//new time window, new limit
	addEntry(m, saved, SBO_METRIC_REFERER, "c", ts(10, 11), 1)
	saved.save(m.FlushAll(testFile))
	tw1, tw2 := tw(ts(10, 1), 10), tw(ts(10, 11), 10)
	expected := map[string]int64{
		savedKey(SBO_METRIC_REFERER, "a", tw1):                  2,
		savedKey(SBO_METRIC_REFERER, "b", tw1):                  1,
		savedKey(SBO_METRIC_REFERER, SBO_METRIC_KEY_OTHER, tw1): 2,
		savedKey(SBO_METRIC_REQ_COUNT, "", tw1):                 5,
		savedKey(SBO_METRIC_REFERER, "c", tw2):                  1,
	}
	if fmt.Sprint(expected) != fmt.Sprint(saved.values) {
		t.Errorf("expected %v got %v", expected, saved.values)
	}
}

// late entries while many keys are in memory, closing a time window must not depend on keys of other time windows
func BenchmarkSBOMetricLateEntriesWithManyKeys(b *testing.B) {
	m := NewSBOMetricsManager(SBOMetricsManagerOptions{MetricsWindowSize: 3, TimeWindowSizeMinutes: 1})
	current := ts(11, 0)
	old := ts(10, 0)
	m.OpenTimeWindow(testFile, old)
	timeWindow, _, _ := m.OpenTimeWindow(testFile, current)
	for i := 0; i < 50000; i++ {
		m.AddMetric(testFile, SBO_METRIC_PATH, fmt.Sprintf("/p%d", i), timeWindow, 1)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		timestamp := current
		if i%2 == 0 {
			timestamp = old
		}
		t, status, _ := m.OpenTimeWindow(testFile, timestamp)
		if status != TIME_WINDOW_REJECTED {
			m.AddMetric(testFile, SBO_METRIC_REQ_COUNT, "", t, 1)
		}
		if i%1000 == 0 {
			m.CollectDataToBeSaved(testFile)
		}
	}
}
