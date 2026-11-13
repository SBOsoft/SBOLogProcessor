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
)

const testFile = "unittest"

// adds the value as a log entry would, collecting closed data into saved. Returns false if the entry was rejected
func addEntry(m *SBOMetricsManager, saved map[string]int64, metricType int, key string, tw int64, value int64) bool {
	accepted, closed := m.OpenTimeWindow(testFile, tw)
	collect(saved, closed)
	if accepted {
		m.AddMetric(testFile, metricType, key, tw, value)
	}
	return accepted
}

func collect(saved map[string]int64, data []*SBOMetricWindowDataToBeSaved) {
	for _, d := range data {
		saved[savedKey(d.MetricType, d.KeyValue, d.TimeWindow)] += d.MetricValue
	}
}

func savedKey(metricType int, key string, tw int64) string {
	return fmt.Sprintf("%d|%s|%d", metricType, key, tw)
}

func TestSBOMetricTimeWindow(t *testing.T) {
	m := NewSBOMetricsManager(5)
	var tw int64 = 202511172030
	m.OpenTimeWindow(testFile, tw)
	m.AddMetric(testFile, SBO_METRIC_REQ_COUNT, "", tw, 100)

	if m.GetAllMetricsForFile(testFile)[SBO_METRIC_REQ_COUNT][""].Values[tw] != 100 {
		t.Error("Values does not contain expected entry", m.GetAllMetricsForFile(testFile))
	}
}

// every value must be saved exactly once: nothing lost, nothing duplicated
func TestSBOMetricEveryValueSavedOnce(t *testing.T) {
	windows := []int64{202611131000, 202611131010, 202611131020, 202611131030, 202611131040, 202611131050}
	for windowSize := 2; windowSize <= 10; windowSize++ {
		m := NewSBOMetricsManager(windowSize)
		saved := make(map[string]int64)
		for _, tw := range windows {
			for i := 0; i < 5; i++ {
				addEntry(m, saved, SBO_METRIC_REFERER, "google.com", tw, 1)
			}
		}
		collect(saved, m.FlushAll(testFile))
		var total int64
		for _, tw := range windows {
			v := saved[savedKey(SBO_METRIC_REFERER, "google.com", tw)]
			if v != 5 {
				t.Errorf("windowSize=%d tw=%d expected 5 got %d", windowSize, tw, v)
			}
			total += v
		}
		if total != 30 {
			t.Errorf("windowSize=%d expected total 30 got %d", windowSize, total)
		}
	}
}

// a key seen in a single time window must be saved when the time window closes, even if the key is never seen again
func TestSBOMetricSparseKeySavedWhenWindowCloses(t *testing.T) {
	m := NewSBOMetricsManager(3)
	saved := make(map[string]int64)
	addEntry(m, saved, SBO_METRIC_REFERER, "rare.com", 202611131000, 1)
	addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", 202611131010, 1)
	addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", 202611131020, 1)
	if len(saved) != 0 {
		t.Errorf("nothing should be saved before the window closes, got %v", saved)
	}
	addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", 202611131030, 1)
	if saved[savedKey(SBO_METRIC_REFERER, "rare.com", 202611131000)] != 1 {
		t.Errorf("rare.com should have been saved when its time window closed, got %v", saved)
	}
	if _, stillThere := m.GetAllMetricsForFile(testFile)[SBO_METRIC_REFERER]["rare.com"]; stillThere {
		t.Error("key without values should have been removed")
	}
}

func TestSBOMetricLateEntries(t *testing.T) {
	m := NewSBOMetricsManager(2)
	saved := make(map[string]int64)
	addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", 202611131010, 1)
	//out of order but there is room, accepted
	if !addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", 202611131000, 1) {
		t.Error("out of order entry should be accepted while there is room")
	}
	addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", 202611131020, 1) //closes 1000
	if addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", 202611131000, 1) {
		t.Error("entry for a closed time window must be rejected")
	}
	addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", 202611131030, 1) //closes 1010
	if addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", 202611131010, 1) {
		t.Error("entry for a closed time window must be rejected")
	}
	//1005 was never open but it is older than the most recently closed window
	if addEntry(m, saved, SBO_METRIC_REQ_COUNT, "", 202611131005, 1) {
		t.Error("entry older than a closed time window must be rejected")
	}
	collect(saved, m.FlushAll(testFile))
	for _, tw := range []int64{202611131000, 202611131010, 202611131020, 202611131030} {
		if saved[savedKey(SBO_METRIC_REQ_COUNT, "", tw)] != 1 {
			t.Errorf("tw=%d expected 1 got %d", tw, saved[savedKey(SBO_METRIC_REQ_COUNT, "", tw)])
		}
	}
}
