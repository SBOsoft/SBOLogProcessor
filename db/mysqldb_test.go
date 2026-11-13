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

package db

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

func TestBuildSaveMetricDataBatchStatement(t *testing.T) {
	batch := []*metrics.SBOMetricWindowDataToBeSaved{
		metrics.NewSBOMetricWindowDataToBeSaved("f", metrics.SBO_METRIC_REFERER, "example.com", 202611131000, 3),
		metrics.NewSBOMetricWindowDataToBeSaved("f", metrics.SBO_METRIC_REQ_COUNT, "", 202611131010, 7),
	}
	sql, args := buildSaveMetricDataBatchStatement(batch, 42, false)
	expectedSql := "INSERT INTO sbo_metrics (domain_id, metric_type, key_value, time_window, metric_value, created) VALUES " +
		"(?, ?, ?, ?, ?, now()), (?, ?, ?, ?, ?, now()) ON DUPLICATE KEY UPDATE metric_value=metric_value+VALUES(metric_value)"
	if sql != expectedSql {
		t.Errorf("unexpected sql: %s", sql)
	}
	if strings.Count(sql, "?") != len(args) {
		t.Errorf("placeholder count %d does not match argument count %d", strings.Count(sql, "?"), len(args))
	}
	expectedArgs := "[42 6 example.com 202611131000 3 42 1  202611131010 7]"
	if fmt.Sprint(args) != expectedArgs {
		t.Errorf("expected args %s got %v", expectedArgs, args)
	}

	sql, _ = buildSaveMetricDataBatchStatement(batch, 42, true)
	if !strings.HasSuffix(sql, " ON DUPLICATE KEY UPDATE metric_value=VALUES(metric_value)") {
		t.Errorf("replace mode must replace existing values: %s", sql)
	}
}

func TestSortInPrimaryKeyOrder(t *testing.T) {
	d := func(metricType int, key string, tw int64, value int64) *metrics.SBOMetricWindowDataToBeSaved {
		return metrics.NewSBOMetricWindowDataToBeSaved("f", metricType, key, tw, value)
	}
	data := []*metrics.SBOMetricWindowDataToBeSaved{
		d(6, "b.com", 202611131010, 1),
		d(1, "", 202611131010, 2),
		d(6, "a.com", 202611131010, 3),
		d(6, "b.com", 202611131000, 4),
		//same metric again, must stay after the first one
		d(6, "b.com", 202611131010, 5),
	}
	sorted := sortInPrimaryKeyOrder(data)
	var got []int64
	for _, s := range sorted {
		got = append(got, s.MetricValue)
	}
	if fmt.Sprint(got) != "[2 4 3 1 5]" {
		t.Errorf("unexpected order %v", got)
	}
	if data[0].MetricValue != 1 {
		t.Error("input must not be modified")
	}
}

func TestIsRetryableError(t *testing.T) {
	if !isRetryableError(fmt.Errorf("wrapped: %w", &mysql.MySQLError{Number: 1213})) || !isRetryableError(&mysql.MySQLError{Number: 1205}) {
		t.Error("deadlock and lock wait timeout must be retried")
	}
	if isRetryableError(&mysql.MySQLError{Number: 1062}) || isRetryableError(mysql.ErrInvalidConn) {
		t.Error("other errors must not be retried")
	}
}

func TestFormatRequestTimestamp(t *testing.T) {
	//the same moment in different time zones must be saved as the same UTC value
	utc := time.Date(2026, 11, 13, 21, 5, 9, 0, time.UTC)
	for _, zone := range []*time.Location{time.UTC, time.FixedZone("+0300", 3*60*60), time.FixedZone("-0800", -8*60*60), time.FixedZone("+0530", 5*60*60+30*60)} {
		if got := FormatRequestTimestamp(utc.In(zone)); got != "2026-11-13 21:05:09" {
			t.Errorf("zone=%v expected 2026-11-13 21:05:09 got %s", zone, got)
		}
	}
}
