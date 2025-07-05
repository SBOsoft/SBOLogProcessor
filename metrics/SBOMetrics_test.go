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
	"testing"
	"time"
)

func TestSBOMetricTimeWindow(t *testing.T) {
	timest := time.Date(2025, 11, 17, 20, 34, 58, 651387237, time.UTC)
	metricManager := NewSBOMetricsManager(5)
	sbom := NewSBOMetric(SBO_METRIC_REQ_COUNT, "aaa", metricManager)
	sbom.addValue("unittest", timest, 100)

	slog.Warn("Values", "values", sbom.Values)

}
