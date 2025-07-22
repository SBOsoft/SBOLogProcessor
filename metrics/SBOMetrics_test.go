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
	"testing"
)

func TestSBOMetricTimeWindow(t *testing.T) {

	metricManager := NewSBOMetricsManager(5)
	sbom := NewSBOMetric(SBO_METRIC_REQ_COUNT, "aaa", metricManager)
	var tw int64 = 202511172034
	sbom.addValue("unittest", tw, 100)

	//slog.Warn("Values", "values", sbom.Values)
	if sbom.Values[tw] != 100 {
		t.Error("sbom.Values does not contain expected entry", sbom.Values)
	}

}
