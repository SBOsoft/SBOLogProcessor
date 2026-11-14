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

func TestGetOSUptimeInfo(t *testing.T) {

	uptimeInfo, err := GetOSUptimeInfo()

	// The `uptime` command is Linux/macOS only. On platforms where it is not
	// available (e.g. Windows) GetOSUptimeInfo returns a nil result and an error;
	// skip rather than nil-deref/fail.
	if err != nil || uptimeInfo == nil {
		t.Skipf("uptime command not available on this platform: %v", err)
	}

	fmt.Printf("Current time: %v \n", uptimeInfo.CurrentTime)
	fmt.Printf("LoadAverage1: %v \n", uptimeInfo.LoadAverage1)
	fmt.Printf("LoadAverage5: %v \n", uptimeInfo.LoadAverage5)
	fmt.Printf("LoadAverage15: %v \n", uptimeInfo.LoadAverage15)
	fmt.Printf("UpDurationMinutes: %v \n", uptimeInfo.UpDurationMinutes)
	fmt.Printf("Users: %v \n", uptimeInfo.Users)
}

func TestGetOSUptimeInfoMacOS(t *testing.T) {

	uptimeInfo, err := GetOSUptimeInfo()

	if err != nil || uptimeInfo == nil {
		t.Skipf("uptime command not available on this platform: %v", err)
	}

	fmt.Printf("Current time: %v \n", uptimeInfo.CurrentTime)
	fmt.Printf("LoadAverage1: %v \n", uptimeInfo.LoadAverage1)
	fmt.Printf("LoadAverage5: %v \n", uptimeInfo.LoadAverage5)
	fmt.Printf("LoadAverage15: %v \n", uptimeInfo.LoadAverage15)
	fmt.Printf("UpDurationMinutes: %v \n", uptimeInfo.UpDurationMinutes)
	fmt.Printf("Users: %v \n", uptimeInfo.Users)
}

func TestParseUptimeOutputMacOS(t *testing.T) {

	uptimeOutput := "12:13  up 13 days, 13:27, 11 users, load averages: 1.25 1.50 1.52"
	uptimeInfo := ParseUptimeOutput(uptimeOutput)

	if uptimeInfo.CurrentTime != "12:13" {
		t.Error("Unexpected CurrentTime value", uptimeInfo.CurrentTime)
	}

	if uptimeInfo.LoadAverage1 != "1.25" {
		t.Error("Unexpected LoadAverage1 value", uptimeInfo.LoadAverage1)
	}
	if uptimeInfo.LoadAverage5 != "1.50" {
		t.Error("Unexpected LoadAverage5 value", uptimeInfo.LoadAverage5)
	}
	if uptimeInfo.LoadAverage15 != "1.52" {
		t.Error("Unexpected LoadAverage15 value", uptimeInfo.LoadAverage15)
	}
	if uptimeInfo.UpDurationMinutes != (13*24*60 + 13*60 + 27) {
		t.Error("Unexpected UpDurationMinutes value", uptimeInfo.UpDurationMinutes)
	}
	if uptimeInfo.Users != 11 {
		t.Error("Unexpected Users value", uptimeInfo.Users)
	}

}

// Ubuntu 24.04.2 LTS
func TestParseUptimeOutputUbuntu(t *testing.T) {

	uptimeOutput := "09:18:58 up 34 days, 14:35,  2 users,  load average: 0.04, 0.03, 0.00"
	uptimeInfo := ParseUptimeOutput(uptimeOutput)

	if uptimeInfo.CurrentTime != "09:18:58" {
		t.Error("Unexpected CurrentTime value", uptimeInfo.CurrentTime)
	}

	if uptimeInfo.LoadAverage1 != "0.04" {
		t.Error("Unexpected LoadAverage1 value", uptimeInfo.LoadAverage1)
	}
	if uptimeInfo.LoadAverage5 != "0.03" {
		t.Error("Unexpected LoadAverage5 value", uptimeInfo.LoadAverage5)
	}
	if uptimeInfo.LoadAverage15 != "0.00" {
		t.Error("Unexpected LoadAverage15 value", uptimeInfo.LoadAverage15)
	}
	if uptimeInfo.UpDurationMinutes != (34*24*60 + 14*60 + 35) {
		t.Error("Unexpected UpDurationMinutes value", uptimeInfo.UpDurationMinutes)
	}
	if uptimeInfo.Users != 2 {
		t.Error("Unexpected Users value", uptimeInfo.Users)
	}

}

// rebooted less than a day before
func TestParseUptimeOutputUbuntu2(t *testing.T) {

	uptimeOutput := "09:18:58 up 14:35,  2 users,  load average: 0.04, 0.03, 0.00"
	uptimeInfo := ParseUptimeOutput(uptimeOutput)

	if uptimeInfo.CurrentTime != "09:18:58" {
		t.Error("Unexpected CurrentTime value", uptimeInfo.CurrentTime)
	}

	if uptimeInfo.LoadAverage1 != "0.04" {
		t.Error("Unexpected LoadAverage1 value", uptimeInfo.LoadAverage1)
	}
	if uptimeInfo.LoadAverage5 != "0.03" {
		t.Error("Unexpected LoadAverage5 value", uptimeInfo.LoadAverage5)
	}
	if uptimeInfo.LoadAverage15 != "0.00" {
		t.Error("Unexpected LoadAverage15 value", uptimeInfo.LoadAverage15)
	}
	if uptimeInfo.UpDurationMinutes != (14*60 + 35) {
		t.Error("Unexpected UpDurationMinutes value", uptimeInfo.UpDurationMinutes)
	}
	if uptimeInfo.Users != 2 {
		t.Error("Unexpected Users value", uptimeInfo.Users)
	}

}

func TestParseFreeOutputUbuntu(t *testing.T) {

	freeOutput := `               total        used        free      shared  buff/cache   available
Mem:         8131912     1142280     5147464        4044     2163520     6989632
Swap:              0           0           0`
	memInfo, err := ParseFreeOutput(freeOutput)
	if err != nil {
		t.Error("Unexpected error", err)
		return
	}

	if memInfo.CachUse != 2163520 {
		t.Error("Unexpected CachUse value", memInfo.CachUse)
	}
	if memInfo.MemFree != 5147464 {
		t.Error("Unexpected MemFree value", memInfo.MemFree)
	}
	if memInfo.MemUse != 1142280 {
		t.Error("Unexpected MemUse value", memInfo.MemUse)
	}

	if memInfo.MemAvailable != 6989632 {
		t.Error("Unexpected MemAvailable value", memInfo.MemAvailable)
	}

	if memInfo.SwapUse != 0 {
		t.Error("Unexpected SwapUse value", memInfo.SwapUse)
	}

}

func TestParseFreeOutputWithSwap(t *testing.T) {

	freeOutput := `               total        used        free      shared  buff/cache   available
Mem:         8131912     1142280     5147464        4044     2163520     6989632
Swap:        2097148      524288     1572860`
	memInfo, err := ParseFreeOutput(freeOutput)
	if err != nil {
		t.Error("Unexpected error", err)
		return
	}

	if memInfo.SwapUse != 524288 {
		t.Error("Unexpected SwapUse value", memInfo.SwapUse)
	}
	if memInfo.MemUse != 1142280 {
		t.Error("Unexpected MemUse value", memInfo.MemUse)
	}
}

func TestParseUptimeOutputDurations(t *testing.T) {
	tests := []struct {
		uptime          string
		expectedMinutes int
		expectedUsers   int
		expectedLoad1   string
	}{
		{" 14:35:01 up 5 min,  2 users,  load average: 0.08, 0.03, 0.00", 5, 2, "0.08"},
		{" 14:35:01 up 3 days,  5 min,  2 users,  load average: 0.08, 0.03, 0.00", 3*24*60 + 5, 2, "0.08"},
		{" 14:35:01 up 1 day,  2:03,  1 user,  load average: 0.08, 0.03, 0.00", 24*60 + 2*60 + 3, 1, "0.08"},
		{" 14:35:01 up 0 min,  0 users,  load average: 0.08, 0.03, 0.00", 0, 0, "0.08"},
		// no user count (e.g. BusyBox without utmp)
		{" 14:35:01 up 3 days,  2:03,  load average: 0.08, 0.03, 0.00", 3*24*60 + 2*60 + 3, 0, "0.08"},
		{" 14:35:01 up 5 min,  load average: 0.08, 0.03, 0.00", 5, 0, "0.08"},
		// decimal comma (non-C locale)
		{" 14:35:01 up 3 days,  2:03,  2 users,  load average: 0,08, 0,03, 0,00", 3*24*60 + 2*60 + 3, 2, "0.08"},
		// macOS
		{"14:35  up 3 days, 4 hrs, 2 users, load averages: 1.20 1.10 1.00", 3*24*60 + 4*60, 2, "1.20"},
		{"14:35  up 3 days, 12 mins, 2 users, load averages: 1.20 1.10 1.00", 3*24*60 + 12, 2, "1.20"},
		{"14:35  up 1 min, 1 user, load averages: 1.20 1.10 1.00", 1, 1, "1.20"},
		{"14:35  up 30 secs, 1 user, load averages: 1.20 1.10 1.00", 0, 1, "1.20"},
		{"9:05  up 2:03, 1 user, load averages: 1.20 1.10 1.00", 2*60 + 3, 1, "1.20"},
	}
	for _, test := range tests {
		info := ParseUptimeOutput(test.uptime)
		if info.UpDurationMinutes != test.expectedMinutes || info.Users != test.expectedUsers || info.LoadAverage1 != test.expectedLoad1 {
			t.Errorf("%q: got minutes=%d users=%d load1=%q, expected %d %d %q", test.uptime,
				info.UpDurationMinutes, info.Users, info.LoadAverage1, test.expectedMinutes, test.expectedUsers, test.expectedLoad1)
		}
	}
}

func TestParseProcUptimeAndLoadAvg(t *testing.T) {
	minutes, err := ParseProcUptime("299381.17 1176533.49\n")
	if err != nil || minutes != 4989 {
		t.Error("Unexpected /proc/uptime result", minutes, err)
	}
	if _, err := ParseProcUptime(""); err == nil {
		t.Error("Expected error for empty /proc/uptime")
	}

	la1, la5, la15, err := ParseProcLoadAvg("0.08 0.03 0.00 1/123 4567\n")
	if err != nil || la1 != "0.08" || la5 != "0.03" || la15 != "0.00" {
		t.Error("Unexpected /proc/loadavg result", la1, la5, la15, err)
	}
	if _, _, _, err := ParseProcLoadAvg("0.08 x 0.00"); err == nil {
		t.Error("Expected error for invalid /proc/loadavg")
	}
}

func TestParseProcMeminfo(t *testing.T) {
	meminfo := `MemTotal:        8131912 kB
MemFree:         5147464 kB
MemAvailable:    6989632 kB
Buffers:          163520 kB
Cached:          1800000 kB
SwapCached:            0 kB
Active:          1000000 kB
SReclaimable:     200000 kB
SwapTotal:       2097148 kB
SwapFree:        1572860 kB
HugePages_Total:       0
`
	info, err := ParseProcMeminfo(meminfo)
	if err != nil {
		t.Fatal("Unexpected error", err)
	}
	// same values as `free` reports for this host, see TestParseFreeOutputUbuntu
	expected := MemoryInfo{SwapUse: 524288, CachUse: 2163520, MemUse: 1142280, MemFree: 5147464, MemAvailable: 6989632}
	if *info != expected {
		t.Errorf("Unexpected result %+v, expected %+v", *info, expected)
	}

	if _, err := ParseProcMeminfo("MemTotal: 8131912 kB\nMemFree: 5147464 kB\n"); err == nil {
		t.Error("Expected error for missing swap values")
	}
}

func TestParseFreeOutputOldFormat(t *testing.T) {
	freeOutput := `             total       used       free     shared    buffers     cached
Mem:       8131912    2984448    5147464       4044     163520    1678648
-/+ buffers/cache:    1142280    6989632
Swap:      2097148     524288    1572860`
	info, err := ParseFreeOutput(freeOutput)
	if err != nil {
		t.Fatal("Unexpected error", err)
	}
	expected := MemoryInfo{SwapUse: 524288, CachUse: 1842168, MemUse: 1142280, MemFree: 5147464, MemAvailable: 6989632}
	if *info != expected {
		t.Errorf("Unexpected result %+v, expected %+v", *info, expected)
	}
}

func TestParseFreeOutputInvalid(t *testing.T) {
	for _, freeOutput := range []string{
		"",
		"              total        used        free      shared  buff/cache   available\nMem:\nSwap: 0 0 0",
		"              total        used        free      shared  buff/cache   available\nMem: 1 2 3 4 5 6",
		"              total        used        free      shared  buff/cache   available\nMem: 1 x 3 4 5 6\nSwap: 0 0 0",
	} {
		if info, err := ParseFreeOutput(freeOutput); err == nil {
			t.Errorf("Expected error for %q, got %+v", freeOutput, info)
		}
	}
}
