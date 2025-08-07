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

	fmt.Printf("Current time: %v \n", uptimeInfo.CurrentTime)
	fmt.Printf("LoadAverage1: %v \n", uptimeInfo.LoadAverage1)
	fmt.Printf("LoadAverage5: %v \n", uptimeInfo.LoadAverage5)
	fmt.Printf("LoadAverage15: %v \n", uptimeInfo.LoadAverage15)
	fmt.Printf("UpDurationMinutes: %v \n", uptimeInfo.UpDurationMinutes)
	fmt.Printf("Users: %v \n", uptimeInfo.Users)

	//slog.Warn("Values", "values", sbom.Values)
	if err != nil {
		t.Error("Failed to run uptime command", "err", err)
	}

}

func TestGetOSUptimeInfoMacOS(t *testing.T) {

	uptimeInfo, err := GetOSUptimeInfo()

	fmt.Printf("Current time: %v \n", uptimeInfo.CurrentTime)
	fmt.Printf("LoadAverage1: %v \n", uptimeInfo.LoadAverage1)
	fmt.Printf("LoadAverage5: %v \n", uptimeInfo.LoadAverage5)
	fmt.Printf("LoadAverage15: %v \n", uptimeInfo.LoadAverage15)
	fmt.Printf("UpDurationMinutes: %v \n", uptimeInfo.UpDurationMinutes)
	fmt.Printf("Users: %v \n", uptimeInfo.Users)

	//slog.Warn("Values", "values", sbom.Values)
	if err != nil {
		t.Error("Failed to run uptime command", "err", err)
	}

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

func TestParseFreeMinusLOutputUbuntu(t *testing.T) {

	freeOutput := "SwapUse           0 CachUse     2104792  MemUse     1132692 MemFree     5213936"
	memInfo := ParseFreeOutput(freeOutput)

	if memInfo.CachUse != 2104792 {
		t.Error("Unexpected CachUse value", memInfo.CachUse)
	}
	if memInfo.MemFree != 5213936 {
		t.Error("Unexpected MemFree value", memInfo.MemFree)
	}
	if memInfo.MemUse != 1132692 {
		t.Error("Unexpected MemUse value", memInfo.MemUse)
	}
	if memInfo.SwapUse != 0 {
		t.Error("Unexpected SwapUse value", memInfo.SwapUse)
	}

}
