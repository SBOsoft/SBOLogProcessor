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
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"log/slog"
)

// UptimeInfo holds the parsed information from the uptime command.
type UptimeInfo struct {
	CurrentTime       string
	UpDurationMinutes int
	Users             int
	LoadAverage1      string // 1-minute load average
	LoadAverage5      string // 5-minute load average
	LoadAverage15     string // 15-minute load average
}

// free -L output
type MemoryInfo struct {
	SwapUse int64
	CachUse int64
	MemUse  int64
	MemFree int64
}

// GetOSUptimeInfo executes the 'uptime' command and parses its output.
// It returns a UptimeInfo struct or an error if the command fails or parsing is unsuccessful.
func GetOSUptimeInfo() (*UptimeInfo, error) {
	// Execute the 'uptime' command
	cmd := exec.Command("uptime")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute 'uptime' command: %w", err)
	}

	uptimeStr := strings.TrimSpace(string(output))
	slog.Debug("Raw uptime output:", "uptime", uptimeStr)
	info := ParseUptimeOutput(uptimeStr)
	return info, nil
}

// parse a given uptime output as string
func ParseUptimeOutput(uptimeStr string) *UptimeInfo {

	info := &UptimeInfo{}

	timeRe := regexp.MustCompile(`^\s*(\d{2}:\d{2}(:\d{2})?)`)
	if match := timeRe.FindStringSubmatch(uptimeStr); len(match) > 1 {
		info.CurrentTime = match[1]
	} else {
		// Fallback: Use current system time if uptime output format is unexpected ??
		info.CurrentTime = time.Now().Format("15:04:05")
	}

	// The `.*?` makes the matching non-greedy.
	re := regexp.MustCompile(`up\s+(.*),\s*(\d+)\s+users?`)

	durationAndUsersMatches := re.FindStringSubmatch(uptimeStr)

	daysHoursRe := regexp.MustCompile(`(\d+).*?,\s*(\d{1,2}):(\d{2})`)
	daysHoursMatches := daysHoursRe.FindStringSubmatch(durationAndUsersMatches[1])
	if len(daysHoursMatches) > 1 {
		days, _ := strconv.Atoi(daysHoursMatches[1])
		hours, _ := strconv.Atoi(daysHoursMatches[2])
		minutes, _ := strconv.Atoi(daysHoursMatches[3])
		info.UpDurationMinutes = days*24*60 + hours*60 + minutes
	} else {
		//no days. just hours:minutes
		hourMinRe := regexp.MustCompile(`(\d{1,2}):(\d{2})`)
		hourMinMatches := hourMinRe.FindStringSubmatch(durationAndUsersMatches[1])
		if len(hourMinMatches) > 1 {
			hours, _ := strconv.Atoi(hourMinMatches[1])
			minutes, _ := strconv.Atoi(hourMinMatches[2])
			info.UpDurationMinutes = hours*60 + minutes
		}
	}

	info.Users, _ = strconv.Atoi(durationAndUsersMatches[2])

	loadAvgRe := regexp.MustCompile(`load averages?\s*:\s*(\d+\.\d+)[,\s]\s*(\d+\.\d+)[,\s]\s*(\d+\.\d+)`)
	laMatch := loadAvgRe.FindStringSubmatch(uptimeStr)

	if len(laMatch) > 3 {
		info.LoadAverage1 = laMatch[1]
		info.LoadAverage5 = laMatch[2]
		info.LoadAverage15 = laMatch[3]
	}

	return info
}

func GetOSMemoryInfo() (*MemoryInfo, error) {
	// Execute the 'uptime' command
	cmd := exec.Command("free -L")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute 'free -L' command: %w", err)
	}

	freeStr := strings.TrimSpace(string(output))
	slog.Debug("Command output", "free -L", freeStr)
	info := ParseFreeOutput(freeStr)
	return info, nil
}

func ParseFreeOutput(freeOutput string) *MemoryInfo {
	//SwapUse           0 CachUse     2104792  MemUse     1132692 MemFree     5213936
	freeLRe := regexp.MustCompile(`SwapUse\s*(\d+)\s*CachUse\s*(\d+)\s*MemUse\s*(\d+)\s*MemFree\s*(\d+)\s*`)

	matches := freeLRe.FindStringSubmatch(freeOutput)

	info := &MemoryInfo{}
	if len(matches) > 1 {
		info.SwapUse, _ = strconv.ParseInt(matches[1], 10, 64)
		info.CachUse, _ = strconv.ParseInt(matches[2], 10, 64)
		info.MemUse, _ = strconv.ParseInt(matches[3], 10, 64)
		info.MemFree, _ = strconv.ParseInt(matches[4], 10, 64)
	}

	return info
}
