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

// free output
type MemoryInfo struct {
	SwapUse      int64
	CachUse      int64
	MemUse       int64
	MemFree      int64
	MemAvailable int64
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
	// Execute the linux 'free' command. Not available on other environments
	cmd := exec.Command("free")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute 'free' command: %w", err)
	}

	freeStr := strings.TrimSpace(string(output))
	slog.Debug("Command output", "free", freeStr)
	info, err := ParseFreeOutput(freeStr)
	return info, err
}

func ParseFreeOutput(freeOutput string) (*MemoryInfo, error) {
	/*
	   	               total        used        free      shared  buff/cache   available
	   Mem:         8131912     1142280     5147464        4044     2163520     6989632
	   Swap:              0           0           0
	*/
	splitFree := strings.Split(freeOutput, "\n")
	if len(splitFree) < 3 {
		return nil, fmt.Errorf("'free' output does not match expected format")
	}
	var memTotal, memUsed, memFree, memShared, memBuffCache, memAvailable int64
	var labelToDiscard string
	fmt.Sscanf(splitFree[1], "%s %d %d %d %d %d %d", &labelToDiscard, &memTotal, &memUsed, &memFree, &memShared, &memBuffCache, &memAvailable)

	var swapTotal, swapUsed, swapFree int64

	fmt.Sscanf(splitFree[2], "%s %d %d %d", &swapTotal, &swapUsed, &swapFree)

	info := &MemoryInfo{}

	info.SwapUse = swapUsed
	info.CachUse = memBuffCache
	info.MemUse = memUsed
	info.MemFree = memFree
	info.MemAvailable = memAvailable

	return info, nil
}
