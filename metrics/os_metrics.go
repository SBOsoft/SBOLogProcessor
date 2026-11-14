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
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"log/slog"
)

// On Linux the values are read from these kernel files; the `uptime`/`free` commands are only
// used for what /proc doesn't provide (logged-in user count) or as a fallback when /proc is not
// available (e.g. macOS).
const (
	procUptimePath  = "/proc/uptime"
	procLoadAvgPath = "/proc/loadavg"
	procMeminfoPath = "/proc/meminfo"
)

// UptimeInfo holds the parsed information from the uptime command.
type UptimeInfo struct {
	CurrentTime       string
	UpDurationMinutes int
	Users             int
	LoadAverage1      string // 1-minute load average, "" if unknown
	LoadAverage5      string // 5-minute load average, "" if unknown
	LoadAverage15     string // 15-minute load average, "" if unknown
}

// Memory usage. All values are in KiB (1024 bytes), the unit of `free` and /proc/meminfo.
type MemoryInfo struct {
	SwapUse      int64
	CachUse      int64 // buffers + page cache + reclaimable slab ("buff/cache" in `free`)
	MemUse       int64 // total - available, as reported by `free` (procps-ng 4)
	MemFree      int64
	MemAvailable int64
}

// runCommandInCLocale runs a command with LC_ALL=C so that its output (decimal separators,
// labels) doesn't depend on the host's locale.
func runCommandInCLocale(name string) (string, error) {
	cmd := exec.Command(name)
	cmd.Env = append(os.Environ(), "LC_ALL=C") // the last value wins for duplicate keys
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// GetOSUptimeInfo collects uptime, load averages and the logged-in user count.
// On Linux uptime and load averages come from /proc; the `uptime` command supplies the user
// count (and everything else when /proc is not available).
// Returns an error only if neither source is available.
func GetOSUptimeInfo() (*UptimeInfo, error) {
	var info *UptimeInfo
	uptimeStr, cmdErr := runCommandInCLocale("uptime")
	if cmdErr == nil {
		slog.Debug("Raw uptime output:", "uptime", uptimeStr)
		info = ParseUptimeOutput(uptimeStr)
	} else {
		info = &UptimeInfo{CurrentTime: time.Now().Format("15:04:05")}
	}

	procAvailable := false
	if data, err := os.ReadFile(procUptimePath); err == nil {
		if minutes, err := ParseProcUptime(string(data)); err == nil {
			info.UpDurationMinutes = minutes
			procAvailable = true
		} else {
			slog.Warn("Failed to parse "+procUptimePath, "error", err)
		}
	}
	if data, err := os.ReadFile(procLoadAvgPath); err == nil {
		if la1, la5, la15, err := ParseProcLoadAvg(string(data)); err == nil {
			info.LoadAverage1, info.LoadAverage5, info.LoadAverage15 = la1, la5, la15
			procAvailable = true
		} else {
			slog.Warn("Failed to parse "+procLoadAvgPath, "error", err)
		}
	}

	if cmdErr != nil && !procAvailable {
		return nil, fmt.Errorf("failed to execute 'uptime' command: %w", cmdErr)
	}
	return info, nil
}

// ParseProcUptime parses /proc/uptime ("<seconds up> <seconds idle>") and returns whole minutes.
func ParseProcUptime(content string) (int, error) {
	fields := strings.Fields(content)
	if len(fields) < 1 {
		return 0, fmt.Errorf("unexpected /proc/uptime content %q", content)
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return 0, fmt.Errorf("unexpected /proc/uptime content %q", content)
	}
	return int(seconds / 60), nil
}

// ParseProcLoadAvg parses /proc/loadavg ("0.08 0.03 0.00 1/123 4567") and returns the
// 1, 5 and 15 minute load averages.
func ParseProcLoadAvg(content string) (string, string, string, error) {
	fields := strings.Fields(content)
	if len(fields) < 3 {
		return "", "", "", fmt.Errorf("unexpected /proc/loadavg content %q", content)
	}
	for _, f := range fields[:3] {
		if _, err := strconv.ParseFloat(f, 64); err != nil {
			return "", "", "", fmt.Errorf("unexpected /proc/loadavg content %q", content)
		}
	}
	return fields[0], fields[1], fields[2], nil
}

// Compiled once; these are used by ParseUptimeOutput which may run periodically.
var (
	reUptimeTime = regexp.MustCompile(`^\s*(\d{1,2}:\d{2}(:\d{2})?)`)
	// the duration is between "up" and the user count or, if there is no user count
	// (e.g. BusyBox without utmp), the load averages
	reUptimeDuration = regexp.MustCompile(`\bup\s+(.*?),\s*(?:\d+\s+users?\b|load averages?\s*:)`)
	reUptimeUsers    = regexp.MustCompile(`(\d+)\s+users?\b`)
	// duration parts: "3 days", "14:35", "5 min", "12 mins", "4 hrs", "30 secs"
	reUptimeDays    = regexp.MustCompile(`^(\d+)\s+days?$`)
	reUptimeHourMin = regexp.MustCompile(`^(\d{1,2}):(\d{2})$`)
	reUptimeHours   = regexp.MustCompile(`^(\d+)\s+(?:hrs?|hours?)$`)
	reUptimeMinutes = regexp.MustCompile(`^(\d+)\s+(?:mins?|minutes?)$`)
	// decimal comma accepted in case the command ignores LC_ALL=C
	reUptimeLoadAvg = regexp.MustCompile(`load averages?\s*:\s*(\d+[.,]\d+)[,\s]\s*(\d+[.,]\d+)[,\s]\s*(\d+[.,]\d+)`)
)

// parse a given uptime output as string
func ParseUptimeOutput(uptimeStr string) *UptimeInfo {

	info := &UptimeInfo{}

	if match := reUptimeTime.FindStringSubmatch(uptimeStr); len(match) > 1 {
		info.CurrentTime = match[1]
	} else {
		// Fallback: Use current system time if uptime output format is unexpected ??
		info.CurrentTime = time.Now().Format("15:04:05")
	}

	if match := reUptimeDuration.FindStringSubmatch(uptimeStr); len(match) > 1 {
		info.UpDurationMinutes = parseUptimeDuration(match[1])
	} else {
		slog.Debug("Unexpected uptime output, duration not found", "uptime", uptimeStr)
	}

	if match := reUptimeUsers.FindStringSubmatch(uptimeStr); len(match) > 1 {
		info.Users, _ = strconv.Atoi(match[1])
	}

	if match := reUptimeLoadAvg.FindStringSubmatch(uptimeStr); len(match) > 3 {
		info.LoadAverage1 = strings.Replace(match[1], ",", ".", 1)
		info.LoadAverage5 = strings.Replace(match[2], ",", ".", 1)
		info.LoadAverage15 = strings.Replace(match[3], ",", ".", 1)
	}

	return info
}

// parseUptimeDuration converts the duration part of uptime output, e.g. "3 days,  5 min",
// "14:35", "13 days, 13:27" or "3 days, 4 hrs", to minutes.
func parseUptimeDuration(duration string) int {
	minutes := 0
	for _, part := range strings.Split(duration, ",") {
		part = strings.TrimSpace(part)
		if m := reUptimeDays.FindStringSubmatch(part); m != nil {
			days, _ := strconv.Atoi(m[1])
			minutes += days * 24 * 60
		} else if m := reUptimeHourMin.FindStringSubmatch(part); m != nil {
			hours, _ := strconv.Atoi(m[1])
			mins, _ := strconv.Atoi(m[2])
			minutes += hours*60 + mins
		} else if m := reUptimeHours.FindStringSubmatch(part); m != nil {
			hours, _ := strconv.Atoi(m[1])
			minutes += hours * 60
		} else if m := reUptimeMinutes.FindStringSubmatch(part); m != nil {
			mins, _ := strconv.Atoi(m[1])
			minutes += mins
		}
		// anything else (e.g. "30 secs") adds no whole minutes
	}
	return minutes
}

// GetOSMemoryInfo reads /proc/meminfo, falling back to the 'free' command.
// Not available on non-Linux environments.
func GetOSMemoryInfo() (*MemoryInfo, error) {
	if data, err := os.ReadFile(procMeminfoPath); err == nil {
		info, parseErr := ParseProcMeminfo(string(data))
		if parseErr == nil {
			return info, nil
		}
		slog.Warn("Failed to parse "+procMeminfoPath+", trying the 'free' command", "error", parseErr)
	}

	freeStr, err := runCommandInCLocale("free")
	if err != nil {
		return nil, fmt.Errorf("failed to execute 'free' command: %w", err)
	}
	slog.Debug("Command output", "free", freeStr)
	return ParseFreeOutput(freeStr)
}

// ParseProcMeminfo parses /proc/meminfo ("MemTotal:  8131912 kB" lines) and computes the
// values the same way procps-ng 4 `free` does.
func ParseProcMeminfo(content string) (*MemoryInfo, error) {
	values := make(map[string]int64)
	for _, line := range strings.Split(content, "\n") {
		key, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 1 {
			continue
		}
		if v, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			values[strings.TrimSpace(key)] = v
		}
	}

	for _, required := range []string{"MemTotal", "MemFree", "SwapTotal", "SwapFree"} {
		if _, ok := values[required]; !ok {
			return nil, fmt.Errorf("/proc/meminfo has no %s value", required)
		}
	}

	info := &MemoryInfo{}
	info.MemFree = values["MemFree"]
	info.CachUse = values["Buffers"] + values["Cached"] + values["SReclaimable"]
	if available, ok := values["MemAvailable"]; ok {
		info.MemAvailable = available
	} else {
		// kernels before 3.14 don't report MemAvailable; approximate it
		info.MemAvailable = info.MemFree + info.CachUse
	}
	info.MemUse = max(values["MemTotal"]-info.MemAvailable, 0)
	info.SwapUse = max(values["SwapTotal"]-values["SwapFree"], 0)
	return info, nil
}

// ParseFreeOutput parses the output of `free` (values in KiB). Columns are located by the
// header names, so both the current and the older (pre procps-ng 3.3.10) formats work:
//
//	               total        used        free      shared  buff/cache   available
//	Mem:         8131912     1142280     5147464        4044     2163520     6989632
//	Swap:              0           0           0
//
//	             total       used       free     shared    buffers     cached
//	Mem:       8131912    3305800    4826112       4044     163520    2000000
//	-/+ buffers/cache:    1142280    6989632
//	Swap:      2097148     524288    1572860
func ParseFreeOutput(freeOutput string) (*MemoryInfo, error) {
	lines := strings.Split(strings.TrimSpace(freeOutput), "\n")
	header := strings.Fields(lines[0])
	var memFields, swapFields []string
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "Mem:":
			memFields = fields[1:]
		case "Swap:":
			swapFields = fields[1:]
		}
	}
	if memFields == nil || swapFields == nil {
		return nil, fmt.Errorf("'free' output does not match expected format")
	}

	// value of the Mem: column with the given header name, -1 if there is no such column
	memValue := func(column string) (int64, error) {
		for i, name := range header {
			if name == column {
				if i >= len(memFields) {
					return 0, fmt.Errorf("'free' output has no value for column %s", column)
				}
				return strconv.ParseInt(memFields[i], 10, 64)
			}
		}
		return -1, nil
	}
	columns := make(map[string]int64)
	for _, column := range []string{"used", "free", "buff/cache", "buffers", "cache", "cached", "available"} {
		v, err := memValue(column)
		if err != nil {
			return nil, fmt.Errorf("failed to parse 'free' output column %s: %w", column, err)
		}
		columns[column] = v
	}
	if columns["used"] < 0 || columns["free"] < 0 {
		return nil, fmt.Errorf("'free' output does not match expected format")
	}

	info := &MemoryInfo{}
	info.MemFree = columns["free"]
	info.MemUse = columns["used"]
	switch {
	case columns["buff/cache"] >= 0:
		info.CachUse = columns["buff/cache"]
	case columns["cache"] >= 0: // free -w
		info.CachUse = max(columns["buffers"], 0) + columns["cache"]
	case columns["cached"] >= 0: // old format, "used" includes buffers and cache
		info.CachUse = max(columns["buffers"], 0) + columns["cached"]
		info.MemUse = max(columns["used"]-info.CachUse, 0)
	}
	if columns["available"] >= 0 {
		info.MemAvailable = columns["available"]
	} else {
		info.MemAvailable = info.MemFree + info.CachUse
	}

	if len(swapFields) < 2 {
		return nil, fmt.Errorf("'free' output has no swap usage")
	}
	swapUsed, err := strconv.ParseInt(swapFields[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse 'free' swap usage: %w", err)
	}
	info.SwapUse = swapUsed

	return info, nil
}
