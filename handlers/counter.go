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

package handlers

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/SBOsoft/SBOLogProcessor/logparsers"
	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

const (
	COUNTER_HANDLER_NAME string = "COUNTER"
)

type CounterValue struct {
	CurrentValue  int64
	PreviousValue int64
}

type CounterMapEntry struct {
	key   string
	value *CounterValue
}

func (cv *CounterValue) Increment(value int64) {
	cv.CurrentValue += value
}

func (cv *CounterValue) NextWindow(value int64) {
	cv.PreviousValue = cv.CurrentValue
	cv.CurrentValue = value
}

type CounterHandler struct {
	filePath              string
	HandledEntryCounter   *CounterValue
	TotalRequests         *CounterValue
	TotalBytesSent        *CounterValue
	RequestsFromNonHumans *CounterValue
	RequestsFromHumans    *CounterValue
	MaliciousRequests     *CounterValue

	StatusCodes         map[string]*CounterValue
	Methods             map[string]*CounterValue
	Clients             map[string]*CounterValue
	UserAgentFamilies   map[string]*CounterValue
	UserAgentOSFamilies map[string]*CounterValue
	DeviceTypes         map[string]*CounterValue
	Referers            map[string]*CounterValue
	RequestedPaths      map[string]*CounterValue
	RequestIntents      map[string]*CounterValue

	dataToBeSavedChannel chan *metrics.SBOMetricWindowDataToBeSaved

	isFollowing    bool
	ticker         *time.Ticker
	tickerStopped  chan (bool)
	syncMutex      sync.Mutex
	topNWindowSize int
}

func NewCounterHandler(filePath string) *CounterHandler {

	var rv = CounterHandler{
		filePath:              filePath,
		HandledEntryCounter:   &CounterValue{CurrentValue: 0, PreviousValue: 0},
		TotalRequests:         &CounterValue{CurrentValue: 0, PreviousValue: 0},
		TotalBytesSent:        &CounterValue{CurrentValue: 0, PreviousValue: 0},
		RequestsFromNonHumans: &CounterValue{CurrentValue: 0, PreviousValue: 0},
		RequestsFromHumans:    &CounterValue{CurrentValue: 0, PreviousValue: 0},
		MaliciousRequests:     &CounterValue{CurrentValue: 0, PreviousValue: 0},
		Clients:               make(map[string]*CounterValue),
		Methods:               make(map[string]*CounterValue),
		StatusCodes:           make(map[string]*CounterValue),
		UserAgentFamilies:     make(map[string]*CounterValue),
		UserAgentOSFamilies:   make(map[string]*CounterValue),
		DeviceTypes:           make(map[string]*CounterValue),
		Referers:              make(map[string]*CounterValue),
		RequestedPaths:        make(map[string]*CounterValue),
		RequestIntents:        make(map[string]*CounterValue)}

	return &rv
}

func (handler *CounterHandler) Name() string {
	return COUNTER_HANDLER_NAME
}

func (handler *CounterHandler) Begin(dataToSaveChan chan *metrics.SBOMetricWindowDataToBeSaved,
	following bool,
	outputIntervalSeconds int,
	topNSize int) error {
	handler.dataToBeSavedChannel = dataToSaveChan
	handler.topNWindowSize = topNSize
	if following {
		handler.isFollowing = true
		slog.Debug("CounterHandler.Begin following is true, starting ticker")
		time.AfterFunc(time.Duration(2)*time.Second, func() {
			//Print initial output, just to give the user something without waiting for the whole window duration
			handler.PrintCounterData(false)
			handler.startNewWindow()
			handler.ticker = time.NewTicker(time.Duration(outputIntervalSeconds) * time.Second)
			handler.tickerStopped = make(chan bool)
			go handler.tickerTick()
		})
	} else {
		slog.Debug("CounterHandler.Begin following is FALSE, NOT starting ticker")
	}

	return nil
}

func (handler *CounterHandler) HandleEntry(parsedLogEntry *logparsers.SBOHttpRequestLog) (bool, error) {

	handler.syncMutex.Lock()
	defer handler.syncMutex.Unlock()

	if handler.HandledEntryCounter == nil {
		handler.HandledEntryCounter = &CounterValue{CurrentValue: 1}
	} else {
		handler.HandledEntryCounter.Increment(1)
	}
	if handler.Clients[parsedLogEntry.ClientIP] == nil {
		handler.Clients[parsedLogEntry.ClientIP] = &CounterValue{CurrentValue: 1}
	} else {
		handler.Clients[parsedLogEntry.ClientIP].Increment(1)
	}
	if handler.DeviceTypes[parsedLogEntry.UserAgent.DeviceType] == nil {
		handler.DeviceTypes[parsedLogEntry.UserAgent.DeviceType] = &CounterValue{CurrentValue: 1}
	} else {
		handler.DeviceTypes[parsedLogEntry.UserAgent.DeviceType].Increment(1)
	}
	if handler.RequestIntents[parsedLogEntry.UserAgent.Intent] == nil {
		handler.RequestIntents[parsedLogEntry.UserAgent.Intent] = &CounterValue{CurrentValue: 1}
	} else {
		handler.RequestIntents[parsedLogEntry.UserAgent.Intent].Increment(1)
	}
	if handler.Methods[parsedLogEntry.Method] == nil {
		handler.Methods[parsedLogEntry.Method] = &CounterValue{CurrentValue: 1}
	} else {
		handler.Methods[parsedLogEntry.Method].Increment(1)
	}
	if parsedLogEntry.UserAgent.Human == logparsers.Human_Yes {
		if handler.RequestsFromHumans == nil {
			handler.RequestsFromHumans = &CounterValue{CurrentValue: 1}
		} else {
			handler.RequestsFromHumans.Increment(1)
		}
	}
	if parsedLogEntry.Malicious != logparsers.REQUEST_MALICIOUS_UNKNOWN {
		if handler.MaliciousRequests == nil {
			handler.MaliciousRequests = &CounterValue{CurrentValue: 1}
		} else {
			handler.MaliciousRequests.Increment(1)
		}
	}
	if parsedLogEntry.UserAgent.Human == logparsers.Human_No {
		if handler.RequestsFromNonHumans == nil {
			handler.RequestsFromNonHumans = &CounterValue{CurrentValue: 1}
		} else {
			handler.RequestsFromNonHumans.Increment(1)
		}
	}
	if handler.StatusCodes[parsedLogEntry.Status] == nil {
		handler.StatusCodes[parsedLogEntry.Status] = &CounterValue{CurrentValue: 1}
	} else {
		handler.StatusCodes[parsedLogEntry.Status].Increment(1)
	}
	if handler.TotalBytesSent == nil {
		handler.TotalBytesSent = &CounterValue{CurrentValue: int64(parsedLogEntry.BytesSent)}
	} else {
		handler.TotalBytesSent.Increment(int64(parsedLogEntry.BytesSent))
	}

	if handler.TotalRequests == nil {
		handler.TotalRequests = &CounterValue{CurrentValue: 1}
	} else {
		handler.TotalRequests.Increment(1)
	}

	if handler.UserAgentFamilies[parsedLogEntry.UserAgent.Family] == nil {
		handler.UserAgentFamilies[parsedLogEntry.UserAgent.Family] = &CounterValue{CurrentValue: 1}
	} else {
		handler.UserAgentFamilies[parsedLogEntry.UserAgent.Family].Increment(1)
	}
	if handler.UserAgentOSFamilies[parsedLogEntry.UserAgent.OS] == nil {
		handler.UserAgentOSFamilies[parsedLogEntry.UserAgent.OS] = &CounterValue{CurrentValue: 1}
	} else {
		handler.UserAgentOSFamilies[parsedLogEntry.UserAgent.OS].Increment(1)
	}

	if handler.Referers[parsedLogEntry.Referer] == nil {
		handler.Referers[parsedLogEntry.Referer] = &CounterValue{CurrentValue: 1}
	} else {
		handler.Referers[parsedLogEntry.Referer].Increment(1)
	}

	if handler.RequestedPaths[parsedLogEntry.Path] == nil {
		handler.RequestedPaths[parsedLogEntry.Path] = &CounterValue{CurrentValue: 1}
	} else {
		handler.RequestedPaths[parsedLogEntry.Path].Increment(1)
	}

	return true, nil
}

func (handler *CounterHandler) End() bool {

	if handler.tickerStopped != nil {
		handler.tickerStopped <- true
	}

	handler.PrintCounterData(false)
	return true
}

func (handler *CounterHandler) tickerTick() {
	slog.Debug("Starting ticker in CounterHandler")
	for {
		select {
		case <-handler.tickerStopped:
			handler.ticker.Stop()
			return
		case <-handler.ticker.C:
			handler.PrintCounterData(true)
			handler.startNewWindow()
		}
	}
}

func (handler *CounterHandler) startNewWindow() {
	slog.Debug("Starting new counting window")
	handler.syncMutex.Lock()
	defer handler.syncMutex.Unlock()

	handler.RequestsFromHumans.PreviousValue = handler.RequestsFromHumans.CurrentValue
	handler.RequestsFromNonHumans.PreviousValue = handler.RequestsFromNonHumans.CurrentValue
	handler.TotalBytesSent.PreviousValue = handler.TotalBytesSent.CurrentValue
	handler.TotalRequests.PreviousValue = handler.TotalRequests.CurrentValue
	handler.MaliciousRequests.PreviousValue = handler.MaliciousRequests.CurrentValue

	handler.ResetCountersInMapForNewWindow(handler.Clients)
	handler.ResetCountersInMapForNewWindow(handler.DeviceTypes)
	handler.ResetCountersInMapForNewWindow(handler.Methods)
	handler.ResetCountersInMapForNewWindow(handler.StatusCodes)
	handler.ResetCountersInMapForNewWindow(handler.UserAgentFamilies)
	handler.ResetCountersInMapForNewWindow(handler.UserAgentOSFamilies)
	handler.ResetCountersInMapForNewWindow(handler.Referers)
	handler.ResetCountersInMapForNewWindow(handler.RequestedPaths)
	handler.ResetCountersInMapForNewWindow(handler.RequestIntents)
}

func (handler *CounterHandler) ResetCountersInMapForNewWindow(theMap map[string]*CounterValue) {
	if theMap == nil {
		return
	}
	for _, v := range theMap {
		v.PreviousValue = v.CurrentValue
	}
}

func ShrinkCounterMapLeavingTopN(currentMap map[string]*CounterValue, topNSize int) map[string]*CounterValue {
	var countsToKeysMap map[int64]map[string]int64 = make(map[int64]map[string]int64)
	var countsForSorting []int64 = make([]int64, len(currentMap))

	for keyValue, counterValue := range currentMap {
		if countsToKeysMap[counterValue.CurrentValue] == nil {
			countsToKeysMap[counterValue.CurrentValue] = make(map[string]int64)
		}
		countsToKeysMap[counterValue.CurrentValue][keyValue] = counterValue.CurrentValue
	}
	countsForSorting = slices.Sorted(maps.Keys(countsToKeysMap))
	slices.Reverse(countsForSorting)
	addedElementCounter := 0
	newMapToReplace := make(map[string]*CounterValue)
	/*
		slog.Debug("ShrinkCounterMapLeavingTopN", "countsForSorting", countsForSorting)
		slog.Debug("ShrinkCounterMapLeavingTopN", "countsToKeysMap", countsToKeysMap)
		slog.Debug("ShrinkCounterMapLeavingTopN", "currentMap", currentMap)
	*/
outOf2Loops:
	for _, countValue := range countsForSorting {
		if countsToKeysMap[countValue] != nil {
			for keyVal2, _ := range countsToKeysMap[countValue] {
				if newMapToReplace[keyVal2] != nil {
					//this should not happen but anyway
					slog.Debug("Unexpected! key already exists in shrinked map", "key", keyVal2, "map", newMapToReplace)
					continue
				}
				newMapToReplace[keyVal2] = &CounterValue{CurrentValue: currentMap[keyVal2].CurrentValue, PreviousValue: currentMap[keyVal2].PreviousValue}
				addedElementCounter++
				if addedElementCounter >= topNSize {
					break outOf2Loops
				}
			}
		}
	}
	//slog.Debug("ShrinkCounterMapLeavingTopN", "newMapToReplace", newMapToReplace)
	return newMapToReplace
}

func (handler *CounterHandler) PrintCounterData(fromTicker bool) {
	fmt.Printf("---------%v---------", time.Now().UTC().Format(time.RFC3339))
	fmt.Println()
	if handler.isFollowing {
		fmt.Printf("Total log lines   : %v (%+d)", handler.HandledEntryCounter.CurrentValue, handler.HandledEntryCounter.CurrentValue-handler.HandledEntryCounter.PreviousValue)
	} else {
		fmt.Printf("Total log lines   : %v", handler.HandledEntryCounter.CurrentValue)
	}

	fmt.Println()
	if handler.isFollowing {
		fmt.Printf("Total requests    : %v (%+d)", handler.TotalRequests.CurrentValue, handler.TotalRequests.CurrentValue-handler.TotalRequests.PreviousValue)
	} else {
		fmt.Printf("Total requests    : %v", handler.TotalRequests.CurrentValue)
	}

	fmt.Println()
	if handler.isFollowing {
		fmt.Printf("Total bytes sent  : %v (%+d)", handler.TotalBytesSent.CurrentValue, handler.TotalBytesSent.CurrentValue-handler.TotalBytesSent.PreviousValue)
	} else {
		fmt.Printf("Total bytes sent  : %v", handler.TotalBytesSent.CurrentValue)
	}

	fmt.Println()
	if handler.RequestsFromHumans != nil {
		if handler.isFollowing {
			fmt.Printf("Requests by humans: %v (%+d)", handler.RequestsFromHumans.CurrentValue, handler.RequestsFromHumans.CurrentValue-handler.RequestsFromHumans.PreviousValue)
		} else {
			fmt.Printf("Requests by humans: %v", handler.RequestsFromHumans.CurrentValue)
		}
		fmt.Println()
	}
	if handler.RequestsFromNonHumans != nil {
		if handler.isFollowing {
			fmt.Printf("Non-human requests: %v (%+d)", handler.RequestsFromNonHumans.CurrentValue, handler.RequestsFromNonHumans.CurrentValue-handler.RequestsFromNonHumans.PreviousValue)
		} else {
			fmt.Printf("Non-human requests: %v", handler.RequestsFromNonHumans.CurrentValue)
		}
		fmt.Println()
	}
	if handler.MaliciousRequests != nil {
		if handler.isFollowing {
			fmt.Printf("Malicious requests: %v (%+d)", handler.MaliciousRequests.CurrentValue, handler.MaliciousRequests.CurrentValue-handler.MaliciousRequests.PreviousValue)
		} else {
			fmt.Printf("Malicious requests: %v", handler.MaliciousRequests.CurrentValue)
		}
		fmt.Println()
	}
	handler.printMapValue("Intents           :", handler.RequestIntents)

	handler.printMapValue("Status codes      :", handler.StatusCodes)

	handler.printMapValue("Methods           :", handler.Methods)
	handler.printMapValue("User agents       :", handler.UserAgentFamilies)
	handler.printMapValue("Operating systems :", handler.UserAgentOSFamilies)

	handler.Clients = ShrinkCounterMapLeavingTopN(handler.Clients, handler.topNWindowSize)
	handler.printMapValue("Clients           :", handler.Clients)

	handler.Referers = ShrinkCounterMapLeavingTopN(handler.Referers, handler.topNWindowSize)
	handler.printMapValue("Referers          :", handler.Referers)

	handler.RequestedPaths = ShrinkCounterMapLeavingTopN(handler.RequestedPaths, handler.topNWindowSize)
	handler.printMapValue("Requested Path    :", handler.RequestedPaths)

	fmt.Println()

}

func (handler *CounterHandler) printMapValue(header string, m map[string]*CounterValue) {
	if m == nil {
		return
	}
	maxLabelLen := 10
	mapAsList := make([]CounterMapEntry, len(m))

	{
		j := 0
		for k, v := range m {
			mapAsList[j] = CounterMapEntry{key: k, value: v}
			if len(k) > maxLabelLen {
				maxLabelLen = len(k)
			}
			j++
		}
	}
	if maxLabelLen > 15 {
		maxLabelLen = 15
	}
	slices.SortFunc(mapAsList, func(a, b CounterMapEntry) int {
		if a.value.CurrentValue < b.value.CurrentValue {
			return -1
		}
		if a.value.CurrentValue > b.value.CurrentValue {
			return 1
		}
		return 0
	})
	slices.Reverse(mapAsList)

	i := 0
	indent := strings.Repeat(" ", len(header))
	linePrefix := header
	for _, mapEntry := range mapAsList {
		keyValueToPrint := mapEntry.key
		if len(keyValueToPrint) < 1 {
			keyValueToPrint = "-not set-"
		}
		if handler.isFollowing {
			fmt.Printf("%s %-*v:%6v (%+d)", linePrefix, maxLabelLen+1, keyValueToPrint, mapEntry.value.CurrentValue, mapEntry.value.CurrentValue-mapEntry.value.PreviousValue)
		} else {
			fmt.Printf("%s %-*v:%6v", linePrefix, maxLabelLen+1, keyValueToPrint, mapEntry.value.CurrentValue)
		}
		fmt.Println()
		if i == 0 {
			linePrefix = indent
		}
		i++
	}
}

/*
//TODO this works but leaving formatting to later
type ConsoleWinsize struct {
	Rows    uint16
	Cols    uint16
	Xpixels uint16 // Unused for most purposes
	Ypixels uint16 // Unused for most purposes
}

func getTerminalWidth() (int, error) {
	ws := &ConsoleWinsize{}
	// syscall.TIOCGWINSZ is the ioctl command to get window size.
	// os.Stdout.Fd() gets the file descriptor for standard output (the terminal).
	// unsafe.Pointer(ws) casts the Winsize struct to a pointer for ioctl.
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(ws))); err != 0 {
		return 0, fmt.Errorf("could not get terminal size: %w", err)
	}
	return int(ws.Cols), nil
}
*/
