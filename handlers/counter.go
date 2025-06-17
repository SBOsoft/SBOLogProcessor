package handlers

import (
	"fmt"
	"log/slog"
	"strings"
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

func (cv *CounterValue) Increment(value int64) {
	cv.CurrentValue += value
}

func (cv *CounterValue) NextWindow(value int64) {
	cv.PreviousValue = cv.CurrentValue
	cv.CurrentValue = value
}

type CounterHandler struct {
	filePath              string
	HandledEntryCounter   int
	TotalRequests         *CounterValue
	TotalBytesSent        *CounterValue
	StatusCodes           map[string]*CounterValue
	Methods               map[string]*CounterValue
	Clients               map[string]*CounterValue
	UserAgentFamilies     map[int]*CounterValue
	UserAgentOSFamilies   map[int]*CounterValue
	DeviceTypes           map[int]*CounterValue
	RequestsFromNonHumans *CounterValue
	RequestsFromHumans    *CounterValue
	dataToBeSavedChannel  chan *metrics.SBOMetricWindowDataToBeSaved
	ticker                *time.Ticker
	tickerStopped         chan (bool)
}

func NewCounterHandler(filePath string) *CounterHandler {

	var rv = CounterHandler{
		filePath:            filePath,
		Clients:             make(map[string]*CounterValue),
		Methods:             make(map[string]*CounterValue),
		StatusCodes:         make(map[string]*CounterValue),
		UserAgentFamilies:   make(map[int]*CounterValue),
		UserAgentOSFamilies: make(map[int]*CounterValue),
		DeviceTypes:         make(map[int]*CounterValue)}

	return &rv
}

func (handler *CounterHandler) Name() string {
	return COUNTER_HANDLER_NAME
}

func (handler *CounterHandler) Begin(dataToSaveChan chan *metrics.SBOMetricWindowDataToBeSaved, following bool) error {
	handler.dataToBeSavedChannel = dataToSaveChan
	if following {
		slog.Debug("CounterHandler.Begin following is true, starting ticker")
		handler.ticker = time.NewTicker(30 * time.Second)
		handler.tickerStopped = make(chan bool)
		go handler.tickerTick()
	} else {
		slog.Debug("CounterHandler.Begin following is FALSE, NOT starting ticker")
	}

	return nil
}

// TODO decide how we will save generated metrics
func (handler *CounterHandler) HandleEntry(parsedLogEntry *logparsers.SBOHttpRequestLog) (bool, error) {
	handler.HandledEntryCounter++
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
		}
	}
}

func (handler *CounterHandler) PrintCounterData(fromTicker bool) {
	fmt.Println("-----------------------------")
	fmt.Printf("Total log lines   : %v", handler.HandledEntryCounter)
	fmt.Println()
	fmt.Printf("Total bytes sent  : %v (%v +%v)", handler.TotalBytesSent.CurrentValue, handler.TotalBytesSent.PreviousValue, handler.TotalBytesSent.CurrentValue-handler.TotalBytesSent.PreviousValue)
	fmt.Println()
	fmt.Printf("Total requests    : %v", handler.TotalRequests.CurrentValue)
	fmt.Println()
	if handler.RequestsFromHumans != nil {
		fmt.Printf("Requests by humans: %v", handler.RequestsFromHumans.CurrentValue)
		fmt.Println()
	}
	if handler.RequestsFromNonHumans != nil {
		fmt.Printf("Non-human requests: %v", handler.RequestsFromNonHumans.CurrentValue)
		fmt.Println()
	}
	handler.printMapValue("Status codes      :", handler.StatusCodes)

	handler.printMapValue("Methods           :", handler.Methods)
	//handler.printMapValue("User agents       :", handler.UserAgentFamilies)
	//handler.printMapValue("Operating systems :", handler.UserAgentOSFamilies)
	fmt.Println()
	fmt.Println("-----------------------------")

}

func (handler *CounterHandler) printMapValue(header string, m map[string]*CounterValue) {
	if m == nil {
		return
	}
	i := 0
	indent := strings.Repeat(" ", len(header))
	linePrefix := header
	for k, v := range m {
		fmt.Printf("%s %-5v:%5v (%v)", linePrefix, k, v.CurrentValue, v.CurrentValue-v.PreviousValue)
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
