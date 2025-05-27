package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/SBOsoft/SBOLogProcessor/logparsers"
	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

type SBOLogProcessorConfig struct {
	follow            bool
	windowSizeMinutes int
	//where 0=beginning -1=end and >0 means line number from beginning
	startFrom int
	//if domain name is not available in logs, e.g separate log file per domain configured
	domainName string
}

const START_FROM_BEGINNING int = 0
const START_FROM_END int = -1

var globalConfig = SBOLogProcessorConfig{
	follow:            false,
	startFrom:         START_FROM_BEGINNING,
	windowSizeMinutes: 1,
	domainName:        ""}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Please provide a file path as argument")
	}
	configureLogging()
	parseCommandArgs()

	var wg sync.WaitGroup

	filePath := flag.Arg(0)
	processFile(filePath, &wg)

	wg.Wait()

	slog.Info("Currrent metrics", "allMetrics", metrics.GetAllMetrics())

}

func parseCommandArgs() {
	followPtr := flag.Bool("f", false, "Follow changes to the file, as in tail -f")
	windowSizePtr := flag.Int("w", 1, "Statistics window size in minutes, e.g to report request statistics for every 5 minute window. Defaults to 300, 5 minute")
	startFromPtr := flag.Int("s", START_FROM_BEGINNING, "When 0, file will be processed starting from the beginning. When -1, file will be processed starting from the end (i.e only lines appended after the program starts will be processed). Defaults to 0")
	domainPtr := flag.String("d", "", "Domain name to report, needed when domain names are not available in logs")

	flag.Parse()

	globalConfig.follow = *followPtr
	globalConfig.startFrom = *startFromPtr
	/*
		if globalConfig.startFrom != START_FROM_BEGINNING && globalConfig.startFrom != START_FROM_END {
			slog.Warn("Invalid -s parameter, assuming 0", "invalidValue", globalConfig.startFrom)
			globalConfig.startFrom = START_FROM_BEGINNING
		}
	*/
	globalConfig.windowSizeMinutes = *windowSizePtr

	globalConfig.domainName = *domainPtr

	slog.Info("Starting app with configuration", "config", globalConfig)
}

func processFile(filePath string, wg *sync.WaitGroup) {

	lines := make(chan string, 10) // Buffered channel to prevent blocking
	wg.Add(1)
	wg.Add(1)
	// Start consumer
	go consumeLinesFromChannel(filePath, lines, wg)

	// Start producer
	produceLinesFromFile(filePath, lines)
	defer wg.Done()
}

func configureLogging() {
	////////log config
	slog.SetLogLoggerLevel(slog.LevelDebug)
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(logHandler))
	log.SetFlags(log.Ldate | log.Lmicroseconds)
	//disable all logging
	//slog.SetLogLoggerLevel(math.MaxInt)

}

func consumeLinesFromChannel(filePath string, theChannel chan string, wg *sync.WaitGroup) {
	var processedLineCount, errorCount int
	var parserFunction func(string) (*logparsers.SBOHttpRequestLog, error) = nil
	var lineResult bool

	defer wg.Done()

	slog.Debug("Start consumer in consumeLinesFromChannel", "filePath", filePath)
	for line := range theChannel {
		lineResult, parserFunction = processSingleLogLine(filePath, line, parserFunction)
		if lineResult {
			processedLineCount++
		} else {
			errorCount++
		}
		/*
			if processedLineCount%5 == 0 {
				slog.Info("Currrent metrics", "allMetrics", metrics.GetAllMetricsForFile(filePath))
			}
		*/
	}
	slog.Info("Currrent metrics", "allMetrics", metrics.GetAllMetricsForFile(filePath))
	slog.Info("consumeLinesFromChannel finished", "processedLineCount", processedLineCount, "errorCount", errorCount)

}

func processSingleLogLine(filePath string, logLine string, parserFunction func(string) (*logparsers.SBOHttpRequestLog, error)) (bool, func(string) (*logparsers.SBOHttpRequestLog, error)) {
	if len(logLine) < 1 {
		return false, parserFunction
	}
	var parseResult *logparsers.SBOHttpRequestLog
	var parseErr error

	if parserFunction == nil {
		// Try parsing with each format
		formats := []struct {
			name string
			fn   func(string) (*logparsers.SBOHttpRequestLog, error)
		}{
			{"Apache Common Log Format", logparsers.ParseApacheCommonLogFormat},
			{"Apache Combined Log Format", logparsers.ParseApacheCombinedLogFormat},
			//{"Apache VHost Combined Log Format", logparsers.ParseApacheVHostCombinedLogFormat},
		}
		slog.Debug("parserFunction not set, trying to find a match")

		for _, format := range formats {
			parseResult, parseErr := format.fn(logLine)
			if parseResult != nil && parseErr == nil {
				parserFunction = format.fn
				slog.Debug("***************************** Successfully parsed as format. Will use this format for this file going forward ********************", "format", format.name)
			}
		}
	} else {
		parseResult, parseErr = parserFunction(logLine)
	}
	if parseResult != nil {
		if parseErr != nil {
			//invalid line
			return false, parserFunction
		} else {
			//slog.Debug("Parse success", "parsed", parseResult)
			//now calculate stats
			processMetricsForRequestLogEntry(filePath, parseResult)
			return true, parserFunction
		}

	}
	return false, parserFunction
}

func processMetricsForRequestLogEntry(filePath string, parseResult *logparsers.SBOHttpRequestLog) {
	metrics.AddMetric(filePath, metrics.SBO_METRIC_REQ_COUNT, "", parseResult.Timestamp, 1)
	metrics.AddMetric(filePath, metrics.SBO_METRIC_BYTES_SENT, "", parseResult.Timestamp, int64(parseResult.BytesSent))
	metrics.AddMetric(filePath, metrics.SBO_METRIC_HTTP_STATUS, parseResult.Status, parseResult.Timestamp, 1)
	metrics.AddMetric(filePath, metrics.SBO_METRIC_UNIQUE_IP, parseResult.ClientIP, parseResult.Timestamp, 1)
	metrics.AddMetric(filePath, metrics.SBO_METRIC_METHOD, parseResult.Method, parseResult.Timestamp, 1)

}

func produceLinesFromFile(filePath string, lines chan<- string) {
	slog.Debug("Enter produceLinesFromFile for file", "filePath", filePath)
	var watcher *fsnotify.Watcher
	slog.Debug("produceLinesFromFile global config", "globalConfig", globalConfig)
	defer close(lines)

	var watcherErr error
	if globalConfig.follow {
		watcher, watcherErr = fsnotify.NewWatcher()
		if watcherErr != nil {
			slog.Error("Error setting up fsnotify.NewWatcher", "filePath", filePath, "error", watcherErr)
			return
		}
		defer watcher.Close()

		// Watch the directory containing the file
		dir := filepath.Dir(filePath)
		watcherErr = watcher.Add(dir)
		if watcherErr != nil {
			slog.Error("Error adding watcher", "filePath", filePath, "error", watcherErr)
			return
		}
		slog.Debug("Set up watcher", "dir", dir, "watchlist", watcher.WatchList())

	}
	baseNameForFile := filepath.Base(filePath)
	var file *os.File
	var fileReader *bufio.Reader
	var err error
	// Initial file open
	if err, file, fileReader = openFile(false, filePath); err != nil {
		slog.Error("Error opening file", "filePath", filePath, "error", err)
		return
	}
	var waitingForNewData bool = false
	var isFileAtEnd bool = false

	for {

		if fileReader != nil {
			if !waitingForNewData { //dont even try to read if just waiting
				isFileAtEnd = readSingleLineFromFile(filePath, lines, fileReader)
				if isFileAtEnd && !globalConfig.follow {
					slog.Info("Finished reading the file and not following, so done...")
					close(lines)
					return
				}
				if isFileAtEnd {
					waitingForNewData = true
					file.Seek(0, 2)
					fileReader.Reset(file)
					//slog.Debug("readSingleLineFromFile isFileAtEnd", "isFileAtEnd", isFileAtEnd)
				}
			} else {
				//slog.Warn("waitingForNewData is true in produceLinesFromFile")
			}

		} else {
			slog.Warn("fileReader is nil", "filePath", filePath)
			break
		}

		if globalConfig.follow {
			//slog.Warn("follow in produceLinesFromFile before select")
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					slog.Info("watcher.Events not ok", "event", event)
					return
				}
				//slog.Debug("fsnotify event ", "event", event)
				if filepath.Base(event.Name) != baseNameForFile {
					//irrelevant event
					continue
				}

				if event.Has(fsnotify.Write) {
					// File was modified, continue reading, normal case
					slog.Info("File was modified after receiving EOF in the previous read. Continue reading", "file", filePath)
					waitingForNewData = false
					continue
				}

				if event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
					// File was renamed/removed (log rotation)
					slog.Info("File was renamed/removed (log rotation)", "file", filePath)

					// read file to end before switching
					readFileToEnd(filePath, lines, fileReader)

					file.Close()

					waitingForNewData = false
					// Try to reopen the file
					for i := 0; i < 5; i++ {
						if err, file, fileReader = openFile(true, filePath); err == nil {
							break
						}
						time.Sleep(1 * time.Second)
					}
					if fileReader == nil {
						slog.Warn("File was renamed/removed (log rotation) but could not be reopened", "file", filePath)
						return
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					slog.Error("Watcher error", "error", err)
					return
				}

			default:
				if waitingForNewData {
					//slog.Warn("wait while waitingForNewData", "waitingForNewData", waitingForNewData)
					time.Sleep(1000 * time.Millisecond)
				}
				continue
			}
		}
	}
}

func openFile(reopeningAfterRotate bool, filePath string) (error, *os.File, *bufio.Reader) {
	var err error
	var file *os.File
	var fileReader *bufio.Reader

	file, err = os.Open(filePath)

	fileReader = nil

	if err != nil {
		slog.Error("Error opening file", "filePath", filePath, "error", err)
		return err, file, fileReader
	}

	if reopeningAfterRotate || globalConfig.startFrom == START_FROM_BEGINNING {
		// Seek to beginning if file exists
		_, err = file.Seek(0, 0)
		if err != nil {
			file.Close()
			slog.Error("Error seeking to beginning of file", "filePath", filePath, "error", err)
			return err, file, fileReader
		}
	} else if globalConfig.startFrom == START_FROM_END || globalConfig.startFrom < 0 {
		// Seek to end if file exists
		_, err = file.Seek(0, 2)
		if err != nil {
			file.Close()
			slog.Error("Error seeking to end of file", "filePath", filePath, "error", err)
			return err, file, fileReader
		}
	} else {
		//skip until the line
		fileReader = bufio.NewReaderSize(file, 8192)
		lineNo := 1
		for {
			_, err := fileReader.ReadString('\n')
			lineNo++
			if lineNo >= globalConfig.startFrom {
				break
			}
			if err != nil {
				break
			}
		}
	}

	if fileReader == nil {
		fileReader = bufio.NewReaderSize(file, 8192)
	}

	return nil, file, fileReader
}

func readFileToEnd(filePath string, lines chan<- string, fileReader *bufio.Reader) {
	slog.Debug("Read file to end ", "filePath", filePath)
	for {
		if !readSingleLineFromFile(filePath, lines, fileReader) {
			slog.Debug("Read file to end DONE", "filePath", filePath)
			return
		}
	}
}

func readSingleLineFromFile(filePath string, lines chan<- string, fileReader *bufio.Reader) bool {
	bytesRead, err := fileReader.ReadString('\n')
	if len(bytesRead) > 0 {
		theLine := strings.TrimSpace(string(bytesRead[:]))
		//slog.Debug("Read line:", "filePath", filePath, "line", theLine)
		lines <- theLine
	}
	if err != nil {
		//slog.Debug("fileReader error", "filePath", filePath, "error", err)
		return io.EOF == err
	}
	return false
}
