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

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/SBOsoft/SBOLogProcessor/db"
	"github.com/SBOsoft/SBOLogProcessor/handlers"
	"github.com/SBOsoft/SBOLogProcessor/logparsers"
	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

const (
	SBO_GLOBAL_PROFILE_METRICS      string = "metrics"
	SBO_GLOBAL_PROFILE_COUNT        string = "count"
	SBO_GLOBAL_PROFILE_SECURITY     string = "security"
	COUNTER_TOPN_SIZE_DEFAULT       int    = 10
	COUNTER_OUTPUT_INTERVAL_DEFAULT int    = 30

	SBO_LOGP_LOG_FILE string = "./sbologp-logs.log"
)

const DEFAULT_CONFIG_KEY string = "--default--"

var globalConfig map[string]ConfigForAMonitoredFile = make(map[string]ConfigForAMonitoredFile)
var globalActiveProfile string = SBO_GLOBAL_PROFILE_METRICS
var globalActiveLogLevel slog.Level = slog.LevelInfo

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Please provide a file path as argument")
	}

	parseCommandArgs()

	var logFile *os.File = configureLogging(globalActiveLogLevel)
	if logFile != nil {
		defer logFile.Close()
	}

	slog.Info("Starting app with configuration:")
	for fp, cfg := range globalConfig {
		slog.Info("File", "filePath", fp, "configuration", cfg)
	}

	var wg sync.WaitGroup

	for filePath, _ := range globalConfig {
		wg.Add(1)
		go processFile(filePath, &wg)
	}

	wg.Wait()

}

func getConfigForFile(filePath string) *ConfigForAMonitoredFile {
	foundConfig, ok := globalConfig[filePath]
	if !ok {
		foundConfig, ok = globalConfig[DEFAULT_CONFIG_KEY]
	}

	if !ok {
		slog.Warn("Failed to find configuration for file", "filePath", filePath)
	}

	return &foundConfig
}

/*
This function will run before logging is set up. Don't use slog here yet
*/
func parseCommandArgs() {
	logLevelPtr := flag.String("l", "info", "Log level. Defaults to info. Supported values are: debug, info, warn.")
	profilePtr := flag.String("p", "metrics", "Active profile. Defaults to metrics which will create metrics. Available options are: metrics, count, security. Where count will output total stats from the given file and security will output malicious IPs and security stats.")
	confFilePtr := flag.String("c", "", "Configuration file in json format. There is no default value but you will want to pass a config file when -m=metrics. ")

	followPtr := flag.Bool("f", false, "Follow changes to the file, as in tail -f")
	windowSizePtr := flag.Int("w", 1, "Statistics window size in minutes, e.g to report request statistics for every 5 minute window.")
	startFromPtr := flag.Int("s", START_FROM_BEGINNING, "When 0, file will be processed starting from the beginning. When -1, file will be processed starting from the end (i.e only lines appended after the program starts will be processed). Defaults to 0")
	domainPtr := flag.String("d", "", "Domain name to report, needed when domain names are not available in logs")
	handlerPtr := flag.String("a", "", "Enabled handler name, defaults to METRICS. Note: It's NOT possible to pass multiple handlers using command line parameters, you need to use a configuration file if you need to enable multiple handlers.")
	writeToFileTargetPtr := flag.String("t", "", "Target file path, required when handler is WRITE_TO_FILE")

	counterTopNPtr := flag.Int("n", COUNTER_TOPN_SIZE_DEFAULT, "Applies to count profile only: Number of items (such as IP addresses, referers, paths) to be displayed. Only the top n items will be displayed in the output.")
	counterOutputIntervalPtr := flag.Int("i", COUNTER_OUTPUT_INTERVAL_DEFAULT, "Applies to count profile only: Number of seconds between successive count outputs")

	helpPtr := flag.Bool("h", false, "Show command line parameters")

	flag.Parse()

	if *helpPtr {
		fmt.Println()
		fmt.Println("SBOLogProcessor command line tool for monitoring web server access logs and more. See https://github.com/SBOsoft/SBOLogProcessor for more details")
		fmt.Println("Passing a configuration file using -c parameter is the recommended method for providing configuration options.")
		fmt.Println("Command line arguments should suffice for the counter profile BUT a command line parameter for every possible configuration option may NOT be available.")
		fmt.Println()
		fmt.Println("Usage: 'sbologp [command line options, e.g -f -p=metrics] access-log-file-path' OR 'sbologp -c path-to-config-file.json'")
		fmt.Println("For example: ./sbologp -f -p=count /var/log/apache/access.log OR ./sbologp -c sbologp-config.json")
		flag.PrintDefaults()
		os.Exit(0)
	}

	switch *logLevelPtr {
	case "info":
		globalActiveLogLevel = slog.LevelInfo
	case "warn":
		globalActiveLogLevel = slog.LevelWarn
	case "debug":
		globalActiveLogLevel = slog.LevelDebug
	}

	globalActiveProfile = *profilePtr
	if globalActiveProfile != SBO_GLOBAL_PROFILE_COUNT &&
		globalActiveProfile != SBO_GLOBAL_PROFILE_METRICS &&
		globalActiveProfile != SBO_GLOBAL_PROFILE_SECURITY {
		fmt.Printf("Invalid profile value (invalid -p parameter): '%s' ", globalActiveProfile)
		fmt.Println()
		fmt.Println("Use -h parameter to view command line options")
		//flag.PrintDefaults()
		os.Exit(1)
	}

	configFileName := *confFilePtr
	loadedConfigFromFile := false

	if len(configFileName) > 0 {
		loadedConfigFromFile = loadConfigFromFile(configFileName)
	}

	if !loadedConfigFromFile {
		if len(flag.Arg(0)) > 0 {
			handlerName := *handlerPtr
			//default handlers for profiles
			if len(handlerName) < 1 {
				if globalActiveProfile == SBO_GLOBAL_PROFILE_COUNT {
					handlerName = handlers.COUNTER_HANDLER_NAME
				} else if globalActiveProfile == SBO_GLOBAL_PROFILE_METRICS {
					handlerName = handlers.METRIC_GENERATOR_HANDLER_NAME
				}
			}

			//Creating config here is not the best way to invoke the program
			var cfFromCmdLine = ConfigForAMonitoredFile{
				Follow:                *followPtr,
				StartFrom:             *startFromPtr,
				TimeWindowSizeMinutes: *windowSizePtr,

				DomainName: *domainPtr,

				Handlers: []string{handlerName}, //<- only 1 handler is supported

				FilePath:              flag.Arg(0),
				WriteToFileTargetFile: *writeToFileTargetPtr,

				HandlerInstances: make(map[string]SBOLogHandlerInterface, 1),

				WriteMetricsToDb:             false,
				DbAddress:                    "",
				DbUser:                       "",
				DbPassword:                   "",
				DbDatabase:                   "",
				ReplaceExistingMetrics:       true,
				MetricsWindowSize:            3,
				CounterTopNForKeyedMetrics:   *counterTopNPtr,
				CounterOutputIntervalSeconds: *counterOutputIntervalPtr}

			globalConfig[cfFromCmdLine.FilePath] = cfFromCmdLine
		} else {
			fmt.Println("Invalid options, cannot continue, missing log file path. Either a configuration file or command line parameters are required. Use -h parameter to view command line options. See https://github.com/SBOsoft/SBOLogProcessor for more details")
			os.Exit(1)
		}

	}
}

func loadConfigFromFile(configFileName string) bool {
	loadedConfigFromFile := false
	var configLoadedFromFile map[string]ConfigForAMonitoredFile = make(map[string]ConfigForAMonitoredFile)
	fileInfo, err := os.Stat(configFileName)
	if os.IsNotExist(err) {
		//no config file provided
		slog.Error("Configuration file path parameter, -c, points to non-existent file. It must point to a json file. Ignoring parameter", "file", configFileName)
	} else {
		if fileInfo.IsDir() {
			slog.Error("Configuration file path parameter, -c, points to a directory. It must point to a json file. Ignoring parameter")
		} else {
			configFileBytes, err := os.ReadFile(configFileName)
			if err != nil {
				slog.Error("Failed to read configuration file", "file", configFileName, "error", err)
			} else {
				err := json.Unmarshal(configFileBytes, &configLoadedFromFile)
				if err != nil {
					slog.Error("Failed to load configuration from file", "file", configFileName, "error", err)
				} else {
					loadedConfigFromFile = true
					for fp, conf := range configLoadedFromFile {
						//validation and defaults
						if conf.CounterOutputIntervalSeconds < 1 {
							conf.CounterOutputIntervalSeconds = 30
						}
						if conf.CounterTopNForKeyedMetrics < 1 || conf.CounterTopNForKeyedMetrics > 100 {
							conf.CounterTopNForKeyedMetrics = 10
						}
						windowSizeToUse := conf.MetricsWindowSize
						if conf.MetricsWindowSize < 2 || conf.MetricsWindowSize > 10 {
							//allow sensible values only
							windowSizeToUse = 3
						}
						globalConfig[fp] = ConfigForAMonitoredFile{
							Enabled:                      conf.Enabled,
							FilePath:                     conf.FilePath,
							Handlers:                     conf.Handlers,
							StartFrom:                    conf.StartFrom,
							SkipIfLineMatchesRegex:       conf.SkipIfLineMatchesRegex,
							Follow:                       conf.Follow,
							DomainName:                   conf.DomainName,
							HostId:                       conf.HostId,
							TimeWindowSizeMinutes:        conf.TimeWindowSizeMinutes,
							WriteToFileTargetFile:        conf.WriteToFileTargetFile,
							HandlerInstances:             make(map[string]SBOLogHandlerInterface),
							WriteMetricsToDb:             conf.WriteMetricsToDb,
							DbAddress:                    conf.DbAddress,
							DbUser:                       conf.DbUser,
							DbPassword:                   conf.DbPassword,
							DbDatabase:                   conf.DbDatabase,
							ReplaceExistingMetrics:       conf.ReplaceExistingMetrics,
							MetricsWindowSize:            windowSizeToUse,
							CounterTopNForKeyedMetrics:   conf.CounterTopNForKeyedMetrics,
							CounterOutputIntervalSeconds: conf.CounterOutputIntervalSeconds,
							SaveLogsToDb:                 conf.SaveLogsToDb,
							SaveLogsToDbMaskIPs:          conf.SaveLogsToDbMaskIPs,
							SaveLogsToDbOnlyRelevant:     conf.SaveLogsToDbOnlyRelevant}

					}
					slog.Debug("Loaded config from file", "file", configFileName)
				}
			}
		}
	}
	return loadedConfigFromFile
}

func createHandler(filePath string, handlerName string, dataToSaveChan chan *metrics.SBOMetricWindowDataToBeSaved, metricsManager *metrics.SBOMetricsManager) SBOLogHandlerInterface {
	config := getConfigForFile(filePath)
	switch {
	case handlerName == handlers.WRITE_TO_FILE_HANDLER_NAME:
		writeToFile := handlers.NewWriteToFileHandler()
		err := writeToFile.Begin(config.WriteToFileTargetFile)
		slog.Info("Created WriteToFileHandler", "error", err)
		return writeToFile
	case handlerName == handlers.METRIC_GENERATOR_HANDLER_NAME:
		metricsGenerator := handlers.NewMetricGeneratorHandler(filePath, metricsManager, config.TimeWindowSizeMinutes)
		metricsGenerator.Begin(dataToSaveChan)
		slog.Info("Created MetricGeneratorHandler")
		return metricsGenerator
	case handlerName == handlers.COUNTER_HANDLER_NAME:
		counterHandler := handlers.NewCounterHandler(filePath)
		counterHandler.Begin(dataToSaveChan,
			config.Follow,
			config.CounterOutputIntervalSeconds,
			config.CounterTopNForKeyedMetrics)
		slog.Info("Created CounterHandler")
		return counterHandler
	}
	slog.Warn("createHandler failed no handler for handler name", "handlerName", handlerName)
	return nil
}

func processFile(filePath string, parentWaitGroup *sync.WaitGroup) {
	defer parentWaitGroup.Done()
	config := getConfigForFile(filePath)
	lines := make(chan string, 10) // Buffered channel to prevent blocking
	dataToBeSavedChannel := make(chan *metrics.SBOMetricWindowDataToBeSaved, 100)

	sbodb := db.NewSBOAnalyticsDB()
	if config.WriteMetricsToDb || config.SaveLogsToDb {
		//if not writing to db then db stuff is unnecessary
		defer sbodb.Close()
		sbodb.Init(config.DbUser, config.DbPassword, config.DbAddress, config.DbDatabase)
	}

	var waitGroupForThisFile sync.WaitGroup
	waitGroupForThisFile.Add(1)
	// Start consumer (producer -> consumer -> save data) consumer generates metrics etc
	go consumeLinesFromChannel(filePath, lines, &waitGroupForThisFile, dataToBeSavedChannel, sbodb)

	waitGroupForThisFile.Add(1)

	// Start goroutine for saving data
	go processMetricDataToBeSaved(filePath, dataToBeSavedChannel, &waitGroupForThisFile, sbodb)

	// Start producer
	produceLinesFromFile(filePath, lines)

	//WaitGroup specific to the file
	waitGroupForThisFile.Wait()
	slog.Info("Finished processing file", "file", filePath)
}

func configureLogging(logLevel slog.Level) *os.File {
	////////log config
	slog.SetLogLoggerLevel(logLevel)
	log.SetFlags(log.Ldate | log.Lmicroseconds)

	logFile, err := os.OpenFile(SBO_LOGP_LOG_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// If we can't open the log file, log to stderr and exit.
		slog.Error(fmt.Sprintf("Failed to open log file '%v'. Will log to stderr instead", SBO_LOGP_LOG_FILE), "error", err)
		logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
		slog.SetDefault(slog.New(logHandler))
		return nil
	} else {
		logHandler := slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: logLevel})
		slog.SetDefault(slog.New(logHandler))
		return logFile
	}
}

/*
Save metric data
*/
func processMetricDataToBeSaved(filePath string, dataToBeSavedChannel chan *metrics.SBOMetricWindowDataToBeSaved, wg *sync.WaitGroup, sbodb *db.SBOAnalyticsDB) {

	defer wg.Done()
	config := getConfigForFile(filePath)
	for dataToSave := range dataToBeSavedChannel {
		if !config.WriteMetricsToDb {
			//nothing to do here, just move
			continue
		}
		domainName := config.DomainName
		if len(dataToSave.DomainName) > 0 {
			domainName = dataToSave.DomainName
		}

		domainId, _ := sbodb.GetDomainId(domainName, config.TimeWindowSizeMinutes)
		/*
			if domainId < 1 {
				slog.Warn("domainId < 1 for data", "data", dataToSave)
			}
		*/
		sbodb.SaveMetricData(dataToSave, domainId, config.ReplaceExistingMetrics)
		slog.Debug("processMetricDataToBeSaved save data:", "dataToSave", dataToSave)
	}

	slog.Debug("processMetricDataToBeSaved done")
}

func consumeLinesFromChannel(filePath string, linesChannel chan string, wg *sync.WaitGroup, dataToBeSavedChannel chan *metrics.SBOMetricWindowDataToBeSaved, sbodb *db.SBOAnalyticsDB) {
	var processedLineCount, errorCount int
	var parserFunction func(string) (*logparsers.SBOHttpRequestLog, error) = nil
	var lineResult bool
	config := getConfigForFile(filePath)
	//*metrics.SBOMetricsManager
	metricsManager := metrics.NewSBOMetricsManager(config.MetricsWindowSize)

	for _, handlerName := range config.Handlers {
		config.HandlerInstances[handlerName] = createHandler(filePath, handlerName, dataToBeSavedChannel, metricsManager)
	}

	defer wg.Done()
	defer close(dataToBeSavedChannel)

	slog.Debug("Start consumer in consumeLinesFromChannel", "filePath", filePath)
	for line := range linesChannel {
		lineResult, parserFunction = processSingleLogLine(filePath, line, parserFunction, dataToBeSavedChannel, sbodb)
		if lineResult {
			processedLineCount++
		} else {
			errorCount++
		}
	}

	for _, h := range config.HandlerInstances {
		h.End()
	}

	slog.Info("consumeLinesFromChannel finished", "processedLineCount", processedLineCount, "errorCount", errorCount)

}

func processSingleLogLine(filePath string, logLine string,
	parserFunction func(string) (*logparsers.SBOHttpRequestLog, error),
	dataToBeSavedChannel chan *metrics.SBOMetricWindowDataToBeSaved,
	sbodb *db.SBOAnalyticsDB) (bool, func(string) (*logparsers.SBOHttpRequestLog, error)) {
	if len(logLine) < 1 {
		return false, parserFunction
	}
	var parseResult *logparsers.SBOHttpRequestLog
	var parseErr error
	config := getConfigForFile(filePath)

	if parserFunction == nil {
		// Try parsing with each format
		formats := []struct {
			name string
			fn   func(string) (*logparsers.SBOHttpRequestLog, error)
		}{
			//TODO add formats and parsers here
			{"Apache Common Log Format", logparsers.ParseApacheCommonLogFormat},
			{"Apache Combined Log Format", logparsers.ParseApacheCombinedLogFormat},
			{"Apache VHost Combined Log Format", logparsers.ParseApacheVHostCombinedLogFormat},
			{"Nginx Combined Log Format", logparsers.ParseNginxCombinedFormat},
			{"Nginx Custom Log Format", logparsers.ParseNginxCustomFormat},
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
			//now calculate stats or do whatever needs to be done
			callHandlersForRequestLogEntry(filePath, parseResult, dataToBeSavedChannel)
			//save log to db
			if config.SaveLogsToDb && sbodb != nil && sbodb.IsInitialized {
				var domainId int = 0
				if len(parseResult.Domain) > 0 {
					domainId, _ = sbodb.GetDomainId(parseResult.Domain, config.TimeWindowSizeMinutes)
				} else {
					domainId, _ = sbodb.GetDomainId(config.DomainName, config.TimeWindowSizeMinutes)
				}
				if config.SaveLogsToDbOnlyRelevant == 1 {
					//save only if not irrelevant
					if (parseResult.Malicious == logparsers.REQUEST_MALICIOUS_UNKNOWN) &&
						(strings.HasPrefix(parseResult.Status, "2") || strings.HasPrefix(parseResult.Status, "5")) &&
						parseResult.UserAgent.DeviceType != logparsers.DeviceType_Script &&
						(parseResult.UserAgent.Family != logparsers.UAFamily_Scanner &&
							parseResult.UserAgent.Family != logparsers.UAFamily_SEOBot &&
							//parseResult.UserAgent.Family != logparsers.UAFamily_SocialBot &&
							//parseResult.UserAgent.Family != logparsers.UAFamily_SearchBot &&
							parseResult.UserAgent.Family != logparsers.UAFamily_Script) {
						sbodb.SaveRawLog(parseResult, domainId, config.HostId, config.SaveLogsToDbMaskIPs)
					}
				} else {
					sbodb.SaveRawLog(parseResult, domainId, config.HostId, config.SaveLogsToDbMaskIPs)
				}

			}
			return true, parserFunction
		}

	}
	return false, parserFunction
}

func callHandlersForRequestLogEntry(filePath string, parsedLogEntry *logparsers.SBOHttpRequestLog, dataToBeSavedChannel chan *metrics.SBOMetricWindowDataToBeSaved) {
	//processMetricsForRequestLogEntry(filePath, parsedLogEntry)
	config := getConfigForFile(filePath)
	for _, h := range config.HandlerInstances {
		h.HandleEntry(parsedLogEntry)
	}

}

func produceLinesFromFile(filePath string, lines chan<- string) {
	slog.Debug("Enter produceLinesFromFile for file", "filePath", filePath)
	var watcher *fsnotify.Watcher
	slog.Debug("produceLinesFromFile global config", "globalConfig", globalConfig)
	defer close(lines)
	config := getConfigForFile(filePath)

	var watcherErr error
	if config.Follow {
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
	if file, fileReader, err = openFile(false, filePath); err != nil {
		slog.Error("Error opening file", "filePath", filePath, "error", err)
		return
	}
	var waitingForNewData bool = false
	var isFileAtEnd bool = false

	for {

		if fileReader != nil {
			if !waitingForNewData { //dont even try to read if just waiting
				isFileAtEnd = readSingleLineFromFileReturnTrueIfEOF(filePath, lines, fileReader)
				if isFileAtEnd && !config.Follow {
					slog.Info("Finished reading the file and not following, so done...")
					return
				}
				if isFileAtEnd {
					waitingForNewData = true
					file.Seek(0, 2)
					fileReader.Reset(file)
					slog.Debug("readSingleLineFromFile isFileAtEnd after waitingForNewData was false", "isFileAtEnd", isFileAtEnd)
				}
			} else {
				//slog.Warn("waitingForNewData is true in produceLinesFromFile")
			}

		} else {
			slog.Warn("fileReader is nil in produceLinesFromFile", "filePath", filePath)
			break
		}

		if config.Follow {
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
					slog.Debug("File was modified after receiving EOF in the previous read. Continue reading", "file", filePath)
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
						if file, fileReader, err = openFile(true, filePath); err == nil {
							break
						}
						time.Sleep(1 * time.Second)
					}
					if fileReader == nil {
						slog.Warn("File was renamed/removed (log rotation) but could not be reopened", "file", filePath)
						return
					} else {
						slog.Info("Re-opened file after rotation", "file", filePath)
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
		} //if follow
	}
}

func openFile(reopeningAfterRotate bool, filePath string) (*os.File, *bufio.Reader, error) {
	var err error
	var file *os.File
	var fileReader *bufio.Reader
	config := getConfigForFile(filePath)
	file, err = os.Open(filePath)

	fileReader = nil

	if err != nil {
		slog.Error("Error opening file", "filePath", filePath, "error", err)
		return file, fileReader, err
	}

	if reopeningAfterRotate || config.StartFrom == START_FROM_BEGINNING {
		// Seek to beginning if file exists
		_, err = file.Seek(0, 0)
		if err != nil {
			file.Close()
			slog.Error("Error seeking to beginning of file", "filePath", filePath, "error", err)
			return file, fileReader, err
		}
	} else if config.StartFrom == START_FROM_END || config.StartFrom < 0 {
		// Seek to end if file exists
		_, err = file.Seek(0, 2)
		if err != nil {
			file.Close()
			slog.Error("Error seeking to end of file", "filePath", filePath, "error", err)
			return file, fileReader, err
		}
	} else {
		//skip until the line
		slog.Info("Skipping lines after opening file", "skippedLines", config.StartFrom)
		fileReader = bufio.NewReaderSize(file, 8192)
		lineNo := 1
		for {
			_, err := fileReader.ReadString('\n')
			lineNo++
			if lineNo >= config.StartFrom {
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

	return file, fileReader, nil
}

func readFileToEnd(filePath string, lines chan<- string, fileReader *bufio.Reader) {
	slog.Debug("Reading file to end ", "filePath", filePath)
	for {
		isEOF := readSingleLineFromFileReturnTrueIfEOF(filePath, lines, fileReader)
		if isEOF {
			slog.Debug("readFileToEnd done", "filePath", filePath)
			return
		}
	}
}

func readSingleLineFromFileReturnTrueIfEOF(filePath string, lines chan<- string, fileReader *bufio.Reader) bool {
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

/////////////////////////Config

const START_FROM_BEGINNING int = 0
const START_FROM_END int = -1

const (
	HANDLER_METRICS   string = "metrics"
	HANDLER_ATTACKERS string = "attackers"
)

type ConfigForAMonitoredFile struct {
	Enabled   bool
	FilePath  string
	Handlers  []string
	StartFrom int
	//Not implemented yet
	SkipIfLineMatchesRegex string
	//Follow changes to the file, like tail -f
	Follow bool
	//if not available in logs
	DomainName string
	//Unique host id, must be configured by the user
	HostId int
	//used for metrics. Only the following specific values are supported: Other values will be ignored. Defaults to 10
	// supported values: 1, 5, 10, 15, 30, 60
	TimeWindowSizeMinutes int
	//used for logs "re-logged" to a different file. parsed log entries will be written as 1 json entry per line into this file
	//only used by writetofile.go
	WriteToFileTargetFile string
	HandlerInstances      map[string]SBOLogHandlerInterface
	WriteMetricsToDb      bool
	DbAddress             string
	DbUser                string
	DbPassword            string
	DbDatabase            string
	//when true then if a metric entry already exists the will be replaced,
	// when false then if a metric entry already exists then the value will be added to the existing value
	ReplaceExistingMetrics bool
	//Only a limited number of most recent time window values will be kept active and others will be removed out of scope (and saved)
	// e.g if we encounter logs for 202507021121 and 202507021122 and 202507021123 then we should be able to handle them
	// e.g if they are somehow unordered, e.g a request takes too long to complete and is logged after subsequent requests
	// or when timewindow goes out of scope when new time window values are encountered
	// this assumes/requires that the logs are in chronological order
	MetricsWindowSize int
	//number of top N items like IP addresses to be displayed in outputs for counter mode (when -p=count option is provided)
	CounterTopNForKeyedMetrics int
	//when following, interval for updating stats/output for counter mode (when -p=count option is provided)
	CounterOutputIntervalSeconds int
	//when true logs will be saved into an SBOanalytics mysql database
	SaveLogsToDb bool
	//when true, IP addresses will not be saved into SBOanalytics database
	SaveLogsToDbMaskIPs bool
	//when 1 requests from bots, scanners, 30x, 40x etc will be skipped. when 0 all logs will be saved into the database
	//other values MAY be added in the future so you must treat it as an enum, which supports only 0 and 1 for the time being
	SaveLogsToDbOnlyRelevant int
}

/*
Don't log db password (note logging globalConfig directly won't call this method and will log the password)
*/
func (sd ConfigForAMonitoredFile) LogValue() slog.Value {
	copySd := sd
	copySd.DbPassword = "--REDACTED--"
	logBytes, _ := json.Marshal(copySd)
	return slog.StringValue(string(logBytes[:]))
}

// ///////////////handlers
type SBOLogHandlerInterface interface {
	Name() string
	//Begin(someVar any) error
	HandleEntry(*logparsers.SBOHttpRequestLog) (bool, error)
	End() bool
}
