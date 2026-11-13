# Example configurations

## Counter mode

### [example-counter-mode.json](example-counter-mode.json)
Configuration options for counter mode. `CounterTopNForKeyedMetrics` controls how many items such as IP addresses will be displayed.
`CounterOutputIntervalSeconds` controls output interval. `StartFrom=-1` means processing will start from the end of the file. 
`StartFrom=-0` will make the program start from the beginning of the file. 

### [example-metrics-mode.json](example-metrics-mode.json)
Configuration options for metrics mode. 

  - `StartFrom=-1` means processing will start from the end of the file. `StartFrom=-0` will make the program start from the beginning of the file. 
  - `SkipIfLineMatchesRegex` this is not implemented yet
  - `DomainName` domain name for metrics. Logs saved to the database use the domain name found in log entries (vhost log formats) and fall back to this value if not available
  - `HostId` assign a unique numeric id for each host you are running the tool, e.g if you are collecting logs from multiple hosts
  - `TimeWindowSizeMinutes` metrics will be generated for each time window. For example, if this value is set to `10` metrics will be generated for 00-10, 10-20, 20-30, 30-40, 40-50, 50-60 minutes. A log entry for 11:30:22 will be counted towards the 10-20 minutes window.
  - `WriteMetricsToDb` when true metrics will be written to a database.
  - `DbAddress` database address such as 127.0.0.1 or somemysqlhost.example.com:23306
  - `ReplaceExistingMetrics` action for when an existing entry for a timewindow already exists. When true, existing entry will be replaced. When false, metric value will be set to `existing value + new value`. 
    Forced to `false` when `SaveReadPosition` is true or when multiple files are configured with the same `DomainName`, as metrics for the same time window may then be saved more than once and each value must be added. 
    Use `false` if you run the tool on multiple hosts for the same domain.
  - `MetricsWindowSize` number of most recent time windows kept open (2-10, defaults to 3). When a log entry for a newer time window arrives, the oldest open time window is closed and its metrics are saved. 
    Log entries for already closed time windows (e.g requests logged very late) are not counted in metrics. Metrics for open time windows are saved when the program stops gracefully (SIGINT/SIGTERM, Ctrl+C), they are lost if the process is killed.
  - `SaveReadPosition` when true the read position in the file is saved periodically and when the program stops. When the program is restarted, processing continues from the saved position instead of `StartFrom`, so the same lines are not processed (and saved into the database) again. 
    The saved position is ignored if the file was rotated or truncated in the meantime. Defaults to `true` (when using a configuration file), set it to `false` to always start as configured by `StartFrom`.
  - `ReadPositionDirectory` directory where read positions are saved when `SaveReadPosition` is true, one small json file per monitored file. Defaults to the current working directory. It is created if it doesn't exist.
  - `SaveLogsToDb` when true logs will be saved to the database
  - `SaveLogsToDbMaskIPs` when true IP addresses will not be saved in database
  - `SaveLogsToDbOnlyRelevant` when 1 some log entries such as 40x statuses, requests from scanners, seobots etc will be skipped and won't be saved into the database.


