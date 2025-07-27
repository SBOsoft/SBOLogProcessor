# Example configurations

## Counter mode

### [example-counter-mode.json] 
Configuration options for counter mode. `CounterTopNForKeyedMetrics` controls how many items such as IP addresses will be displayed.
`CounterOutputIntervalSeconds` controls output interval. `StartFrom=-1` means processing will start from the end of the file. 
`StartFrom=-0` will make the program start from the beginning of the file. 

### [example-metrics-mode.json] 
Configuration options for metrics mode. 

  - `StartFrom=-1` means processing will start from the end of the file. `StartFrom=-0` will make the program start from the beginning of the file. 
  - `SkipIfLineMatchesRegex` this is not implemented yet
  - `DomainName` default domain name if a domain name cannot be found in processed log entries
  - `HostId` assign a unique numeric id for each host you are running the tool, e.g if you are collecting logs from multiple hosts
  - `TimeWindowSizeMinutes` metrics will be generated for each time window. For example, if this value is set to `10` metrics will be generated for 00-10, 10-20, 20-30, 30-40, 40-50, 50-60 minutes. A log entry for 11:30:22 will be counted towards the 10-20 minutes window.
  - `WriteMetricsToDb` when true metrics will be written to a database.
  - `DbAddress` database address such as 127.0.0.1 or somemysqlhost.example.com:23306
  - `ReplaceExistingMetrics` action for when an existing entry for a timewindow already exists. When true, existing entry will be replaced. When false, metric value will be set to `existing value + new value`.
  - `SaveLogsToDb` when true logs will be saved to the database
  - `SaveLogsToDbMaskIPs` when true IP addresses will not be saved in database
  - `SaveLogsToDbOnlyRelevant` when 1 some log entries such as 40x statuses, requests from scanners, seobots etc will be skipped and won't be saved into the database.


