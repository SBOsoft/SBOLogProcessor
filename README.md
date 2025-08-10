# SBOLogProcessor
Access Log Processor and Metrics Generator

There are 3 main use cases supported by this tool:

 1. Counter mode: Count logs from an access log file and print statistics to stdout every 30 seconds.  For example, running `sbologp -p count /var/log/apache2/example.com-access.log` will print stats from /var/log/apache2/example.com-access.log file every 30 seconds.
 2. Metrics generator mode: Process logs from an access log file (or files) and generates metrics, which can be saved into a mysql database to be used with [SBOanalytics](https://github.com/SBOsoft/SBOanalytics) (web front-end for metrics) or just printed to stdout. 
 Processed (and optionally filtered) logs can be pushed to a mysql server, later to be viewed using SBOanalytics. Besides web server metrics, it can capture host metrics such as cpu and memory and save them to the mysql database as well.
 3. Security mode: (**Not implemented yet**) Process logs from an access log file and output potential security issues (e.g abuser, stats on sql injection attempts etc) giving you a list of IPs and/or patterns that you may want to block

# Usage
This is a command line tool without a user interface.

## Database configuration
If you want to save metrics and logs into a database, i.e to be used with SBOanalytics, then you must set up a mysql database
before running this tool.
A database is not required for counter mode.

Database set up scripts can be found at https://github.com/SBOsoft/SBOanalytics/tree/main/db. There are multiple database script files named 
using yyyymmddxxxx format, for example 202507210001-some-descriptive-name.sql, where xxxx part is typically 0001. 

During the initial set up you must run all files in alphabetical order. 

During upgrades only run files that were added after the last time you updated your database. Both SBOLogProcessor and SBOanalytics 
use version numbers following yyyy.mm.dd.xxxx pattern, e.g 2025.07.11.0001. You can find your current version number in version.txt files in
both SBOLogProcessor and SBOanalytics packages.

So if your current version is 2025.07.15.0001 and want to upgrade to 2025.07.25.0001 then you must run database scripts created 
after 202507150001. 

**You MUST always run sql files in alphabetical order.**

## Binary releases
Download a precompiled binary from [releases](https://github.com/SBOsoft/SBOLogProcessor/releases) page, unzip/untar and execute `sbologp` (or sbologp.exe on windows) command.

## Command line options and configuration

Run `sbologp -h` to see available command line options.

There are too many options which may not have a corresponding command line parameter, passing a configuration file using -c option is required when generating metrics.

See https://github.com/SBOsoft/SBOLogProcessor/tree/main/conf/ for example configurations. Normally copying a configuration example  and modifying it to meet your needs and then running the application using `-c` option should suffice. 

Configuration must be a json map, with file paths as keys. There are two special key values `--default--` and `--OS-metrics--` which can be used to configure default settings for all files and for operating system metrics respectively. For example if you want to configure log processing for five file paths and operating system metrics which will all use the same database connection settings, then you can configure database settings under the `--default--` key only and those settings will be used for all five files and operating system metrics.

For more details on configuration options, see comments for `type ConfigForAMonitoredFile struct ` near the bottom of 
https://github.com/SBOsoft/SBOLogProcessor/blob/main/main.go.

## Example commands
Examples assume you are running a linux, e.g ubuntu.

### Counter mode
Counter mode generates statistics from an access log file. 

Run the application in counter mode (following changes to the file like tail -f), and print stats every 30 seconds incrementally:

```./sbologp -f -p=count /var/log/apache2/access.log```

Run in counter mode without following changes, prints total stats and exits:

```./sbologp -p=count /var/log/apache2/access.log```


### Metrics 

Run in the background using configuration file:

```nohup ./sbologp -f -c sbologp-config.json &```

nohup will ensure the program continues to run in the background even after your session ends, e.g your ssh connection is disconnected.
You will always want to pass a configuration file when using the tool to generate metrics.

# Development

Install go first, then clone the project from github.

## Build

Build
```go build -o ./output/bin/sbologp```

Clean
```go clean```

## Run using go
Use `go run . -option1 -option2 path-to-access-log-file`  

For example: 
```go run . -f -p=count /var/log/apache2/access.log```


### Counter mode

Print stats from the given log file every 30 seconds (follow changes).

```go run . -f -p count /var/log/apache2/example.com-access.log```

Print total stats from the given log file.

```go run . -p count /var/log/apache2/example.com-access.log```

### Run tests

`go test ./...` in project root folder or `go test ./...` in a sub-folder.

Do NOT expect high test coverage.