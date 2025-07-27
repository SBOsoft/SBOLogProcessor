# SBOLogProcessor
Access Log Processor and Metrics Generator

There are 3 main use cases (profiles) supported by this tool:

 1. Counter mode (when -p=count option is provided): Counts logs from an access log file and prints statistics to stdout every 30 seconds.  For example, running `sbologp -p count /var/log/apache2/example.com-access.log` will print stats from /var/log/apache2/example.com-access.log file every 30 seconds.
 2. Metrics generator (when -p=metrics option is provided): Processes logs from an access log file (or files) and generates metrics, which can be saved into a mysql database to be used with [SBOanalytics](https://github.com/SBOsoft/SBOanalytics) (web front-end for metrics) or just printed to stdout. Optionally processed (and optionally filtered) logs can be pushed to a mysql server, later to be viewed using SBOanalytics.
 3. Security mode (when -p=security option is provided): (**Not implemented yet**) Processes logs from an access log file and outputs potential security issues (e.g abuser, stats on sql injection attempts etc) giving you a list of IPs and/or patterns that you may want to block

# Usage
This is a command line tool without a user interface.

## Database configuration
If you want to save metrics and logs to a database, i.e to query using SBOanalytics, then you must set up a mysql database
before running this tool.
A database is not required for counter mode.

Database set up scripts can be found at https://github.com/SBOsoft/SBOanalytics/tree/main/db. There are multiple database script files named 
using yyyymmddxxxx format, for example 20250721-somedescriptivepart.sql, where xxxx part is typically 0001. 

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

There are too many options which may not have a corresponding command line parameter so if you need more control, passing a configuration file using -c option is required.

See https://github.com/SBOsoft/SBOLogProcessor/tree/main/conf/ for example configurations. Normally copying a configuration example  and modifying it to meet your needs and then running the application using `-c` option should suffice. 

Configuration must be a json map, with file paths as keys. 

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
```go run . -f -h=COUNTER -p=count /var/log/apache2/access.log```


### Counter mode

Print stats from the given log file every 30 seconds (follow changes).

```go run . -f -p count /var/log/apache2/example.com-access.log```

Print total stats from the given log file.

```go run . -p count /var/log/apache2/example.com-access.log```

### Run tests

`go test ./...` in project root folder or `go test ./...` in a sub-folder.

Do NOT expect high test coverage.