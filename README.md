# SBOLogProcessor
Access Log Processor and Metrics Generator

There are 3 main use cases (profiles) supported by this tool:

 1. Counter mode (when -p=count option is provided): Counts logs from an access log file and prints statistics to stdout
 2. Metrics generator (when -p=metrics option is provided): Processes logs from an access log file (or files) and generates metrics, which can be saved into a mysql database to be used with SBOAnalytics (a web front-end for metrics) or just printed to stdout.
 3. Security mode (when -p=security option is provided): (Not implemented yet) Processes logs from an access log file and outputs potential security issues (e.g abuser, stats on sql injection attempts etc) giving you a list of IPs and/or patterns that you may want to block

# Usage 

## Binary releases
Download a precompiled binary from [releases](https://github.com/SBOsoft/SBOLogProcessor/releases) page, unzip/untar and execute sbologp (or sbologp.exe on windows) command.

## Command line options and configuration

Run `sbologp -h` to see available command line options.

There are too many options which may not have a corresponding command line parameter so if you need more control, passing a configuration file using -c option might be required.

See https://github.com/SBOsoft/SBOLogProcessor/tree/main/conf/example-config-file.json for configuration examples.
Configuration must be a json map, with file paths as keys. 


# Build and run

## Development

Install go first

### Build

Build
```go build -o ./output/bin/sbologp```

Clean
```go clean```

### Run
Use `go run . -option1 -option2 path-to-access-log-file`  

For example: 
```go run . -f -h=COUNTER -p=count /var/log/apache2/access.log```

### Run tests

`go test ./...` in project root folder or `go test ./...` in a sub-folder.

Do NOT expect high test coverage.