# SBOLogProcessor
Log processor for SBOanalytics

The purpose of this tool is to monitor web server to:

 1. Generate metrics
 2. Allow users to view realtime metrics by running the tool on the command line
 3. Push metrics to a SBOanalytics database
 4. Report on web site visitors
 5. Report on non-human visitors, e.g google bot, scanners, malicious actors


The primary goal is to provide realtime metrics from the command line by following realtime changes to log files, 
e.g top offending IPs (e.g so you can block them).
The secondary goal of this tool is to generate insights about web site visitors, to replace Google analytics.


# Build and Run

## Development

### Build

Build
```go build -o ./output/bin/sbologc```

Clean
```go clean```

### Run

```go run . -f=true ./test-data/testfile.txt```
