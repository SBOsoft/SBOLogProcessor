package logparsers

import (
	"errors"
	"regexp"
	"strconv"
	"time"
)

type SBOHttpRequestLog struct {
	Domain   string
	ClientIP string
	//Remote logname (from identd, if supplied). This will return a dash unless mod_ident is present and IdentityCheck is set On.
	RemoteLogname   string
	RemoteUser      string
	Timestamp       time.Time
	Method          string
	Path            string
	Protocol        string
	Status          string
	BytesSent       int
	Referer         string
	RefererDomain   string
	UserAgent       string
	UserAgentFamily string
	OSFamily        string
	IsBot           bool
	BotType         string
	IsMalicious     bool
	MaliciousType   string
	//log timestamp is before the timestamps in previous lines. e.g we see logs from 18:01:33 then a log with timestamp 18:00:55 comes
	//this indicates that this request took longer than others
	IsOutOfOrder bool
}

func (sbol *SBOHttpRequestLog) SBOHttpRequestLogSetUserAgent(userAgent string) {
	sbol.UserAgent = userAgent
}

func (sbol *SBOHttpRequestLog) SBOHttpRequestLogSetReferer(referer string) {
	sbol.Referer = referer
}

func (sbol *SBOHttpRequestLog) SBOHttpRequestLogSetPath(requestedPath string) {
	sbol.Path = requestedPath
}

// CommonLogFormat parses a line in Common Log Format (CLF)
// Example: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
func ParseApacheCommonLogFormat(line string) (*SBOHttpRequestLog, error) {
	re := regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 10 {
		return nil, ErrInvalidLogFormat
	}
	parsedTimestamp, _ := ParseApacheTimestamp(matches[4])
	bytesSentInt, _ := strconv.Atoi(matches[9])

	sbol := SBOHttpRequestLog{
		ClientIP:      matches[1],
		RemoteLogname: matches[2],
		RemoteUser:    matches[3],
		Timestamp:     parsedTimestamp,
		Method:        matches[5],
		//Path :         matches[6],
		Protocol:  matches[7],
		Status:    matches[8],
		BytesSent: bytesSentInt}

	sbol.SBOHttpRequestLogSetPath(matches[6])

	return &sbol, nil
}

// CombinedLogFormat parses a line in Combined Log Format
// Example: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
func ParseApacheCombinedLogFormat(line string) (*SBOHttpRequestLog, error) {
	re := regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$`)
	matches := re.FindStringSubmatch(line)
	//slog.Debug("ParseApacheCombinedLogFormat", "matches", matches)
	if len(matches) != 12 {
		return nil, ErrInvalidLogFormat
	}

	parsedTimestamp, _ := ParseApacheTimestamp(matches[4])
	bytesSentInt, _ := strconv.Atoi(matches[9])

	sbol := SBOHttpRequestLog{
		ClientIP:      matches[1],
		RemoteLogname: matches[2],
		RemoteUser:    matches[3],
		Timestamp:     parsedTimestamp,
		Method:        matches[5],
		//Path :         matches[6],
		Protocol:  matches[7],
		Status:    matches[8],
		BytesSent: bytesSentInt,
	}

	sbol.SBOHttpRequestLogSetPath(matches[6])
	sbol.SBOHttpRequestLogSetReferer(matches[10])
	sbol.SBOHttpRequestLogSetUserAgent(matches[11])

	return &sbol, nil
}

// VHostCombinedLogFormat parses a line in Virtual Host Combined Log Format
// Example: example.com:80 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
func ParseApacheVHostCombinedLogFormat(line string) (map[string]string, error) {
	re := regexp.MustCompile(`^(\S+) (\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 13 {
		return nil, ErrInvalidLogFormat
	}

	return map[string]string{
		"vhost":          matches[1],
		"remote_host":    matches[2],
		"remote_logname": matches[3],
		"remote_user":    matches[4],
		"timestamp":      matches[5],
		"method":         matches[6],
		"path":           matches[7],
		"protocol":       matches[8],
		"status":         matches[9],
		"bytes_sent":     matches[10],
		"referer":        matches[11],
		"user_agent":     matches[12],
	}, nil
}

// NginxCombinedFormat parses a line in Nginx Combined Log Format
// Example: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (Macintosh)"
func ParseNginxCombinedFormat(line string) (map[string]string, error) {
	re := regexp.MustCompile(`^(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 11 {
		return nil, ErrInvalidLogFormat
	}

	return map[string]string{
		"remote_addr":     matches[1],
		"remote_user":     matches[2],
		"timestamp":       matches[3],
		"method":          matches[4],
		"path":            matches[5],
		"protocol":        matches[6],
		"status":          matches[7],
		"bytes_sent":      matches[8],
		"http_referer":    matches[9],
		"http_user_agent": matches[10],
	}, nil
}

// NginxCustomFormat parses a line in Nginx Custom Log Format (with $request_time and $upstream_response_time)
// Example: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0" 0.123 0.456
func ParseNginxCustomFormat(line string) (map[string]string, error) {
	re := regexp.MustCompile(`^(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)" (\S+) (\S+)$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 13 {
		return nil, ErrInvalidLogFormat
	}

	return map[string]string{
		"remote_addr":            matches[1],
		"remote_user":            matches[2],
		"timestamp":              matches[3],
		"method":                 matches[4],
		"path":                   matches[5],
		"protocol":               matches[6],
		"status":                 matches[7],
		"bytes_sent":             matches[8],
		"http_referer":           matches[9],
		"http_user_agent":        matches[10],
		"request_time":           matches[11],
		"upstream_response_time": matches[12],
	}, nil
}

// TODO FIX THIS it's plain wrong
// HAProxyHTTPLogFormat parses a line in HAProxy HTTP Log Format
// Example: Feb  6 12:14:14 localhost haproxy[14389]: 10.0.1.2:57317 [06/Feb/2009:12:14:14.655] http-in static/srv1 10/0/30/69/109 200 2750 - - ---- 1/1/1/1/0 0/0 {1wt.eu} {} "GET /index.html HTTP/1.1"
func ParseHAProxyHTTPLogFormat(line string) (map[string]string, error) {
	re := regexp.MustCompile(`^\w+\s+\d+\s+\d+:\d+:\d+\s+\S+\s+haproxy\[\d+\]:\s+(\S+)\s+\[([^\]]+)\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\{([^}]*)\}\s+\{([^}]*)\}\s+"(\S+)\s+(\S+)\s+(\S+)"$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 18 {
		return nil, ErrInvalidLogFormat
	}

	return map[string]string{
		"client_ip":                matches[1],
		"timestamp":                matches[2],
		"frontend_name":            matches[3],
		"backend_name":             matches[4],
		"time_metrics":             matches[5],
		"status_code":              matches[6],
		"bytes_read":               matches[7],
		"captured_request_cookie":  matches[8],
		"captured_response_cookie": matches[9],
		"termination_state":        matches[10],
		"actconn":                  matches[11],
		"feconn":                   matches[12],
		"beconn":                   matches[13],
		"srvconn":                  matches[14],
		"retries":                  matches[15],
		"http_referer":             matches[16],
		"http_user_agent":          matches[17],
		"method":                   matches[18],
		"path":                     matches[19],
		"protocol":                 matches[20],
	}, nil
}

// TODO fix this
// HAProxyTCPLogFormat parses a line in HAProxy TCP Log Format
// Example: Feb  6 12:14:14 localhost haproxy[14389]: 10.0.1.2:57317 [06/Feb/2009:12:14:14.655] tcp-in tcp-srv1 10/0/30/69/109 - - ---- 1/1/1/1/0 0/0
func ParseHAProxyTCPLogFormat(line string) (map[string]string, error) {
	re := regexp.MustCompile(`^\w+\s+\d+\s+\d+:\d+:\d+\s+\S+\s+haproxy\[\d+\]:\s+(\S+)\s+\[([^\]]+)\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 13 {
		return nil, ErrInvalidLogFormat
	}

	return map[string]string{
		"client_ip":         matches[1],
		"timestamp":         matches[2],
		"frontend_name":     matches[3],
		"backend_name":      matches[4],
		"time_metrics":      matches[5],
		"termination_state": matches[6],
		"actconn":           matches[7],
		"feconn":            matches[8],
		"beconn":            matches[9],
		"srvconn":           matches[10],
		"retries":           matches[11],
	}, nil
}

// ParseNginxTimestamp parses the Nginx log timestamp into a time.Time
func ParseNginxTimestamp(timestamp string) (time.Time, error) {
	return time.Parse("02/Jan/2006:15:04:05 -0700", timestamp)
}

// ParseHAProxyTimestamp parses the HAProxy log timestamp into a time.Time
func ParseHAProxyTimestamp(timestamp string) (time.Time, error) {
	return time.Parse("02/Jan/2006:15:04:05.000", timestamp)
}

// ParseTimestamp parses the Apache log timestamp into a time.Time
func ParseApacheTimestamp(timestamp string) (time.Time, error) {
	return time.Parse("02/Jan/2006:15:04:05 -0700", timestamp)
}

var ErrInvalidLogFormat = errors.New("invalid log format")

var LogParserErrors = errors.New("package errors")
