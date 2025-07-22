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

package logparsers

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	REQUEST_MALICIOUS_UNKNOWN   int = 0
	REQUEST_MALICIOUS_INVALID   int = 1
	REQUEST_MALICIOUS_SQLINJ    int = 10
	REQUEST_MALICIOUS_XSS       int = 20
	REQUEST_MALICIOUS_TRAVERSAL int = 30
	REQUEST_MALICIOUS_SCAN      int = 40
)

type SBOHttpRequestLog struct {
	Domain   string
	ClientIP string
	//Remote logname (from identd, if supplied). This will return a dash unless mod_ident is present and IdentityCheck is set On.
	RemoteLogname string
	RemoteUser    string
	Timestamp     time.Time
	Method        string
	Path          string //full path
	Path1         string //first part of the path, e.g /a in /a/b/c/d/e.html
	Path2         string //first and second part of the path, e.g /a/b in /a/b/c/d/e.html
	Path3         string //first, second and third part of the path, e.g /a/b/c in /a/b/c/d/e.html
	Protocol      string
	Status        string
	BytesSent     int
	Referer       string
	UserAgent     *SBOUserAgent
	Malicious     int
	//log timestamp is before the timestamps in previous lines. e.g we see logs from 18:01:33 then a log with timestamp 18:00:55 comes
	//this indicates that this request took longer than others
	IsOutOfOrder bool
}

func (sbol *SBOHttpRequestLog) SBOHttpRequestLogSetUserAgent(userAgent string) {
	sbol.UserAgent = NewSBOUserAgent(userAgent)
}

func (sbol *SBOHttpRequestLog) SBOHttpRequestLogSetReferer(referer string, requestUri string) {
	//sbol.Referer = referer
	rx := regexp.MustCompile(`(\?|&)utm_source=([^&]+)(&|\z)`)
	match := rx.FindStringSubmatch(requestUri)
	if len(match) > 0 {
		sbol.Referer = match[2]
	} else if len(referer) > 0 {
		parsed, err := url.Parse(referer)

		if err == nil {
			sbol.Referer = parsed.Hostname()
			sbol.Referer = strings.TrimPrefix(sbol.Referer, "www.")
		}
	}
}

func (sbol *SBOHttpRequestLog) SBOHttpRequestLogSetPath(requestUri string) {

	parsedurl, err := url.ParseRequestURI(requestUri)

	if err != nil {
		sbol.Malicious = REQUEST_MALICIOUS_INVALID
		sbol.Path, _, _ = strings.Cut(requestUri, "?")
		return
	}

	sbol.Path = parsedurl.Path

	if len(sbol.Path) > 0 {
		splitPath := strings.Split(sbol.Path, "/")
		//splitPath[0] is empty, leading / leads to an empty element ?
		if len(splitPath) == 1 {
			sbol.Path1 = "/"
		}
		if len(splitPath) > 1 {
			sbol.Path1 = "/" + splitPath[1]
		}
		if len(splitPath) > 2 {
			sbol.Path2 = sbol.Path1 + "/" + splitPath[2]
		}
		if len(splitPath) > 3 {
			sbol.Path3 = sbol.Path2 + "/" + splitPath[3]
		}
	}

	if isDirectoryTraversal(parsedurl.Path, requestUri) {
		sbol.Malicious = REQUEST_MALICIOUS_TRAVERSAL
	} else if isXSSAttempt(parsedurl.RawQuery) {
		sbol.Malicious = REQUEST_MALICIOUS_XSS
	} else if isSqlInjectionAttempt(parsedurl.RawQuery) {
		sbol.Malicious = REQUEST_MALICIOUS_SQLINJ
	}
}

func isDirectoryTraversal(parsedPath string, requestUriVerbatimFromLog string) bool {
	if strings.Contains(parsedPath, "/../") || strings.Contains(requestUriVerbatimFromLog, "%00") {
		return true
	}

	return false
}

/*
TODO obviously far from ideal, just placeholders for now
*/
func isSqlInjectionAttempt(rawQueryString string) bool {
	rx := regexp.MustCompile(`'.*(insert|update|exec|execute)`)
	match := rx.FindString(rawQueryString)

	if len(match) > 0 {
		return true
	}
	return false
}

/*
TODO obviously far from ideal, just placeholders for now
*/
func isXSSAttempt(rawQueryString string) bool {
	rx := regexp.MustCompile(`<script|script>|alert|onmouseover|onmouseout`)
	match := rx.FindString(rawQueryString)

	if len(match) > 0 {
		return true
	}
	return false
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
	sbol.SBOHttpRequestLogSetReferer(matches[10], matches[6])
	sbol.SBOHttpRequestLogSetUserAgent(matches[11])

	return &sbol, nil
}

// VHostCombinedLogFormat parses a line in Virtual Host Combined Log Format
// Example: example.com:80 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
func ParseApacheVHostCombinedLogFormat(line string) (*SBOHttpRequestLog, error) {
	re := regexp.MustCompile(`^(\S+) (\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 13 {
		return nil, ErrInvalidLogFormat
	}

	parsedTimestamp, _ := ParseApacheTimestamp(matches[5])
	bytesSentInt, _ := strconv.Atoi(matches[10])

	sbol := SBOHttpRequestLog{
		ClientIP:      matches[2],
		RemoteLogname: matches[3],
		RemoteUser:    matches[4],
		Timestamp:     parsedTimestamp,
		Method:        matches[6],
		Protocol:      matches[8],
		Status:        matches[9],
		BytesSent:     bytesSentInt,
	}
	sbol.Domain = matches[1]
	sbol.SBOHttpRequestLogSetPath(matches[7])
	sbol.SBOHttpRequestLogSetReferer(matches[11], matches[7])
	sbol.SBOHttpRequestLogSetUserAgent(matches[12])

	return &sbol, nil

}

// NginxCombinedFormat parses a line in Nginx Combined Log Format
// Example: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (Macintosh)"
func ParseNginxCombinedFormat(line string) (*SBOHttpRequestLog, error) {
	re := regexp.MustCompile(`^(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 11 {
		return nil, ErrInvalidLogFormat
	}

	parsedTimestamp, _ := ParseNginxTimestamp(matches[3])
	bytesSentInt, _ := strconv.Atoi(matches[8])

	sbol := SBOHttpRequestLog{
		ClientIP:   matches[1],
		RemoteUser: matches[2],
		Timestamp:  parsedTimestamp,
		Method:     matches[4],
		Protocol:   matches[6],
		Status:     matches[7],
		BytesSent:  bytesSentInt,
	}
	//sbol.Domain = matches[1]
	sbol.SBOHttpRequestLogSetPath(matches[5])
	sbol.SBOHttpRequestLogSetReferer(matches[9], matches[5])
	sbol.SBOHttpRequestLogSetUserAgent(matches[10])

	return &sbol, nil
}

// NginxCustomFormat parses a line in Nginx Custom Log Format (with $request_time and $upstream_response_time)
// Example: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0" 0.123 0.456
func ParseNginxCustomFormat(line string) (*SBOHttpRequestLog, error) {
	re := regexp.MustCompile(`^(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)" (\S+) (\S+)$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 13 {
		return nil, ErrInvalidLogFormat
	}

	parsedTimestamp, _ := ParseNginxTimestamp(matches[3])
	bytesSentInt, _ := strconv.Atoi(matches[8])

	sbol := SBOHttpRequestLog{
		ClientIP:   matches[1],
		RemoteUser: matches[2],
		Timestamp:  parsedTimestamp,
		Method:     matches[4],
		Protocol:   matches[6],
		Status:     matches[7],
		BytesSent:  bytesSentInt,
	}
	//sbol.Domain = matches[1]
	sbol.SBOHttpRequestLogSetPath(matches[5])
	sbol.SBOHttpRequestLogSetReferer(matches[9], matches[5])
	sbol.SBOHttpRequestLogSetUserAgent(matches[10])
	//TODO we are ignoring the following fields
	/*
		"request_time":           matches[11],
		"upstream_response_time": matches[12],

	*/
	return &sbol, nil
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
