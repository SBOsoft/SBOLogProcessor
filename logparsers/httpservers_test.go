package logparsers

import (
	"testing"
	"time"
)

func TestParseApacheCommonLogFormat(t *testing.T) {
	line := `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326`
	expected := map[string]string{
		"remote_host":    "127.0.0.1",
		"remote_logname": "-",
		"remote_user":    "frank",
		"timestamp":      "10/Oct/2000:13:55:36 -0700",
		"method":         "GET",
		"path":           "/apache_pb.gif",
		"protocol":       "HTTP/1.0",
		"status":         "200",
		"bytes_sent":     "2326",
	}

	result, err := ParseApacheCommonLogFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.ClientIP != expected["remote_host"] {
		t.Errorf("Expected %s, got %s", expected["remote_host"], result.ClientIP)
	}

}

/*
func TestParseApacheCombinedLogFormat(t *testing.T) {
	line := `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"`
	expected := map[string]string{
		"remote_host":    "127.0.0.1",
		"remote_logname": "-",
		"remote_user":    "frank",
		"timestamp":      "10/Oct/2000:13:55:36 -0700",
		"method":         "GET",
		"path":           "/apache_pb.gif",
		"protocol":       "HTTP/1.0",
		"status":         "200",
		"bytes_sent":     "2326",
		"referer":        "http://www.example.com/start.html",
		"user_agent":     "Mozilla/4.08 [en] (Win98; I ;Nav)",
	}

	result, err := ParseApacheCombinedLogFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	for k, v := range expected {
		if result[k] != v {
			t.Errorf("Expected %s=%s, got %s", k, v, result[k])
		}
	}
}

func TestParseApacheCombinedLogFormat2(t *testing.T) {
	line := `43.166.245.120 - - [23/May/2025:17:03:05 +0000] "GET / HTTP/1.1" 200 5761 "http://casualgames.dev" "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1"`

	result, err := ParseApacheCombinedLogFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	for k, v := range result {
		fmt.Printf("%v %v \n", k, v)
	}
}

func TestParseApacheVHostCombinedLogFormat(t *testing.T) {
	line := `example.com:80 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"`
	expected := map[string]string{
		"vhost":          "example.com:80",
		"remote_host":    "127.0.0.1",
		"remote_logname": "-",
		"remote_user":    "frank",
		"timestamp":      "10/Oct/2000:13:55:36 -0700",
		"method":         "GET",
		"path":           "/apache_pb.gif",
		"protocol":       "HTTP/1.0",
		"status":         "200",
		"bytes_sent":     "2326",
		"referer":        "http://www.example.com/start.html",
		"user_agent":     "Mozilla/4.08 [en] (Win98; I ;Nav)",
	}

	result, err := ParseApacheVHostCombinedLogFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	for k, v := range expected {
		if result[k] != v {
			t.Errorf("Expected %s=%s, got %s", k, v, result[k])
		}
	}
}

func TestParseApacheTimestamp(t *testing.T) {
	timestamp := "10/Oct/2000:13:55:36 -0700"
	expected := time.Date(2000, time.October, 10, 13, 55, 36, 0, time.FixedZone("", -7*60*60))

	result, err := ParseApacheTimestamp(timestamp)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Equal(expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestParseApacheInvalidLogFormats(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		funcToTest func(string) (map[string]string, error)
	}{
		{
			name:       "Invalid CLF",
			line:       "invalid log line",
			funcToTest: ParseApacheCommonLogFormat,
		},
		{
			name:       "Invalid Combined",
			line:       "invalid log line",
			funcToTest: ParseApacheCombinedLogFormat,
		},
		{
			name:       "Invalid VHost",
			line:       "invalid log line",
			funcToTest: ParseApacheVHostCombinedLogFormat,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.funcToTest(test.line)
			if err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}

func TestNginxCombinedFormat(t *testing.T) {
	line := `127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (Macintosh)"`
	expected := map[string]string{
		"remote_addr":     "127.0.0.1",
		"remote_user":     "-",
		"timestamp":       "10/Oct/2000:13:55:36 -0700",
		"method":          "GET",
		"path":            "/",
		"protocol":        "HTTP/1.1",
		"status":          "200",
		"bytes_sent":      "612",
		"http_referer":    "-",
		"http_user_agent": "Mozilla/5.0 (Macintosh)",
	}

	result, err := ParseNginxCombinedFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	for k, v := range expected {
		if result[k] != v {
			t.Errorf("Expected %s=%s, got %s", k, v, result[k])
		}
	}
}

func TestNginxCustomFormat(t *testing.T) {
	line := `127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0" 0.123 0.456`
	expected := map[string]string{
		"remote_addr":            "127.0.0.1",
		"remote_user":            "-",
		"timestamp":              "10/Oct/2000:13:55:36 -0700",
		"method":                 "GET",
		"path":                   "/",
		"protocol":               "HTTP/1.1",
		"status":                 "200",
		"bytes_sent":             "612",
		"http_referer":           "-",
		"http_user_agent":        "Mozilla/5.0",
		"request_time":           "0.123",
		"upstream_response_time": "0.456",
	}

	result, err := ParseNginxCustomFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	for k, v := range expected {
		if result[k] != v {
			t.Errorf("Expected %s=%s, got %s", k, v, result[k])
		}
	}
}
*/

/*
func TestHAProxyHTTPLogFormat(t *testing.T) {
	line := `Feb  6 12:14:14 localhost haproxy[14389]: 10.0.1.2:57317 [06/Feb/2009:12:14:14.655] http-in static/srv1 10/0/30/69/109 200 2750 - - ---- 1/1/1/1/0 0/0 {1wt.eu} {} "GET /index.html HTTP/1.1"`
	expected := map[string]string{
		"client_ip":               "10.0.1.2:57317",
		"timestamp":               "06/Feb/2009:12:14:14.655",
		"frontend_name":           "http-in",
		"backend_name":            "static/srv1",
		"time_metrics":            "10/0/30/69/109",
		"status_code":             "200",
		"bytes_read":              "2750",
		"captured_request_cookie": "-",
		"captured_response_cookie": "-",
		"termination_state":       "----",
		"actconn":                 "1/1/1/1/0",
		"feconn":                  "0",
		"beconn":                  "0",
		"srvconn":                 "{1wt.eu}",
		"retries":                 "{}",
		"http_referer":            "GET",
		"http_user_agent":         "/index.html",
		"method":                  "HTTP/1.1",
	}

	result, err := ParseHAProxyHTTPLogFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	for k, v := range expected {
		if result[k] != v {
			t.Errorf("Expected %s=%s, got %s", k, v, result[k])
		}
	}
}
*/
/*
func TestHAProxyTCPLogFormat(t *testing.T) {
	line := `Feb  6 12:14:14 localhost haproxy[14389]: 10.0.1.2:57317 [06/Feb/2009:12:14:14.655] tcp-in tcp-srv1 10/0/30/69/109 - - ---- 1/1/1/1/0 0/0`
	expected := map[string]string{
		"client_ip":         "10.0.1.2:57317",
		"timestamp":         "06/Feb/2009:12:14:14.655",
		"frontend_name":     "tcp-in",
		"backend_name":      "tcp-srv1",
		"time_metrics":      "10/0/30/69/109",
		"termination_state": "-",
		"actconn":           "-",
		"feconn":            "----",
		"beconn":            "1/1/1/1/0",
		"srvconn":           "0",
		"retries":           "0",
	}

	result, err := ParseHAProxyTCPLogFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	for k, v := range expected {
		if result[k] != v {
			t.Errorf("Expected %s=%s, got %s", k, v, result[k])
		}
	}
}
*/
func TestParseNginxTimestamp(t *testing.T) {
	timestamp := "10/Oct/2000:13:55:36 -0700"
	expected := time.Date(2000, time.October, 10, 13, 55, 36, 0, time.FixedZone("", -7*60*60))

	result, err := ParseNginxTimestamp(timestamp)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Equal(expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestParseHAProxyTimestamp(t *testing.T) {
	timestamp := "06/Feb/2009:12:14:14.655"
	expected := time.Date(2009, time.February, 6, 12, 14, 14, 655000000, time.UTC)

	result, err := ParseHAProxyTimestamp(timestamp)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Equal(expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestParseNginxInvalidLogFormats(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		funcToTest func(string) (map[string]string, error)
	}{
		{
			name:       "Invalid Nginx Combined",
			line:       "invalid log line",
			funcToTest: ParseNginxCombinedFormat,
		},
		{
			name:       "Invalid Nginx Custom",
			line:       "invalid log line",
			funcToTest: ParseNginxCustomFormat,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.funcToTest(test.line)
			if err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}

func TestParseHAProxyInvalidLogFormats(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		funcToTest func(string) (map[string]string, error)
	}{
		{
			name:       "Invalid HAProxy HTTP",
			line:       "invalid log line",
			funcToTest: ParseHAProxyHTTPLogFormat,
		},
		{
			name:       "Invalid HAProxy TCP",
			line:       "invalid log line",
			funcToTest: ParseHAProxyTCPLogFormat,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.funcToTest(test.line)
			if err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}
