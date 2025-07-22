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
	"testing"
	"time"
)

func TestParseApacheCommonLogFormat(t *testing.T) {
	line := `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /p1/p2/p3/apache_pb.gif HTTP/1.0" 200 2326`
	expected := map[string]string{
		"remote_host":    "127.0.0.1",
		"remote_logname": "-",
		"remote_user":    "frank",
		"timestamp":      "10/Oct/2000:13:55:36 -0700",
		"method":         "GET",
		"path":           "/p1/p2/p3/apache_pb.gif",
		"path1":          "/p1",
		"path2":          "/p1/p2",
		"path3":          "/p1/p2/p3",
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

	if result.Path1 != expected["path1"] {
		t.Errorf("Expected %s, got %s", expected["path1"], result.Path1)
	}
	if result.Path2 != expected["path2"] {
		t.Errorf("Expected %s, got %s", expected["path2"], result.Path2)
	}
	if result.Path3 != expected["path3"] {
		t.Errorf("Expected %s, got %s", expected["path3"], result.Path3)
	}

}

func TestParseApacheCommonLogFormat2(t *testing.T) {
	line := `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 2326`
	expected := map[string]string{
		"remote_host":    "127.0.0.1",
		"remote_logname": "-",
		"remote_user":    "frank",
		"timestamp":      "10/Oct/2000:13:55:36 -0700",
		"method":         "GET",
		"path":           "/",
		"path1":          "/",
		"path2":          "",
		"path3":          "",
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

	if result.Path1 != expected["path1"] {
		t.Errorf("Expected %s, got %s", expected["path1"], result.Path1)
	}
	if result.Path2 != expected["path2"] {
		t.Errorf("Expected %s, got %s", expected["path2"], result.Path2)
	}
	if result.Path3 != expected["path3"] {
		t.Errorf("Expected %s, got %s", expected["path3"], result.Path3)
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

func TestNginxCombinedFormat(t *testing.T) {
	line := `127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (Macintosh)"`

	result, err := ParseNginxCombinedFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.BytesSent != 612 {
		t.Errorf("BytesSent expected %v, got %v", 612, result.BytesSent)
	}
	if result.ClientIP != "127.0.0.1" {
		t.Errorf("ClientIP expected %v, got %v", "127.0.0.1", result.ClientIP)
	}
	if result.Method != "GET" {
		t.Errorf("Method expected %v, got %v", "GET", result.Method)
	}
	if result.Path != "/" {
		t.Errorf("Path expected %v, got %v", "/", result.Path)
	}
	if result.Protocol != "HTTP/1.1" {
		t.Errorf("Protocol expected %v, got %v", "HTTP/1.1", result.Protocol)
	}
	if result.Status != "200" {
		t.Errorf("Status expected %v, got %v", "200", result.Status)
	}
	if result.Referer != "" {
		t.Errorf("Referer expected %v, got %v", "", result.Referer)
	}
	if result.UserAgent.Family != UAFamily_Other {
		t.Errorf("Family expected %v, got %v", UAFamily_Other, result.UserAgent.Family)
	}
	if result.UserAgent.OS != OSFamily_MacOS {
		t.Errorf("OS expected %v, got %v", OSFamily_MacOS, result.UserAgent.OS)
	}
}

func TestNginxCombinedFormatWithReferer(t *testing.T) {
	line := `127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 612 "https://example.com/somepage" "Mozilla/5.0 (Macintosh)"`

	result, err := ParseNginxCombinedFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.BytesSent != 612 {
		t.Errorf("BytesSent expected %v, got %v", 612, result.BytesSent)
	}
	if result.ClientIP != "127.0.0.1" {
		t.Errorf("ClientIP expected %v, got %v", "127.0.0.1", result.ClientIP)
	}
	if result.Method != "GET" {
		t.Errorf("Method expected %v, got %v", "GET", result.Method)
	}
	if result.Path != "/" {
		t.Errorf("Path expected %v, got %v", "/", result.Path)
	}
	if result.Protocol != "HTTP/1.1" {
		t.Errorf("Protocol expected %v, got %v", "HTTP/1.1", result.Protocol)
	}
	if result.Status != "200" {
		t.Errorf("Status expected %v, got %v", "200", result.Status)
	}
	if result.Referer != "example.com" {
		t.Errorf("Referer expected %v, got %v", "example.com", result.Referer)
	}
	if result.UserAgent.Family != UAFamily_Other {
		t.Errorf("Family expected %v, got %v", UAFamily_Other, result.UserAgent.Family)
	}
	if result.UserAgent.OS != OSFamily_MacOS {
		t.Errorf("OS expected %v, got %v", OSFamily_MacOS, result.UserAgent.OS)
	}
}

/*
utm_source overrides referer
*/
func TestNginxCombinedFormatWithRefererAndUtmSource(t *testing.T) {
	line := `127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /?a=b&utm_source=justexample HTTP/1.1" 200 612 "https://example.com/somepage" "Mozilla/5.0 (Macintosh)"`

	result, err := ParseNginxCombinedFormat(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.BytesSent != 612 {
		t.Errorf("BytesSent expected %v, got %v", 612, result.BytesSent)
	}
	if result.ClientIP != "127.0.0.1" {
		t.Errorf("ClientIP expected %v, got %v", "127.0.0.1", result.ClientIP)
	}
	if result.Method != "GET" {
		t.Errorf("Method expected %v, got %v", "GET", result.Method)
	}
	if result.Path != "/" {
		t.Errorf("Path expected %v, got %v", "/", result.Path)
	}
	if result.Protocol != "HTTP/1.1" {
		t.Errorf("Protocol expected %v, got %v", "HTTP/1.1", result.Protocol)
	}
	if result.Status != "200" {
		t.Errorf("Status expected %v, got %v", "200", result.Status)
	}
	if result.Referer != "justexample" {
		t.Errorf("Referer expected %v, got %v", "justexample", result.Referer)
	}
	if result.UserAgent.Family != UAFamily_Other {
		t.Errorf("Family expected %v, got %v", UAFamily_Other, result.UserAgent.Family)
	}
	if result.UserAgent.OS != OSFamily_MacOS {
		t.Errorf("OS expected %v, got %v", OSFamily_MacOS, result.UserAgent.OS)
	}
}

/*
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

func TestParseReferer(t *testing.T) {
	/*


	   149.102.254.35 - - [23/May/2025:03:53:41 +0000] "GET /wp-content/plugins/helloapx/wp-apxupx.php?apx=upx HTTP/1.1" 404 363 "https://casualgames.dev/wp-content/plugins/helloapx/wp-apxupx.php?apx=upx" "Go-http-client/1.1"
	*/
	{
		line1 := `149.102.254.35 - - [23/May/2025:03:53:41 +0000] "GET /wp-content/plugins/helloapx/wp-apxupx.php?apx=upx&AAAutm_source=google HTTP/1.1" 301 549 "http://casualgames.dev/wp-content/plugins/helloapx/wp-apxupx.php?apx=upx" "Go-http-client/1.1"`
		parsed, _ := ParseApacheCombinedLogFormat(line1)
		if parsed.Referer != "casualgames.dev" {
			t.Errorf("Expected %v, got %v", "casualgames.dev", parsed.Referer)
		}
	}

	{
		line1 := `149.102.254.35 - - [23/May/2025:03:53:41 +0000] "GET /wp-content/plugins/helloapx/wp-apxupx.php?apx=upx&utm_source=google&otherparam=1 HTTP/1.1" 301 549 "http://casualgames.dev/wp-content/plugins/helloapx/wp-apxupx.php?apx=upx" "Go-http-client/1.1"`
		parsed, _ := ParseApacheCombinedLogFormat(line1)
		if parsed.Referer != "google" {
			t.Errorf("Expected %v, got %v", "google", parsed.Referer)
		}
	}

}
