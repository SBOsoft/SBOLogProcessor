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

package db

import (
	"cmp"
	"database/sql"
	"errors"
	"log/slog"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/SBOsoft/SBOLogProcessor/logparsers"
	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

const MYSQL_DATETIME_FORMAT string = "2006-01-02 15:04:05"

/*
request_ts values in sbo_rawlogs are always in UTC, regardless of the time zone of the log, so that logs from servers in
different time zones are consistent. Metric time windows are in UTC too, see metrics.CalculateTimeWindow.
Converted explicitly instead of relying on the time zone setting of the mysql driver.
*/
func FormatRequestTimestamp(timestamp time.Time) string {
	return timestamp.UTC().Format(MYSQL_DATETIME_FORMAT)
}

type SBOAnalyticsDB struct {
	DbInstance     *sql.DB
	IsInitialized  bool
	syncMutex      sync.Mutex
	domainIdsCache map[string]int
}

func NewSBOAnalyticsDB() *SBOAnalyticsDB {
	rv := SBOAnalyticsDB{
		domainIdsCache: make(map[string]int)}
	return &rv
}

func (sboadb *SBOAnalyticsDB) Init(dbUser string, dbPassword string, dbAddress string, databaseName string) (bool, error) {
	sboadb.syncMutex.Lock()
	defer sboadb.syncMutex.Unlock()
	if sboadb.IsInitialized {
		//already initialized
		return true, nil
	}
	cfg := mysql.NewConfig()
	cfg.User = dbUser
	cfg.Passwd = dbPassword
	cfg.Net = "tcp"
	cfg.Addr = dbAddress
	cfg.DBName = databaseName
	cfg.Params = map[string]string{"charset": "utf8mb4"}

	var err error
	sboadb.DbInstance, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		slog.Error("Failed to connect to mysql db", "error", err)
		return false, err
	}

	pingErr := sboadb.DbInstance.Ping()
	if pingErr != nil {
		slog.Error("Failed to ping the db after connection", "error", pingErr)
		return false, err
	}
	sboadb.IsInitialized = true
	return true, nil
}

func (sboadb *SBOAnalyticsDB) Close() (bool, error) {
	if sboadb.DbInstance == nil {
		stackTrace := debug.Stack()
		slog.Warn("Trying to close an invalid database connection", "stackTrace", string(stackTrace))
		return false, nil
	}
	err := sboadb.DbInstance.Close()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (sboadb *SBOAnalyticsDB) GetDomainId(domainName string, timeWindowSizeInMinutes int) (int, error) {
	sboadb.syncMutex.Lock()
	defer sboadb.syncMutex.Unlock()

	if sboadb.domainIdsCache[domainName] > 0 {
		return sboadb.domainIdsCache[domainName], nil
	}
	//Note timeWindowSizeInMinutes is set only on initial creation, requires manual db update if needed
	// e.g you collected some data with timeWindowSizeInMinutes=10 then you changed it to 5, leaving it unchanged if decreasing should be okay
	// consider updating the db record if increasing timeWindowSizeInMinutes
	result, err := sboadb.DbInstance.Exec("INSERT INTO sbo_domains (domain_name, created, timeWindowSizeMinutes) VALUES (?, now(), ?)", ReduceToMaxColumnLen(domainName, 255), timeWindowSizeInMinutes)
	if err != nil {
		//exists? try to select
		var domainId int
		var savedTimeWindowSizeMinutes int
		row := sboadb.DbInstance.QueryRow("SELECT domain_id, timeWindowSizeMinutes FROM sbo_domains WHERE domain_name = ?", domainName)
		err := row.Scan(&domainId, &savedTimeWindowSizeMinutes)
		if err != nil {
			if err == sql.ErrNoRows {
				slog.Error("Unexpected error. db.GetDomainId could not create a new domain but selecting the existing record also failed", "domainName", domainName)
			}
			return -1, err
		} else {
			if savedTimeWindowSizeMinutes != timeWindowSizeInMinutes {
				//SBOanalytics uses the saved value e.g for links from metrics to logs
				slog.Warn("TimeWindowSizeMinutes in the configuration is different from the value saved for the domain in the database (sbo_domains.timeWindowSizeMinutes). "+
					"Update the database record if you changed TimeWindowSizeMinutes intentionally",
					"domainName", domainName, "configured", timeWindowSizeInMinutes, "savedInDb", savedTimeWindowSizeMinutes)
			}
			sboadb.domainIdsCache[domainName] = domainId
			return domainId, nil
		}
	} else {
		newDomainId, err := result.LastInsertId()
		sboadb.domainIdsCache[domainName] = int(newDomainId)
		return sboadb.domainIdsCache[domainName], err
	}
}

func (sboadb *SBOAnalyticsDB) GetFileId(domainId int, hostname string, filePath string) (int, error) {
	result, err := sboadb.DbInstance.Exec("INSERT INTO sbo_log_files (domain_id, host_name, file_path, created) VALUES (?, ?, ?, now())", domainId, hostname, filePath)
	if err != nil {
		//exists? try to select
		var fileId int
		row := sboadb.DbInstance.QueryRow("SELECT file_id FROM sbo_log_files WHERE domain_id = ? AND host_name=? AND file_path=?", domainId, hostname, filePath)
		err := row.Scan(&fileId)
		if err != nil {
			if err == sql.ErrNoRows {
				slog.Error("Unexpected error. db.GetFileId could not create a new log file entry but selecting the existing record also failed", "domainId", domainId, "hostname", hostname, "filePath", filePath)
			}
			return -1, err
		} else {
			return fileId, nil
		}
	} else {
		newFileId, err := result.LastInsertId()
		return int(newFileId), err
	}
}

// max number of rows in a single multi-row insert statement
const SAVE_METRIC_DATA_BATCH_SIZE int = 500

/*
Saves metric values using multi-row insert statements. When replaceIfExists is false values are added to existing values.
If the same metric (type, key, time window) appears more than once in data, values are applied in order,
i.e they are summed when replaceIfExists is false and the last one wins when replaceIfExists is true.
*/
func (sboadb *SBOAnalyticsDB) SaveMetricDataBatch(data []*metrics.SBOMetricWindowDataToBeSaved, domainId int, replaceIfExists bool) (bool, error) {
	//rows are written in primary key order so that concurrent writers (e.g multiple files for the same domain)
	// lock rows in the same order, which avoids deadlocks
	sorted := sortInPrimaryKeyOrder(data)
	var firstErr error
	for start := 0; start < len(sorted); start += SAVE_METRIC_DATA_BATCH_SIZE {
		end := min(start+SAVE_METRIC_DATA_BATCH_SIZE, len(sorted))
		batch := sorted[start:end]
		sql, args := buildSaveMetricDataBatchStatement(batch, domainId, replaceIfExists)
		err := execWithRetry(sboadb.DbInstance, sql, args)
		if err != nil {
			slog.Error("SaveMetricDataBatch failed, metric values are lost", "domainId", domainId, "rowCount", len(batch), "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr == nil, firstErr
}

// returns a copy sorted by (metric type, time window, key), i.e the primary key order of sbo_metrics.
// The sort is stable so rows for the same metric keep their order, which matters when replaceIfExists is true
func sortInPrimaryKeyOrder(data []*metrics.SBOMetricWindowDataToBeSaved) []*metrics.SBOMetricWindowDataToBeSaved {
	sorted := slices.Clone(data)
	slices.SortStableFunc(sorted, func(a, b *metrics.SBOMetricWindowDataToBeSaved) int {
		if c := cmp.Compare(a.MetricType, b.MetricType); c != 0 {
			return c
		}
		if c := cmp.Compare(a.TimeWindow, b.TimeWindow); c != 0 {
			return c
		}
		return strings.Compare(ReduceToMaxColumnLen(a.KeyValue, 100), ReduceToMaxColumnLen(b.KeyValue, 100))
	})
	return sorted
}

const SAVE_METRIC_DATA_MAX_ATTEMPTS int = 3

/*
Retries statements failing because of deadlocks (1213) or lock wait timeouts (1205). The failing statement is rolled back
by mysql in both cases so it is safe to execute it again, even when it adds to existing values.
Other errors are not retried, e.g after a connection error it is unknown whether the statement was executed or not.
*/
func execWithRetry(dbInstance *sql.DB, statement string, args []any) error {
	var err error
	for attempt := 1; attempt <= SAVE_METRIC_DATA_MAX_ATTEMPTS; attempt++ {
		_, err = dbInstance.Exec(statement, args...)
		if err == nil || !isRetryableError(err) {
			return err
		}
		slog.Warn("Retrying db statement after a deadlock or lock wait timeout", "attempt", attempt, "error", err)
		time.Sleep(time.Duration(attempt*attempt) * 100 * time.Millisecond)
	}
	return err
}

func isRetryableError(err error) bool {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == 1213 || mysqlErr.Number == 1205
	}
	return false
}

func buildSaveMetricDataBatchStatement(batch []*metrics.SBOMetricWindowDataToBeSaved, domainId int, replaceIfExists bool) (string, []any) {
	var sb strings.Builder
	sb.WriteString("INSERT INTO sbo_metrics (domain_id, metric_type, key_value, time_window, metric_value, created) VALUES ")
	args := make([]any, 0, len(batch)*5)
	for i, d := range batch {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("(?, ?, ?, ?, ?, now())")
		args = append(args, domainId, d.MetricType, ReduceToMaxColumnLen(d.KeyValue, 100), d.TimeWindow, d.MetricValue)
	}
	if replaceIfExists {
		sb.WriteString(" ON DUPLICATE KEY UPDATE metric_value=VALUES(metric_value)")
	} else {
		sb.WriteString(" ON DUPLICATE KEY UPDATE metric_value=metric_value+VALUES(metric_value)")
	}
	return sb.String(), args
}

func (sboadb *SBOAnalyticsDB) SaveRawLog(data *logparsers.SBOHttpRequestLog, domainId int, hostId int, maskIPs bool) (bool, error) {
	var sql string = "INSERT INTO sbo_rawlogs (domain_id, host_id, request_ts, client_ip, remote_user, http_method, " +
		" path3, request_uri, http_status, bytes_sent, referer, is_malicious, " +
		" ua_string, ua_os, ua_family, ua_device_type, ua_is_human, ua_intent) " +
		" VALUES (?, ?, ?, "
	if !maskIPs {
		sql += " INET6_ATON(?) "
	} else {
		sql += " null "
	}
	sql += ", ?, ?, " +
		" ?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, ?) "

	var err error = nil
	requestTs := FormatRequestTimestamp(data.Timestamp)
	pathUpTo3rd := data.Path3
	if len(pathUpTo3rd) < 1 {
		pathUpTo3rd = data.Path2
	}
	if len(pathUpTo3rd) < 1 {
		pathUpTo3rd = data.Path1
	}

	if !maskIPs {
		_, err = sboadb.DbInstance.Exec(sql, domainId, hostId, requestTs, data.ClientIP,
			ReduceToMaxColumnLen(data.RemoteUser, 100),
			ReduceToMaxColumnLen(data.Method, 20),
			ReduceToMaxColumnLen(pathUpTo3rd, 100),
			ReduceToMaxColumnLen(data.Path, 100),
			data.Status, data.BytesSent,
			ReduceToMaxColumnLen(data.Referer, 100),
			data.Malicious,
			ReduceToMaxColumnLen(data.UserAgent.FullName, 100),
			ReduceToMaxColumnLen(data.UserAgent.OS, 20),
			ReduceToMaxColumnLen(data.UserAgent.Family, 20),
			ReduceToMaxColumnLen(data.UserAgent.DeviceType, 20),
			ReduceToMaxColumnLen(data.UserAgent.Human, 20),
			ReduceToMaxColumnLen(data.UserAgent.Intent, 20))
	} else {
		_, err = sboadb.DbInstance.Exec(sql, domainId, hostId, requestTs,
			ReduceToMaxColumnLen(data.RemoteUser, 100),
			ReduceToMaxColumnLen(data.Method, 20),
			ReduceToMaxColumnLen(pathUpTo3rd, 100),
			ReduceToMaxColumnLen(data.Path, 100),
			data.Status, data.BytesSent,
			ReduceToMaxColumnLen(data.Referer, 100),
			data.Malicious,
			ReduceToMaxColumnLenKeepingLastPart(data.UserAgent.FullName, 100),
			ReduceToMaxColumnLen(data.UserAgent.OS, 20),
			ReduceToMaxColumnLen(data.UserAgent.Family, 20),
			ReduceToMaxColumnLen(data.UserAgent.DeviceType, 20),
			ReduceToMaxColumnLen(data.UserAgent.Human, 20),
			ReduceToMaxColumnLen(data.UserAgent.Intent, 20))
	}
	if err != nil {
		slog.Error("SaveRawLog failed", "domainId", domainId, "hostId", hostId, "timestamp", data.Timestamp, "error", err)
		return false, err
	} else {
		//slog.Debug("SaveRawLog succeeded", "domainId", domainId, "hostId", hostId, "timestamp", data.Timestamp, "error", err)
		return true, nil
	}
}

func ReduceToMaxColumnLen(str string, colSize int) string {
	if len(str) <= colSize {
		return str
	}
	//TODO assuming ASCII, add unicode support
	return str[:colSize]
}

func ReduceToMaxColumnLenKeepingLastPart(str string, colSize int) string {
	if len(str) <= colSize {
		return str
	}
	//TODO assuming ASCII, add unicode support
	return str[(len(str) - colSize):]
}

// loadAverageValue converts a load average to a number. Unknown ("") or invalid values are saved
// as 0 because the columns are NOT NULL; an empty string would fail the insert in strict mode.
func loadAverageValue(loadAverage string) float64 {
	v, err := strconv.ParseFloat(loadAverage, 64)
	if err != nil {
		return 0
	}
	return v
}

func (sboadb *SBOAnalyticsDB) SaveOSMetrics(uptimeInfo *metrics.UptimeInfo, memoryInfo *metrics.MemoryInfo, hostId int) (bool, error) {
	var sql string = "INSERT INTO sbo_os_metrics (host_id, metrics_ts, up_duration_minutes, users, " +
		" load_average1, load_average5, load_average15, " +
		" swap_use, cache_use, memory_use, memory_free, memory_available) " +
		" VALUES (?, ?, ?, ?, " +
		" ?, ?, ?, " +
		" ?, ?, ?, ?, ?) "
	var swapUse int64 = 0
	var cacheUse int64 = 0
	var memUse int64 = 0
	var memFree int64 = 0
	var memAvailable int64 = 0
	//memoryInfo may be nil
	if memoryInfo != nil {
		swapUse = memoryInfo.SwapUse
		cacheUse = memoryInfo.CachUse
		memUse = memoryInfo.MemUse
		memFree = memoryInfo.MemFree
		memAvailable = memoryInfo.MemAvailable
	}
	// metrics_ts is in UTC like all other saved times, see FormatRequestTimestamp
	_, err := sboadb.DbInstance.Exec(sql, hostId, FormatRequestTimestamp(time.Now()), uptimeInfo.UpDurationMinutes, uptimeInfo.Users,
		loadAverageValue(uptimeInfo.LoadAverage1), loadAverageValue(uptimeInfo.LoadAverage5), loadAverageValue(uptimeInfo.LoadAverage15),
		swapUse, cacheUse, memUse, memFree, memAvailable)
	if err != nil {
		slog.Error("SaveOSMetrics failed", "hostId", hostId, "uptimeInfo", uptimeInfo, "memoryInfo", memoryInfo, "error", err)
		return false, err
	} else {
		return true, nil
	}
}
