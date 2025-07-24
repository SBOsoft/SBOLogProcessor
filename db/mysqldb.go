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
	"database/sql"
	"log/slog"
	"sync"

	"github.com/go-sql-driver/mysql"

	"github.com/SBOsoft/SBOLogProcessor/logparsers"
	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

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
		row := sboadb.DbInstance.QueryRow("SELECT domain_id FROM sbo_domains WHERE domain_name = ?", domainName)
		err := row.Scan(&domainId)
		if err != nil {
			if err == sql.ErrNoRows {
				slog.Error("Unexpected error. db.GetDomainId could not create a new domain but selecting the existing record also failed", "domainName", domainName)
			}
			return -1, err
		} else {
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

func (sboadb *SBOAnalyticsDB) SaveMetricData(data *metrics.SBOMetricWindowDataToBeSaved, domainId int, replaceIfExists bool) (bool, error) {
	var sql string = "INSERT INTO sbo_metrics (domain_id, metric_type, key_value, time_window, metric_value, created) " +
		" VALUES (?, ?, ?, ?, ?, now()) "
	if replaceIfExists {
		sql += "ON DUPLICATE KEY UPDATE metric_value=VALUES(metric_value)"
	} else {
		sql += "ON DUPLICATE KEY UPDATE metric_value=metric_value+VALUES(metric_value)"
	}
	_, err := sboadb.DbInstance.Exec(sql, domainId, data.MetricType, ReduceToMaxColumnLen(data.KeyValue, 100), data.TimeWindow, data.MetricValue)
	if err != nil {
		slog.Error("SaveMetricData failed", "domainId", domainId, "data.FilePath", data.FilePath, "error", err)
		return false, err
	} else {
		return true, nil
	}
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
	pathUpTo3rd := data.Path3
	if len(pathUpTo3rd) < 1 {
		pathUpTo3rd = data.Path2
	}
	if len(pathUpTo3rd) < 1 {
		pathUpTo3rd = data.Path1
	}

	if !maskIPs {
		_, err = sboadb.DbInstance.Exec(sql, domainId, hostId, data.Timestamp, data.ClientIP,
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
		_, err = sboadb.DbInstance.Exec(sql, domainId, hostId, data.Timestamp,
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
