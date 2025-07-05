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

	"github.com/go-sql-driver/mysql"

	"github.com/SBOsoft/SBOLogProcessor/metrics"
)

type SBOAnalyticsDB struct {
	DbInstance *sql.DB
}

func NewSBOAnalyticsDB() *SBOAnalyticsDB {
	rv := SBOAnalyticsDB{}
	return &rv
}

func (sboadb *SBOAnalyticsDB) Init(dbUser string, dbPassword string, dbAddress string, databaseName string) (bool, error) {
	cfg := mysql.NewConfig()
	cfg.User = dbUser
	cfg.Passwd = dbPassword
	cfg.Net = "tcp"
	cfg.Addr = dbAddress
	cfg.DBName = databaseName

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
	return true, nil
}

func (sboadb *SBOAnalyticsDB) Close() (bool, error) {
	err := sboadb.DbInstance.Close()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (sboadb *SBOAnalyticsDB) GetDomainId(domainName string) (int, error) {
	result, err := sboadb.DbInstance.Exec("INSERT INTO sbo_domains (domain_name, created) VALUES (?, now())", domainName)
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
			return domainId, nil
		}
	} else {
		newDomainId, err := result.LastInsertId()
		return int(newDomainId), err
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
	_, err := sboadb.DbInstance.Exec(sql, domainId, data.MetricType, data.KeyValue, data.TimeWindow, data.MetricValue)
	if err != nil {
		slog.Error("SaveMetricData failed", "domainId", domainId, "data.FilePath", data.FilePath, "error", err)
		return false, err
	} else {
		return true, nil
	}
}
