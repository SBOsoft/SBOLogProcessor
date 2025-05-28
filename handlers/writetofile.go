package handlers

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"os"

	"github.com/SBOsoft/SBOLogProcessor/logparsers"
)

const (
	WRITE_TO_FILE_HANDLER_NAME string = "WRITE_TO_FILE"
)

type WriteToFileHandler struct {
	targetFile *os.File
	fileWriter *bufio.Writer
}

func NewWriteToFileHandler() *WriteToFileHandler {
	var rv = WriteToFileHandler{}
	return &rv
}

func (handler *WriteToFileHandler) Name() string {
	return WRITE_TO_FILE_HANDLER_NAME
}

func (handler *WriteToFileHandler) Begin(targetFilePath string) error {
	var err error

	if len(targetFilePath) < 1 {
		return errors.New("WriteToFileTargetFile must be set in configuration")
	}
	handler.targetFile, err = os.OpenFile(targetFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640)

	if err != nil {
		slog.Error("Error opening file for writing", "filePath", targetFilePath, "error", err)
		return err
	}
	handler.fileWriter = bufio.NewWriter(handler.targetFile)
	slog.Info("WRITE_TO_FILE opened target file", "filePath", targetFilePath)
	return nil
}

func (handler *WriteToFileHandler) HandleEntry(parsedLogEntry *logparsers.SBOHttpRequestLog) (bool, error) {
	if handler.fileWriter == nil {
		return false, nil
	}
	logEntry, err := json.Marshal(parsedLogEntry)
	if err != nil {
		return false, err
	}
	_, _ = handler.fileWriter.WriteString(string(logEntry))
	_, _ = handler.fileWriter.WriteString(string("\n"))

	if err != nil {
		slog.Error("Error writing to file", "filePath", handler.targetFile, "error", err)
		return false, err
	}
	return true, nil
}

func (handler *WriteToFileHandler) End() bool {
	handler.fileWriter.Flush()
	handler.targetFile.Close()

	return true
}
