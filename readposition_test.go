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

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// opens the file as the producer does, reads one line, records and saves the read position, closes the file
func readOneLineAndSavePosition(t *testing.T, filePath string, config *ConfigForAMonitoredFile) logLineToProcess {
	tracker := newReadPositionTracker(filePath, config)
	fileReader, err := openFile(false, filePath, tracker)
	if err != nil {
		t.Fatal(err)
	}
	defer fileReader.file.Close()
	lines := make(chan logLineToProcess, 1)
	fileReader.readSingleLineReturnTrueIfEOF(lines)
	item := <-lines
	tracker.update(item)
	tracker.saveIfChanged()
	return item
}

func resumeOffset(t *testing.T, filePath string, config *ConfigForAMonitoredFile) int64 {
	tracker := newReadPositionTracker(filePath, config)
	fileReader, err := openFile(false, filePath, tracker)
	if err != nil {
		t.Fatal(err)
	}
	defer fileReader.file.Close()
	return fileReader.offset
}

func TestReadPositionResumeAndRotation(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "access.log")
	config := &ConfigForAMonitoredFile{StartFrom: START_FROM_BEGINNING, SaveReadPosition: true,
		//does not exist yet, must be created
		ReadPositionDirectory: filepath.Join(dir, "state")}
	globalConfig[filePath] = config
	defer delete(globalConfig, filePath)

	//file is empty when opened, then lines are appended: the fingerprint must not stay empty
	if err := os.WriteFile(filePath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	tracker := newReadPositionTracker(filePath, config)
	fileReader, err := openFile(false, filePath, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if fileReader.fingerprint.Len != 0 {
		t.Errorf("expected empty fingerprint for empty file, got %v", fileReader.fingerprint)
	}
	if err = os.WriteFile(filePath, []byte("line1\nline2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	lines := make(chan logLineToProcess, 1)
	fileReader.readSingleLineReturnTrueIfEOF(lines)
	item := <-lines
	fileReader.file.Close()
	if item.endOffset != 6 || int64(item.fingerprint.Len) < item.endOffset {
		t.Errorf("fingerprint must cover the data up to the offset, offset=%d fingerprint=%v", item.endOffset, item.fingerprint)
	}
	tracker.update(item)
	tracker.saveIfChanged()

	//same file with more data: resume
	if err = os.WriteFile(filePath, []byte("line1\nline2\nline3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if offset := resumeOffset(t, filePath, config); offset != 6 {
		t.Errorf("expected to resume at 6, got %d", offset)
	}

	//rotated: a different, longer file. Must start from the beginning
	if err = os.WriteFile(filePath, []byte("other1\nother2\nother3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if offset := resumeOffset(t, filePath, config); offset != 0 {
		t.Errorf("expected to start from 0 after rotation, got %d", offset)
	}

	//truncated: shorter than the saved offset. Save a position first
	item = readOneLineAndSavePosition(t, filePath, config)
	if err = os.WriteFile(filePath, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if offset := resumeOffset(t, filePath, config); offset != 0 {
		t.Errorf("expected to start from 0 after truncation (saved offset %d), got %d", item.endOffset, offset)
	}
}

func TestReadPositionDisabled(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "access.log")
	config := &ConfigForAMonitoredFile{StartFrom: START_FROM_BEGINNING, SaveReadPosition: false, ReadPositionDirectory: dir}
	globalConfig[filePath] = config
	defer delete(globalConfig, filePath)
	if err := os.WriteFile(filePath, []byte("line1\nline2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	readOneLineAndSavePosition(t, filePath, config)
	if offset := resumeOffset(t, filePath, config); offset != 0 {
		t.Errorf("read position must not be used when disabled, got %d", offset)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "sbologp-readpos-*")); len(matches) > 0 {
		t.Errorf("no state file expected when disabled, got %v", matches)
	}
}
