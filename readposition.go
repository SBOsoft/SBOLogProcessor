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

/*
Saving and restoring the read position (byte offset) for monitored files, so that a restarted process
continues from where the previous one stopped instead of processing (and saving) the same lines again.

The saved position is used only if the file is still the same file: the beginning of the file must match
a fingerprint (hash of the first bytes) saved with the position and the file must not be shorter than the
saved offset. Otherwise the file was rotated or truncated and processing starts from the beginning.
*/

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// max number of bytes from the beginning of the file used for fingerprinting
const READ_POSITION_FINGERPRINT_MAX_LEN int = 1024

// how often the read position is saved while processing
const READ_POSITION_SAVE_INTERVAL time.Duration = 10 * time.Second

type fileFingerprint struct {
	Len  int
	Hash string
}

// a line read from a monitored file, along with the position in the file right after the line
type logLineToProcess struct {
	line        string
	endOffset   int64
	fingerprint fileFingerprint
}

type savedReadPosition struct {
	FilePath    string
	Offset      int64
	Fingerprint fileFingerprint
	Updated     string
}

func computeFileFingerprint(file *os.File, length int) fileFingerprint {
	buf := make([]byte, length)
	//ReadAt does not change the current offset of the file
	n, _ := file.ReadAt(buf, 0)
	sum := sha256.Sum256(buf[:n])
	return fileFingerprint{Len: n, Hash: hex.EncodeToString(sum[:])}
}

/*
Tracks the read position for a single file. Not safe for concurrent use: updated and saved
by the consumer goroutine and saved one last time after the consumer is done.
*/
type readPositionTracker struct {
	enabled       bool
	stateFilePath string
	position      savedReadPosition
	dirty         bool
	//true after a failed save, used to avoid logging the same error every READ_POSITION_SAVE_INTERVAL
	saveFailing bool
}

func newReadPositionTracker(filePath string, config *ConfigForAMonitoredFile) *readPositionTracker {
	rv := readPositionTracker{enabled: config.SaveReadPosition}
	if rv.enabled {
		rv.stateFilePath = readPositionStateFilePath(filePath, config.ReadPositionDirectory)
		rv.position.FilePath = filePath
		stateDir := filepath.Dir(rv.stateFilePath)
		if err := os.MkdirAll(stateDir, 0755); err != nil {
			slog.Error("Failed to create directory for saving read positions, read position will NOT be saved. Check ReadPositionDirectory configuration option",
				"filePath", filePath, "directory", stateDir, "error", err)
			rv.enabled = false
		}
	}
	return &rv
}

// state file name is derived from the absolute path of the monitored file
func readPositionStateFilePath(filePath string, directory string) string {
	if len(directory) < 1 {
		directory = "."
	}
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}
	h := fnv.New64a()
	h.Write([]byte(absPath))
	return filepath.Join(directory, fmt.Sprintf("sbologp-readpos-%s-%016x.json", filepath.Base(filePath), h.Sum64()))
}

// call after a line is processed
func (tracker *readPositionTracker) update(item logLineToProcess) {
	if !tracker.enabled {
		return
	}
	tracker.position.Offset = item.endOffset
	tracker.position.Fingerprint = item.fingerprint
	tracker.dirty = true
}

func (tracker *readPositionTracker) saveIfChanged() {
	if !tracker.enabled || !tracker.dirty {
		return
	}
	tracker.position.Updated = time.Now().Format(time.RFC3339)
	data, err := json.Marshal(tracker.position)
	if err != nil {
		slog.Error("Failed to serialize read position", "stateFile", tracker.stateFilePath, "error", err)
		return
	}
	//write to a temp file and rename so that a crash during the write does not leave a corrupt state file
	tmpFile := tracker.stateFilePath + ".tmp"
	if err = os.WriteFile(tmpFile, data, 0644); err == nil {
		err = os.Rename(tmpFile, tracker.stateFilePath)
	}
	if err != nil {
		//will be retried, log only the first failure
		if !tracker.saveFailing {
			slog.Error("Failed to save read position, will keep retrying. Further errors will not be logged until saving succeeds", "stateFile", tracker.stateFilePath, "error", err)
			tracker.saveFailing = true
		}
		return
	}
	if tracker.saveFailing {
		slog.Info("Saving read position succeeded after previous failures", "stateFile", tracker.stateFilePath)
		tracker.saveFailing = false
	}
	tracker.dirty = false
}

/*
Returns the saved offset if there is a saved read position for this file and it is still valid for the opened file.
*/
func (tracker *readPositionTracker) getResumeOffset(file *os.File) (int64, bool) {
	if !tracker.enabled {
		return 0, false
	}
	data, err := os.ReadFile(tracker.stateFilePath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("Failed to read saved read position", "stateFile", tracker.stateFilePath, "error", err)
		}
		return 0, false
	}
	var saved savedReadPosition
	if err = json.Unmarshal(data, &saved); err != nil {
		slog.Warn("Ignoring invalid saved read position", "stateFile", tracker.stateFilePath, "error", err)
		return 0, false
	}
	fileInfo, err := file.Stat()
	if err != nil {
		slog.Warn("Failed to stat file, ignoring saved read position", "filePath", tracker.position.FilePath, "error", err)
		return 0, false
	}
	if saved.Offset < 0 || fileInfo.Size() < saved.Offset {
		slog.Info("File is shorter than the saved read position, it was probably rotated or truncated. Ignoring saved read position",
			"filePath", tracker.position.FilePath, "savedOffset", saved.Offset, "fileSize", fileInfo.Size())
		return 0, false
	}
	if computeFileFingerprint(file, saved.Fingerprint.Len) != saved.Fingerprint {
		slog.Info("Beginning of the file does not match the saved read position, it was probably rotated. Ignoring saved read position",
			"filePath", tracker.position.FilePath, "savedOffset", saved.Offset)
		return 0, false
	}
	tracker.position = saved
	return saved.Offset, true
}
