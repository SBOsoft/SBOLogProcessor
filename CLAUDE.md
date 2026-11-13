# CLAUDE.md — SBOLogProcessor

Guidance for AI assistants (and humans) working in this repository. Read this first.

## What this is

`sbologp` is a single-binary Go CLI that tails/reads web server **access logs** (Apache & Nginx
formats), parses each line, classifies the user agent, detects a few malicious request patterns,
and emits **metrics** and **logs**. Output targets: stdout (counter mode), a re-log file, or a
**MySQL database** consumed by the sister project [SBOanalytics](https://github.com/SBOsoft/SBOanalytics)
(the web front-end). It can also collect host OS metrics (uptime/load/memory) on Linux.

There is **no HTTP server and no UI** in this project — it is a batch/stream processor.

### Three run modes (`-p` profile)
- `count` — read a file, print rolling statistics to stdout every N seconds. No DB needed.
- `metrics` — parse logs, aggregate into time-windowed metrics, optionally write to MySQL. (default)
- `security` — **not implemented yet** (placeholder).

## Architecture / data flow

```
main.go
  parseCommandArgs / loadConfigFromFile        -> globalConfig map[filePath]*ConfigForAMonitoredFile
  per file: goroutine processFile
      produceLinesFromFile   (producer)  --lines chan string-->
      consumeLinesFromChannel (consumer) -> processSingleLogLine
          logparsers.ParseXxx(line)       -> *SBOHttpRequestLog  (auto-detects format on 1st line)
          logparsers.NewSBOUserAgent(ua)  -> classifies UA family/OS/device/human/intent
          handlers (METRICS | COUNTER | WRITE_TO_FILE).HandleEntry(entry)
      processMetricDataToBeSaved (saver)  --SBOMetricWindowDataToBeSaved chan--> db.SaveMetricData
  --OS-metrics-- entry: goroutine setupOSMetricsCollection -> metrics.GetOS* -> db.SaveOSMetrics
```

### Package map
- `main.go` — CLI flags, JSON config loading + default merging, goroutine orchestration, file tailing (`fsnotify`), log rotation handling.
- `logparsers/` — `httpservers.go` (log-line regex parsers, path/referer parsing, weak malicious-pattern detection) and `useragent.go` (UA classification via ordered regex matchers).
- `handlers/` — pluggable `SBOLogHandlerInterface` implementations: `metricgenerator.go`, `counter.go`, `writetofile.go`.
- `metrics/` — `SBOMetrics.go` (in-memory sliding time-window metric aggregation) and `os_metrics.go` (parses Linux `uptime`/`free`).
- `db/` — `mysqldb.go` (all MySQL writes; parameterized queries; domain-id cache).
- `conf/` — example JSON config files (the primary way to configure the tool).

### Key domain types
- `logparsers.SBOHttpRequestLog` — one parsed request line.
- `logparsers.SBOUserAgent` — classification: `Family`, `OS`, `DeviceType`, `Human`, `Intent`.
- `metrics.SBOMetricsManager` — aggregates per (file, time window, metricType, key); values are stored **window-first** with a per-window dirty list, so closing/flushing is proportional to that window's changes. **Everything is log-time based — never use the wall clock in `metrics`** (bulk processing of old files must behave like live logs). `OpenTimeWindow(timestamp)` must be called once per log entry before `AddMetric`; it advances the **watermark** (latest log timestamp; a jump > 5 min moves it only after 3 consecutive such lines) and closes windows whose end + allowed lateness (`max((MetricsWindowSize-1) × TimeWindowSizeMinutes, 10 min)`) is before it. Late entries (additive) and unconfirmed-jump windows are *flagged* and closed at the next flush or 1 min of log time later; replace mode rejects late entries for saved windows. Open windows are capped (lateness/size + 4, outliers evicted first). `CollectDataToBeSaved` (every `MetricsFlushIntervalSeconds`, via `SBOLogHandlerFlusher`) and closing return only changed values — **increments** in additive mode, **totals** in replace mode. `FlushAll` (from `End()`) closes everything.
- `main.ConfigForAMonitoredFile` — per-file config; the field comments at the bottom of `main.go` are the source of truth for config options.

## Build / test / run

```bash
go build -o ./output/bin/sbologp        # build
go vet ./...                            # vet (currently clean)
go test ./...                           # tests — see gotcha below
gofmt -l .                              # formatting check (uses tabs, Go standard)

# run
go run . -f -p=count /var/log/apache2/access.log     # counter mode, follow
go run . -f -c conf/example-config-file.json         # metrics mode via config
```

Config is a JSON **map keyed by file path**, plus two special keys: `--default--` (defaults merged
into every file entry) and `--OS-metrics--` (host metrics collection). See `conf/*.json`.

## Conventions
- Standard Go formatting (tabs). Match the surrounding style; keep the GPLv3 license header on new `.go` files.
- Logging is `log/slog` to `./sbologp-logs.log`. **Never log `DbPassword`** — `ConfigForAMonitoredFile.LogValue()` redacts it; don't bypass it by logging raw DSN/config.
- DB access: **always** use parameterized queries (`?` placeholders) — never string-concatenate SQL. Truncate strings to column widths with `db.ReduceToMaxColumnLen`.
- Errors are generally logged and processing continues (best-effort stream processor); a bad log line should never crash the process.

## Gotchas / landmines (verify before trusting)
- **Metrics vs raw logs consistency** (fixed 2026-11, see git history): in additive mode (`ReplaceExistingMetrics=false`, forced when `SaveReadPosition` is on or several files share a `DomainName`, see `validateAndAdjustConfig` in `main.go`) every added value must reach the DB exactly once as an increment — never emit a value without resetting its unsaved part (`newDataToBeSaved`). In replace mode the emitted values are totals and the saver must preserve their order (later totals win); `processMetricDataToBeSaved` batches without reordering.
- **Graceful shutdown**: SIGINT/SIGTERM closes `globalStopChannel`; producers stop, consumers drain and call handler `End()` (flushes open metric windows), then the read position is saved. A second signal exits immediately. Long-running goroutines must watch `globalStopChannel`, otherwise `wg.Wait()` in `main` hangs.
- **Read position** (`readposition.go`): the producer sends `logLineToProcess{line, endOffset, fingerprint}`; the consumer records the offset after processing and saves it every 10s and at the end. On restart the saved offset is used only if the file still starts with the same bytes (fingerprint, which must always cover min(offset, 1KB) bytes) and isn't shorter than the offset. `SaveReadPosition` defaults to true for config files, false for command-line-only runs.
- **Windows checkout uses CRLF** (`core.autocrlf=true`), so `gofmt -l .` flags every `.go` file there even when correctly formatted — check with `tr -d '\r' < f | gofmt -l` instead.
- **All times saved to the DB are UTC**: `request_ts` in `sbo_rawlogs` (`db.FormatRequestTimestamp`, explicit `.UTC()` — don't rely on the driver's `Loc`) and metric `time_window`s (`metrics.CalculateTimeWindow`). Logs from servers in different time zones must stay consistent; never use the log's local time for anything saved. SBOanalytics must treat these values as UTC. Metric rows saved before 2026-11 used the log's local time.
- Raw logs use the domain parsed from the log line (vhost formats); metrics always use the configured `DomainName`. This mismatch is accepted.
- **`go test ./...` fails on non-Linux** (`metrics` package): the OS-metrics tests shell out to `uptime`/`free`, which don't exist on Windows/macOS, and the test then nil-derefs the result. On Windows, test just `logparsers` (`go test ./logparsers/`) or expect that panic. This is a test/robustness bug, not your change breaking things.
- Hot-path regexes in `logparsers` and `metrics` are now compiled once as package-level `var`s (fixed 2026-07). Keep it that way: never put `regexp.MustCompile` inside a per-line function — declare it at package scope.
- **Format auto-detection** in `processSingleLogLine` uses `:=` inside the detection loop, which means the detection line (typically the first line of a file) is intentionally **not** processed. This is **deliberate** (skip a possible header line) — do not "fix" it to process the first line. (Latent nit: no `break`, so on the rare line matching multiple formats the last wins; harmless because the format regexes are mutually exclusive.)
- Malicious-request detection (`isSqlInjectionAttempt`, `isXSSAttempt`, `isDirectoryTraversal`) is explicitly a **placeholder** — very weak, do not treat it as a security control.
- `CounterHandler.PrintCounterData` now takes `syncMutex` for the whole print (fixed 2026-07). It's always called separately from `startNewWindow` (which locks independently), so there's no nested locking — keep that invariant if you refactor.
- `MetricGeneratorHandler.addToLastN` is currently **dead code** and would panic (index out of range) past 50 entries if wired up — it lacks ring-buffer wraparound.
- The two sibling projects share a **version scheme** `yyyy.mm.dd.xxxx` and DB migration ordering; DB schema lives in SBOanalytics, not here.

## Where to look first for common tasks
- Add/adjust a **log format** → `logparsers/httpservers.go` + register it in the `formats` slice in `main.go` `processSingleLogLine`.
- Add/adjust **user-agent matching** → `logparsers/useragent.go` (ordered matcher blocks in `NewSBOUserAgent`). See `docs/useragent-review.md` for a proposed refreshed matcher set.
- Add a **metric type** → constants in `metrics/SBOMetrics.go` + emit it in `handlers/metricgenerator.go` + persist in `db/mysqldb.go`.
- Add a **config option** → `ConfigForAMonitoredFile` struct + `loadConfigFromFile` parsing + default-merge block, all in `main.go`.

## Before you finish
- Run `gofmt -l .` and `go vet ./...`.
- Keep changes minimal and in the existing style; this is a personal/small project with intentionally low test coverage (per README).
