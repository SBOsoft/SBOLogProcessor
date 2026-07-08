# TODO & Potential Improvements — SBOLogProcessor

Compiled from a full-repository review on 2026-07-08 (open items only — resolved items removed).
Cross-references: [`security-and-performance-review.md`](security-and-performance-review.md),
[`useragent-review.md`](useragent-review.md). IDs (P#, R#, S#) map to that review.

Legend: 🔴 bug/correctness · 🟠 performance · 🟡 security/privacy · 🔵 maintainability/feature · ✅ quick win

---

## Medium priority

- [ ] 🟡 **S3 — Unicode-safe truncation.** `db.ReduceToMaxColumnLen` / `...KeepingLastPart` byte-slice
  UTF-8 and can emit invalid UTF-8 to a `utf8mb4` column (row rejected / data dropped). Truncate on
  rune boundaries.
- [ ] 🔴 **R5 — Check write errors in `WriteToFileHandler.HandleEntry`.** Write errors are discarded
  (`_, _ =`); the later `err` check only reflects `json.Marshal`. Capture and handle the write error.
- [ ] 🟡 **S5 — Reconsider IP-masking default.** `SaveLogsToDbMaskIPs` defaults to `false` for
  command-line/bare configs, storing raw client IPs (PII). Default to masked, or document loudly.
- [ ] 🔵 **Consider reading `/proc` instead of shelling out** for OS metrics (`/proc/loadavg`,
  `/proc/uptime`, `/proc/meminfo`) — faster, no subprocess, no locale parsing issues (P4). Keep the
  `free`/`uptime` fallback if desired.

## Lower priority / maintainability

- [ ] 🔵 **Refactor `loadConfigFromFile`.** ~230 lines of repetitive `map[string]interface{}` parsing
  + `_ok` flags + default-merging. The function's own comment says "should be improved." Options:
  use `json.RawMessage` per field, or unmarshal into a struct of pointers (`*int`, `*bool`) so
  "unset vs zero" is distinguishable without the `_ok` bookkeeping, then merge defaults generically.
- [ ] 🔴 **R4 — Ring-buffer wraparound in `MetricGeneratorHandler.addToLastN`** before wiring it up
  (currently dead code; would panic past 50 entries). Also decide/implement the "last N requests →
  detect repeat offenders" feature it was meant for.
- [ ] 🟡 **S1 — Improve malicious-request detection** (or clearly label it best-effort). Decode
  URL-encoding before matching (attackers send `%2e%2e%2f`, `%3Cscript%3E`); current checks miss
  encoded payloads. Consider consolidating traversal/XSS/SQLi into a small ruleset. This is the basis
  for the unimplemented `security` profile.
- [ ] 🔵 **Implement the `security` profile** (README lists it as "not implemented yet"): output
  abusive IPs, attack-pattern stats, blocklist suggestions. Leverage improved S1 detection + scanner
  UA classification.
- [ ] 🔵 **Increase test coverage where it's cheap and high-value:** table-driven tests for each log
  format parser (valid + malformed + edge cases), `calculateTimeWindow`, `ShrinkCounterMapLeavingTopN`,
  and the config default-merge logic.
- [ ] 🔵 **`SkipIfLineMatchesRegex` is documented but not implemented** (`main.go` struct comment says
  "Not implemented yet"). Either implement the pre-filter in `produceLinesFromFile`/`processSingleLogLine`
  or remove it from examples to avoid confusion.
- [ ] 🔵 **Nginx custom format drops `request_time` / `upstream_response_time`** (TODO in
  `ParseNginxCustomFormat`). Capture them if latency metrics are wanted.
- [ ] 🔵 **Graceful shutdown.** No `signal.Notify`/context cancellation — SIGINT/SIGTERM kills mid-flush
  (buffered `WriteToFileHandler` output and in-window metrics are lost, R6). Add signal handling that
  flushes handlers and drains channels.
- [ ] 🔵 **`WriteToFileHandler` durability (R6):** buffered writer flushes only on `End()`. Add periodic
  `Flush()` if crash durability matters.
- [ ] 🟡 **S4 — Document file-permission hygiene:** recommend `chmod 600` for config files (plaintext
  DB password) and note the app log may contain client IPs. Consider env-var / file-ref for the DB
  password. Confirm `.gitignore` excludes real config/log files.
- [ ] 🔵 **Handler mixing caveat:** the example config warns METRICS + COUNTER together "may not work
  as expected." Either make handlers composable or validate/reject unsupported combinations at load
  time with a clear error.
- [ ] 🔵 **Consider a maintained UA-parsing library** (e.g. `uap-go`) if classification accuracy
  becomes important — trade-off is a dependency + perf vs. the current lightweight hand-rolled matcher.

## Housekeeping

- [ ] ✅ Run `gofmt -l .` and `go vet ./...` in CI (`.github/workflows/go.yml`) and consider adding
  `go test -race`.
- [ ] 🔵 Remove large commented-out blocks (e.g. the dead test scaffolding in `useragent_test.go`,
  `getTerminalWidth` in `counter.go`) or move experiments out of the main files.
- [ ] 🔵 Add a `version.txt` reference / `-version` flag (README mentions `version.txt` versioning but
  the flag isn't in `parseCommandArgs`).
