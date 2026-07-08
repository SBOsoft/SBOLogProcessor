# Security & Performance Review — SBOLogProcessor

_Review date: 2026-07-08. Scope: full repository at branch `main` (commit `a934866`)._

> [!NOTE]
> This lists **open findings only**. Fixed on 2026-07-08 and removed from this doc: P1 (per-line regex
> compilation), P2 (format-detection recompile), R2 (counter data race), R3 (uptime nil-deref). R1
> (first-line skip) was confirmed **intentional** and closed. Remaining items are tracked in
> [`todo.md`](todo.md).

This is a code review, not a pen-test. The tool processes **untrusted input** (attacker-controlled
access-log lines: URLs, user-agent strings, referers) so input-handling robustness matters. Findings
are grouped by severity.

---

## Summary

Overall the code is reasonable for a small personal streaming log processor. **No SQL injection was
found** — all DB writes use parameterized queries, which is the single most important thing done
right given the input source. The highest-severity issues (per-line regex compilation, a counter
data race, and an OS-metrics parsing panic) have been fixed. Remaining open items are lower-severity:
malicious-request detection that is explicitly a placeholder and must not be relied upon, UTF-8-safe
truncation, IP-masking defaults, and a few robustness/error-handling gaps.

---

## Security findings

### S1 — (Info/By design) Malicious-request detection is a weak placeholder
`logparsers/httpservers.go`: `isSqlInjectionAttempt`, `isXSSAttempt`, `isDirectoryTraversal` use
trivial substring/regex checks (`'.*(insert|update|exec)`, `<script|alert|...`, `/../`, `%00`).
These produce many false negatives and some false positives. The code comments already say
"placeholders for now." **Risk:** anyone reading the `is_malicious` column may over-trust it.
**Action:** document clearly as best-effort; do not gate any security decision on it. Consider
decoding URL-encoding before matching (attackers send `%2e%2e%2f`, `%3Cscript%3E`) — current checks
run on `RawQuery`/decoded path inconsistently and miss encoded payloads.

### S2 — (Low) Log injection / unsanitized untrusted fields in logs
Parsed fields (user-agent, path, referer, client IP) are written to `sbologp-logs.log` via `slog`.
`slog`'s text handler quotes values, which mitigates most CRLF-injection, but very large UA strings
are logged verbatim in error paths (e.g. `SaveRawLog` failure logs the whole entry). **Action:**
keep using slog structured attrs (already done); avoid logging entire request structs at Info level.

### S3 — (Low) `ReduceToMaxColumnLen` byte-slices UTF-8 → possible invalid UTF-8 to MySQL
`db/mysqldb.go`: `str[:colSize]` / `str[len-colSize:]` cut on **byte** boundaries. A multibyte
UTF-8 sequence (common in paths/referers/UA) can be split, producing invalid UTF-8. With the
`utf8mb4` charset MySQL may reject the row or store replacement chars, silently dropping a log.
The code's own `//TODO assuming ASCII, add unicode support` acknowledges this. **Action:** truncate
on rune boundaries (`utf8.RuneCountInString` + rune-safe slice, or `[]rune` conversion).

### S4 — (Low) DB credentials stored in plaintext config; log file world-readable-ish
Config JSON holds `DbPassword` in cleartext (unavoidable for this design, and `LogValue()` correctly
redacts it in logs — good). The app log `./sbologp-logs.log` is created `0644` and may contain client
IPs; the re-log file is `0640`. **Action:** document that the config file and log file should have
restricted permissions (e.g. `chmod 600` the config). Consider supporting an env var / file-reference
for the DB password. Ensure `.gitignore` excludes real config files (it should — verify).

### S5 — (Info) IP masking is opt-in, not default
`SaveLogsToDbMaskIPs` defaults to `false` when set via command line / unset in a bare config, so raw
client IPs (PII under GDPR) are stored unless explicitly masked. The example config sets it `true`.
**Action:** consider defaulting to masked, or prominently documenting the privacy implication.

### S6 — (Info) External command execution for OS metrics
`metrics/os_metrics.go` shells out to `uptime` and `free` with fixed argv (no user input in the
command), so no injection risk. It is Linux-only and fragile (see P4). Fine as-is security-wise.

**No SQL injection, no path traversal in file handling, no unsafe deserialization found.** Config is
parsed with `encoding/json` into typed structures.

---

## Performance findings

### P3 — (Low) `ShrinkCounterMapLeavingTopN` allocates several maps per print interval
Called for `Clients`, `Referers`, `RequestedPaths` on every output tick; builds a
`map[int64]map[string]int64` plus a slice plus a replacement map. For high-cardinality client-IP maps
this is O(n) allocation each tick. Acceptable at 30s intervals but could use a bounded heap
(`container/heap`) or partial sort if intervals shorten or cardinality grows.

### P4 — (Low) `metrics` OS collection spawns subprocesses
`GetOSUptimeInfo`/`GetOSMemoryInfo` fork `uptime`/`free` each run. Runs only every N minutes so impact
is negligible, but consider reading `/proc/loadavg`, `/proc/uptime`, `/proc/meminfo` directly instead
of shelling out (faster, no locale issues, no subprocess).

---

## Concurrency / correctness findings

### R4 — (Low, latent panic) `addToLastN` lacks ring-buffer wraparound
`handlers/metricgenerator.go`: `lastNPosition++` with no modulo over a size-50 slice → index out of
range after 50 entries. Currently **dead code** (never called), so harmless today, but a trap if
someone wires up the "last N requests" feature. **Action:** `handler.lastNPosition = (handler.lastNPosition + 1) % len(handler.lastNEntries)` when implementing.

### R5 — (Low) `WriteToFileHandler.HandleEntry` ignores write errors
`_, _ = handler.fileWriter.WriteString(...)` discards the error; the later `if err != nil` checks a
stale `err` from `json.Marshal`, never the write. Disk-full / broken-pipe would be silently lost.
**Action:** capture and check the write error.

### R6 — (Info) `bufio.Writer` in `WriteToFileHandler` flushed only on `End()`
If the process is killed (SIGKILL) buffered lines are lost. Acceptable for a re-logger; consider
periodic `Flush()` if durability matters.

---

## Things done well (keep)
- Parameterized SQL everywhere; DSN password redaction via `LogValue()`.
- Clean producer/consumer/saver goroutine split with buffered channels and `sync.WaitGroup`.
- Domain-id caching under a mutex to avoid repeated lookups.
- Log-rotation handling (rename/remove → reopen with retries) in `produceLinesFromFile`.
- Column-length clamping before DB writes (modulo the UTF-8 caveat in S3).
- Best-effort philosophy: bad lines are skipped rather than aborting the run.
