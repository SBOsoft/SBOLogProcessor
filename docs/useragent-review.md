# User-Agent Matcher Review — `logparsers/useragent.go`

_Review date: 2026-07-08._

> [!NOTE]
> The 2026-07 matcher-list refresh has been **applied** to `logparsers/useragent.go` (bytespider
> reclassified to AI bots; 2025–2026 AI crawlers, scanners, and script libraries added; the sloppy
> `yandex.` pattern fixed; the inner structural regex hoisted to a package-level `var`; tests
> updated/added). The **code is authoritative.** This doc now lists **open items only**.

## How matching works (context)
1. Six ordered regex matchers run over the **lower-cased** UA string; **first match wins**:
   `reSearchBots → reSocialBots → reMarketingBots → reAIBots → reScannerBots → reScriptAgents`.
   Then a structural parse handles real browsers.
2. Patterns must be lowercase (the UA is lower-cased first).
3. Order matters: a token in an earlier list beats the same substring appearing later — so
   reclassifying a bot means *moving* its token, not just adding it.

---

## Open matcher-content items (left as-is, low priority)

- **`google-extended` is a dead token.** Google-Extended is a robots.txt token, **not** a UA string —
  real Google AI fetches use `googlebot`, `googleother`, or `google-inspectiontool`. It's harmless
  but never matches. Kept for documentation value; could be replaced with `googleother` /
  `google-inspectiontool` if you want to distinguish those.
- **`java` in `reScriptAgents` is broad.** It matches any UA containing "java" (e.g. some legit mobile
  UAs, `javafx`). Low impact because it's the last list checked, but be aware of false positives.

## Open structural improvements (beyond the lists)
- Detect more Chromium-based browsers if browser-level granularity is wanted: **`OPR/`** (Opera),
  **`SamsungBrowser`**, **`YaBrowser`** (Yandex Browser), **`Vivaldi`**, **`Brave`**. Today these fall
  through to Chrome — acceptable, but noted.
- Consider matching **`Windows Phone`**, **`CrOS`** (ChromeOS), **`Linux; Android … TV`** for device
  refinement if useful.
- The `robots.txt` heuristic in `SBOHttpRequestLogSetUserAgent` (any client hitting `/robots.txt` is a
  bot) is reasonable but will mislabel humans who manually open `/robots.txt`. Low impact.

## Open classification/intent ideas
- Add a distinct `RequestIntent_AIAssistant` for **user-triggered** AI fetchers (`chatgpt-user`,
  `perplexity-user`, `claude-user`) vs. bulk training crawlers (`Intent = Processing`/scraping), if
  that distinction matters for SBOanalytics.
- Give attack tooling (`sqlmap`, `nikto`, `nuclei`, `wpscan`, …) `RequestIntent_Malicious` instead of
  `RequestIntent_Scanning` — high-signal for the (future) `security` profile.
- If classification accuracy becomes important, evaluate a maintained UA-parsing library (e.g.
  `uap-go`) — trade-off is a dependency + perf vs. the current lightweight hand-rolled matcher.
