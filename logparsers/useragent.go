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

package logparsers

import (
	"regexp"
	"strings"
)

/*
Not a perfect solution which will identify every single user agent
we just want to know if it's chrome, firefox, safari, bot, script, other
and high level OS info, windows, iphoneos, macos, android, other

Typical user-agent headers
chrome
	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Edge
	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59
Safari
 	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15
Firefox
	Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0
ios
safari
	Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1
chrome
	Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/137.0.7151.51 Mobile/15E148 Safari/604.1
	Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1
	Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1

Android
	Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.127 Mobile Safari/537.36
	Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.127 Mobile Safari/537.36

# We also want bots like Google, Yandex, Bing, OpenAI and other AI bots

Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
Mozilla/5.0 (compatible; YandexAccessibilityBot/3.0; +http://yandex.com/bots)

We also want to detect scripts like curl, go-http-client etc
*/

const (
	UA_NAME_SAFARI  string = "Safari"
	UA_NAME_CRIOS   string = "CriOS"
	UA_NAME_EDGE    string = "Edg"
	UA_NAME_CHROME  string = "Chrome"
	UA_NAME_FIREFOX string = "Firefox"

	UAFamily_Other     string = "Other"
	UAFamily_Chrome    string = "Chrome"
	UAFamily_Firefox   string = "Firefox"
	UAFamily_Safari    string = "Safari"
	UAFamily_Edge      string = "Edge"
	UAFamily_SearchBot string = "SearchBot"
	UAFamily_AIBot     string = "AIBot"
	UAFamily_Script    string = "Script"
	UAFamily_SocialBot string = "SocialBot"
	UAFamily_OtherBot  string = "OtherBot"
	UAFamily_SEOBot    string = "SEOBot"
	UAFamily_Scanner   string = "Scanner"

	OSFamily_Other   string = "Other"
	OSFamily_Windows string = "Windows"
	OSFamily_MacOS   string = "MacOS"
	OSFamily_Linux   string = "Linux"
	OSFamily_Android string = "Android"
	OSFamily_IOS     string = "IOS"

	DeviceType_Unknown string = "Unknown"
	DeviceType_Desktop string = "Desktop"
	DeviceType_Mobile  string = "Mobile"
	DeviceType_Script  string = "Script"

	Human_Yes     string = "Human"
	Human_No      string = "NonHuman"
	Human_Unknown string = "Unknown"

	RequestIntent_Unknown    string = "Unknown"
	RequestIntent_Scraping   string = "Scraping"
	RequestIntent_Malicious  string = "Malicious"
	RequestIntent_Scanning   string = "Scanning"
	RequestIntent_Processing string = "Processing"
)

// Matchers run in order; first match wins. All patterns are lowercase because the
// UA string is lower-cased before matching. Refreshed 2026-07 - see docs/useragent-review.md.

// Search-engine crawlers (indexing)
var reSearchBots *regexp.Regexp = regexp.MustCompile(`(googlebot|bingbot|baiduspider|yandexbot|duckduckbot|applebot|petalbot|seznambot|sogou|exabot|bravebot|googleother|google-inspectiontool|coccocbot|mojeekbot|yeti)`)

// Social / link-preview / messaging unfurlers
var reSocialBots *regexp.Regexp = regexp.MustCompile(`(facebookexternalhit|facebookcatalog|twitterbot|linkedinbot|pinterest|slackbot|slack-imgproxy|telegrambot|whatsapp|discordbot|redditbot|skypeuripreview|vkshare|embedly|flipboard|tumblr)`)

// SEO / marketing / analytics crawlers
var reMarketingBots *regexp.Regexp = regexp.MustCompile(`(ahrefs|semrush|dotbot|mj12bot|seobilitybot|siteauditbot|blexbot|dataforseobot|barkrowler|serpstatbot|screaming ?frog|screamingfrogseospider|zoominfobot|awariobot|linkdexbot|rogerbot|majestic|seokicks|sistrix|cocolyzebot|yandeximages)`)

// AI / LLM crawlers: training-data collectors AND user-triggered fetchers.
// Note: bytespider (ByteDance) is an AI training crawler, classified here (not as a social bot).
var reAIBots *regexp.Regexp = regexp.MustCompile(`(gptbot|oai-searchbot|chatgpt-user|chatgpt|claudebot|claude-user|claude-searchbot|anthropic-ai|google-extended|googlebot-news|meta-externalagent|meta-externalfetcher|bytespider|amazonbot|bedrockbot|novaact|perplexitybot|perplexity-user|youbot|cohere-ai|cohere-training-data-crawler|mistralai-user|diffbot|imagesiftbot|omgili|omgilibot|webzio-extended|timpibot|duckassistbot|ai2bot|semanticscholarbot|panscient|friendlycrawler|velenpublicwebcrawler)`)

// Security scanners / internet-measurement / attack tooling
var reScannerBots *regexp.Regexp = regexp.MustCompile(`(censysinspect|censys|expanse|internet-measurement|internetmeasurement|paloaltonetworks|aliyunsecbot|nmap|masscan|zgrab|zmap|shodanbot|shodan|urlscan|tchelebi|binaryedge|criminalip|netsystemsresearch|l9scan|leakix|odin|nuclei|sqlmap|nikto|wpscan|dirbuster|gobuster|feroxbuster|acunetix|nessus|projectdiscovery)`)

// Generic scripts / HTTP libraries / headless browsers
var reScriptAgents *regexp.Regexp = regexp.MustCompile(`(curl|scrapy|wget|python|python-requests|aiohttp|httpx|go-http-client|java|okhttp|ruby|postman|insomnia|axios|got |node-fetch|undici|guzzlehttp|libwww-perl|lwp::|winhttp|dart|symfony|headlesschrome|phantomjs|puppeteer|playwright|selenium|http_request|cloudflare-traffic-manager)`)

// Structural regex for parsing real browser UA strings: matches parenthesised
// groups "(...)" or "token/version" pairs. Compiled once (hot path, per UA).
var reUAStructure *regexp.Regexp = regexp.MustCompile(`\s*\(([^)]+)\)|\s*([^/]+/[^ ]+)`)

type SBOUserAgent struct {
	FullName   string
	OS         string
	Family     string
	DeviceType string
	Human      string
	Intent     string
}

func NewSBOUserAgent(uaString string) *SBOUserAgent {
	ua := SBOUserAgent{
		FullName:   uaString,
		OS:         OSFamily_Other,
		Family:     UAFamily_Other,
		DeviceType: DeviceType_Unknown,
		Human:      Human_Unknown,
		Intent:     RequestIntent_Unknown}

	lowerUaString := strings.ToLower(uaString)
	if foundMatch := reSearchBots.FindString(lowerUaString); len(foundMatch) > 0 {
		ua.DeviceType = DeviceType_Script
		ua.Family = UAFamily_SearchBot
		ua.Human = Human_No
		ua.Intent = RequestIntent_Processing
	} else if foundMatch := reSocialBots.FindString(lowerUaString); len(foundMatch) > 0 {
		ua.DeviceType = DeviceType_Script
		ua.Family = UAFamily_SocialBot
		ua.Human = Human_No
		ua.Intent = RequestIntent_Processing
	} else if foundMatch := reMarketingBots.FindString(lowerUaString); len(foundMatch) > 0 {
		ua.DeviceType = DeviceType_Script
		ua.Family = UAFamily_SEOBot
		ua.Human = Human_No
		ua.Intent = RequestIntent_Processing
	} else if foundMatch := reAIBots.FindString(lowerUaString); len(foundMatch) > 0 {
		ua.DeviceType = DeviceType_Script
		ua.Family = UAFamily_AIBot
		ua.Human = Human_No
		ua.Intent = RequestIntent_Processing
	} else if foundMatch := reScannerBots.FindString(lowerUaString); len(foundMatch) > 0 {
		ua.DeviceType = DeviceType_Script
		ua.Family = UAFamily_Scanner
		ua.Human = Human_No
		ua.Intent = RequestIntent_Scanning
	} else if foundMatch := reScriptAgents.FindString(lowerUaString); len(foundMatch) > 0 {
		ua.DeviceType = DeviceType_Script
		ua.Family = UAFamily_Script
		ua.Human = Human_No
		ua.Intent = RequestIntent_Scraping
	} else {
		before, after, found := strings.Cut(uaString, " ")
		if !found {
			lowerBefore := strings.ToLower(before)
			if strings.Contains(lowerBefore, "google") {
				ua.Family = UAFamily_SearchBot
			} else if strings.HasPrefix(lowerBefore, "facebook") {
				ua.Family = UAFamily_OtherBot
				ua.DeviceType = DeviceType_Script
			} else if strings.HasPrefix(lowerBefore, "meta-") {
				ua.Family = UAFamily_AIBot
				ua.DeviceType = DeviceType_Script
			} else if strings.Contains(lowerBefore, "curl") || strings.HasPrefix(lowerBefore, "go-") || strings.Contains(lowerBefore, "java") || strings.Contains(lowerBefore, "apache") || strings.Contains(lowerBefore, "php") || strings.Contains(lowerBefore, "python") || strings.Contains(lowerBefore, "requests") {
				ua.Family = UAFamily_Script
			} else {
				//ua.Human = Human_No
			}
			ua.Human = Human_No
		} else {
			var foundCrios bool = false
			var foundChrome bool = false
			var foundSafari bool = false
			var foundFirefox bool = false
			var foundEdge bool = false

			matches := reUAStructure.FindAllStringSubmatch(after, -1)
			for _, v := range matches {
				if len(v[1]) > 0 { //paranthesis
					if strings.HasPrefix(v[1], "Windows") {
						ua.DeviceType = DeviceType_Desktop
						ua.OS = OSFamily_Windows
					} else if strings.HasPrefix(v[1], "Mac") {
						ua.DeviceType = DeviceType_Desktop
						ua.OS = OSFamily_MacOS
					} else if strings.HasPrefix(v[1], "iPhone") || strings.HasPrefix(v[1], "iPad") {
						ua.DeviceType = DeviceType_Mobile
						ua.OS = OSFamily_IOS
					} else if strings.Contains(v[1], "Android") {
						ua.DeviceType = DeviceType_Mobile
						//update if it's some google bot
						if strings.Contains(v[1], "Googlebot") {
							ua.Human = Human_No
						}
						ua.OS = OSFamily_Android
					} else if strings.Contains(v[1], "Linux") {
						ua.DeviceType = DeviceType_Desktop
						ua.OS = OSFamily_Linux
					} else if strings.HasPrefix(v[1], "compatible") {
						processCompatiblePart(&ua, v[1])
					} else if strings.Contains(v[1], "Claude") {
						ua.Human = Human_No
						ua.Family = UAFamily_AIBot
						ua.DeviceType = DeviceType_Script
					}
				} else if len(v[2]) > 0 { //xxxx/yyyy
					if strings.HasPrefix(v[2], UA_NAME_CHROME) {
						ua.Family = UAFamily_Chrome
						foundChrome = true
					} else if strings.HasPrefix(v[2], UA_NAME_SAFARI) {
						ua.Family = UAFamily_Safari
						foundSafari = true
					} else if strings.HasPrefix(v[2], UA_NAME_CRIOS) {
						ua.Family = UAFamily_Chrome
						ua.OS = OSFamily_IOS
						foundCrios = true
					} else if strings.HasPrefix(v[2], UA_NAME_EDGE) {
						ua.Family = UAFamily_Edge
						ua.OS = OSFamily_Windows
						foundEdge = true
					} else if strings.HasPrefix(v[2], UA_NAME_FIREFOX) {
						ua.Family = UAFamily_Firefox
						foundFirefox = true
					} else if strings.Contains(v[2], "compatible") {
						processCompatiblePart(&ua, v[2])
					} else if strings.Contains(v[2], "openai") {
						ua.Human = Human_No
						ua.Family = UAFamily_AIBot
						ua.DeviceType = DeviceType_Script
					} else if strings.Contains(v[2], "Claude") {
						ua.Human = Human_No
						ua.Family = UAFamily_AIBot
						ua.DeviceType = DeviceType_Script
					}
				}
			}
			if foundCrios {
				//override
				ua.Family = UAFamily_Chrome
				ua.OS = OSFamily_IOS
			} else if foundEdge {
				ua.Family = UAFamily_Edge
				ua.OS = OSFamily_Windows
			} else if foundSafari && foundChrome {
				ua.Family = UAFamily_Chrome
			} else if foundSafari && !foundChrome && !foundEdge && !foundFirefox {
				ua.Family = UAFamily_Safari
			}

			if ua.Family == UAFamily_SearchBot || ua.Family == UAFamily_OtherBot {
				ua.DeviceType = DeviceType_Script
				ua.OS = OSFamily_Other
				ua.Human = Human_No
			}
		}
	}
	return &ua

}

func processCompatiblePart(ua *SBOUserAgent, compatiblePart string) {
	lowerCompatiblePart := strings.ToLower(compatiblePart)
	if strings.Contains(lowerCompatiblePart, "bot") {
		ua.DeviceType = DeviceType_Script
		ua.Human = Human_No
		ua.Family = UAFamily_OtherBot
		if strings.Contains(lowerCompatiblePart, "blex") {
			ua.DeviceType = UAFamily_SEOBot
			ua.Intent = RequestIntent_Processing
		}
	}
}
