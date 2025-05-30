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

	UAFamily_Other     int = 0
	UAFamily_Chrome    int = 10
	UAFamily_Firefox   int = 20
	UAFamily_Safari    int = 30
	UAFamily_Edge      int = 40
	UAFamily_SearchBot int = 100
	UAFamily_AIBot     int = 200
	UAFamily_Script    int = 300
	UAFamily_OtherBot  int = 400

	OSFamily_Other   int = 0
	OSFamily_Windows int = 10
	OSFamily_MacOS   int = 20
	OSFamily_Linux   int = 30
	OSFamily_Android int = 40
	OSFamily_IOS     int = 50

	DeviceType_Unknown int = 0
	DeviceType_Desktop int = 10
	DeviceType_Mobile  int = 20
	DeviceType_Script  int = 30

	Human_Yes     int = 1
	Human_No      int = 2
	Human_Unknown int = 0

	RequestIntent_Unknown   int = 0
	RequestIntent_Scraping  int = 2
	RequestIntent_Malicious int = 3
)

type SBOUserAgent struct {
	FullName   string
	OS         int
	Family     int
	DeviceType int
	Human      int
	Intent     int
}

func NewSBOUserAgent(uaString string) *SBOUserAgent {
	ua := SBOUserAgent{}
	ua.FullName = uaString
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
		if strings.HasPrefix(before, "facebook") {
			ua.Family = UAFamily_OtherBot
			ua.DeviceType = DeviceType_Script
			ua.Human = Human_No
		} else if strings.HasPrefix(before, "meta-") {
			ua.Family = UAFamily_AIBot
			ua.DeviceType = DeviceType_Script
			ua.Human = Human_No
		} else if strings.HasSuffix(after, "Bytespider") {
			ua.Family = UAFamily_OtherBot
			ua.DeviceType = DeviceType_Script
			ua.Human = Human_No
		} else if strings.HasSuffix(after, "Python") {
			ua.Family = UAFamily_Script
			ua.DeviceType = DeviceType_Script
			ua.Human = Human_No
		} else {
			var foundCrios bool = false
			var foundChrome bool = false
			var foundSafari bool = false
			var foundFirefox bool = false
			var foundEdge bool = false

			var rx = regexp.MustCompile(`\s*\(([^)]+)\)|\s*([^/]+/[^ ]+)`)
			matches := rx.FindAllStringSubmatch(after, -1)
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
				/*
					for x := range v {
						fmt.Printf("matches %v %v %v \n", x, v[x], len(v[x]))
					}
				*/
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

	//slog.Debug("SBOUserAgent", "ua", ua)
	return &ua
}

func processCompatiblePart(ua *SBOUserAgent, compatiblePart string) {
	if strings.Contains(compatiblePart, "Googlebot") {
		ua.DeviceType = DeviceType_Script
		ua.Human = Human_No
		ua.Family = UAFamily_SearchBot
	} else if strings.Contains(compatiblePart, "yandex") {
		ua.DeviceType = DeviceType_Script
		ua.Human = Human_No
		ua.Family = UAFamily_SearchBot
	} else if strings.Contains(compatiblePart, "bingbot") {
		ua.DeviceType = DeviceType_Script
		ua.Human = Human_No
		ua.Family = UAFamily_SearchBot
	} else if strings.Contains(compatiblePart, "ahrefs") {
		ua.DeviceType = DeviceType_Script
		ua.Human = Human_No
		ua.Family = UAFamily_OtherBot
	} else if strings.Contains(compatiblePart, "Bytespider") {
		ua.Family = UAFamily_OtherBot
		ua.DeviceType = DeviceType_Script
		ua.Human = Human_No
	} else if strings.Contains(compatiblePart, "bot") {
		ua.DeviceType = DeviceType_Script
		ua.Human = Human_No
		ua.Family = UAFamily_OtherBot
	}
}
