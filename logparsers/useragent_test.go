package logparsers

import (
	"fmt"
	"testing"
)

/*
	func TestParseUserAgent(t *testing.T) {
		uaString := `Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/137.0.7151.51 Mobile/15E148 Safari/604.1`

		startPos := 0

		pieceCounter := 0

		var pieces []string = make([]string, 0)

		for i, k := range uaString {
			switch {
			case k == '(':
				startPos = i + 1
			case k == ' ' || k == ')':
				pieces = append(pieces, uaString[startPos:(i-1)])
				startPos = i + 1
				pieceCounter++
			}
		}

		for i, k := range pieces {
			fmt.Printf("pieces[%d] %v \n", i, k)
		}

}
*/
// func TestREParseUserAgent(t *testing.T) {
// 	uaString := `Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/137.0.7151.51 Mobile/15E148 Safari/604.1`
// 	//uaString = `Mozilla/5.0 (compatible; YandexAccessibilityBot/3.0; +http://yandex.com/bots)`
// 	//var rx = regexp.MustCompile(`^(?P<moz>[^/]+)/(?P<mozver>\S+)(((\s\(([^)]+)[^)]+\))*(\s([^/]+)/(\S+))*)*)$`)

// 	var rx = regexp.MustCompile(`^(?P<moz>[^/]+)/(?P<mozver>\S+)(\s(\([^)]+\))|(\s(\S+)/(\S+)))*$`)

// 	/*
// 		var rx = regexp.MustCompile(`(\s*
// 		\(
// 		([^;]+);[^)]+
// 		\)
// 		(\s([^/]+)/(\S+))*
// 		)*`)
// 	*/
// 	matches := rx.FindStringSubmatch(uaString)

// 	for i, k := range matches {
// 		fmt.Printf("matches[%d] %v \n", i, k)
// 	}

// }

//^([^/]+/[^ ]+)(\s*\(([^)]+)\))*(\s+([^/]+/\S+)*(\s*\(([^)]+)\))*(\s*([^/]+/[^ ]+))*

// func TestDeepseekParseUserAgent(t *testing.T) {
// 	uaString := `Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/137.0.7151.51 Mobile/15E148 Safari/604.1`
// 	//uaString = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0`
// 	// Define the regex pattern to match the user-agent components
// 	//pattern := `^([^/]+/[^ ]+)(\s*\(([^)]+)\))*(\s+([^/]+/\S+))*(\s*\(([^)]+)\))*(\s*([^/]+/[^ ]+))*`

// 	pattern := `^([^/]+/[^ ]+)(\s*\(([^)]+)\))*(\s+([^/]+/\S+))*(\s*\(([^)]+)\))*(\s*([^/]+/[^ ]+))*`

// 	re, err := regexp.Compile(pattern)
// 	if err != nil {
// 		fmt.Printf("failed to compile regex: %v", err)
// 		return
// 	}

// 	// Match the user-agent string
// 	matches := re.FindStringSubmatch(uaString)
// 	if matches == nil {
// 		fmt.Printf("user-agent string doesn't match expected pattern")
// 		return
// 	}
// 	/*
// 		// Extract the components into a map
// 		components := map[string]string{
// 			"user_agent":         strings.TrimSpace(matches[1]),
// 			"device_info":        strings.TrimSpace(matches[2]),
// 			"engine":             strings.TrimSpace(matches[3]),
// 			"engine_info":        strings.TrimSpace(matches[4]),
// 			"browser":            strings.TrimSpace(matches[5]),
// 			"mobile_info":        strings.TrimSpace(matches[6]),
// 			"browser_compatible": strings.TrimSpace(matches[7]),
// 		}

// 		for i, k := range components {
// 			fmt.Printf("components[%v] %v \n", i, k)
// 		}
// 	*/
// 	for i, k := range matches {
// 		fmt.Printf("matches[%d] %v \n", i, k)
// 	}

// }

func TestParseUserAgentIphone(t *testing.T) {
	uaString := `Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/137.0.7151.51 Mobile/15E148 Safari/604.1`
	/*
		uaString = `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot`
		uaString = `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)`
	*/
	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Mobile {
		t.Errorf("Expected DeviceType_Mobile but got %v", ua.DeviceType)
	}
	if ua.DeviceType != DeviceType_Mobile {
		t.Errorf("Expected DeviceType_Mobile but got %v", ua.DeviceType)
	}
	if ua.Family != UAFamily_Chrome {
		t.Errorf("Expected UAFamily_Chrome but got %v", ua.Family)
	}
	if ua.Human != Human_Unknown {
		t.Errorf("Expected Human_Unknown but got %v", ua.Human)
	}

	if ua.OS != OSFamily_IOS {
		t.Errorf("Expected OSFamily_IOS but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentOpenAI(t *testing.T) {
	uaString := `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_AIBot {
		t.Errorf("Expected UAFamily_AIBot but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentChrome(t *testing.T) {
	uaString := `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Desktop {
		t.Errorf("Expected DeviceType_Desktop but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_Chrome {
		t.Errorf("Expected UAFamily_Chrome but got %v", ua.Family)
	}
	if ua.Human != Human_Unknown {
		t.Errorf("Expected Human_Unknown but got %v", ua.Human)
	}

	if ua.OS != OSFamily_MacOS {
		t.Errorf("Expected OSFamily_MacOS but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentEdge(t *testing.T) {
	uaString := `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Desktop {
		t.Errorf("Expected DeviceType_Desktop but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_Edge {
		t.Errorf("Expected UAFamily_Edge but got %v", ua.Family)
	}
	if ua.Human != Human_Unknown {
		t.Errorf("Expected Human_Unknown but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Windows {
		t.Errorf("Expected OSFamily_Windows but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentSafari(t *testing.T) {
	uaString := `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Desktop {
		t.Errorf("Expected DeviceType_Desktop but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_Safari {
		t.Errorf("Expected UAFamily_Safari but got %v", ua.Family)
	}
	if ua.Human != Human_Unknown {
		t.Errorf("Expected Human_Unknown but got %v", ua.Human)
	}

	if ua.OS != OSFamily_MacOS {
		t.Errorf("Expected OSFamily_MacOS but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentFirefox(t *testing.T) {
	uaString := `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Desktop {
		t.Errorf("Expected DeviceType_Desktop but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_Firefox {
		t.Errorf("Expected UAFamily_Firefox but got %v", ua.Family)
	}
	if ua.Human != Human_Unknown {
		t.Errorf("Expected Human_Unknown but got %v", ua.Human)
	}

	if ua.OS != OSFamily_MacOS {
		t.Errorf("Expected OSFamily_MacOS but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentSafariIOS(t *testing.T) {
	uaString := `Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Mobile {
		t.Errorf("Expected DeviceType_Mobile but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_Safari {
		t.Errorf("Expected UAFamily_Safari but got %v", ua.Family)
	}
	if ua.Human != Human_Unknown {
		t.Errorf("Expected Human_Unknown but got %v", ua.Human)
	}

	if ua.OS != OSFamily_IOS {
		t.Errorf("Expected OSFamily_IOS but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentCrios(t *testing.T) {
	uaString := `Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/137.0.7151.51 Mobile/15E148 Safari/604.1`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Mobile {
		t.Errorf("Expected DeviceType_Mobile but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_Chrome {
		t.Errorf("Expected UAFamily_Chrome but got %v", ua.Family)
	}
	if ua.Human != Human_Unknown {
		t.Errorf("Expected Human_Unknown but got %v", ua.Human)
	}

	if ua.OS != OSFamily_IOS {
		t.Errorf("Expected OSFamily_IOS but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentAndroid(t *testing.T) {
	uaString := `Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.127 Mobile Safari/537.36`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Mobile {
		t.Errorf("Expected DeviceType_Mobile but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_Chrome {
		t.Errorf("Expected UAFamilUAFamily_Chrome but got %v", ua.Family)
	}
	if ua.Human != Human_Unknown {
		t.Errorf("Expected Human_Unknown but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Android {
		t.Errorf("Expected OSFamily_Android but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentGoogleBot(t *testing.T) {
	uaString := `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_SearchBot {
		t.Errorf("Expected UAFamily_SearchBot but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentGoogleBotMobile(t *testing.T) {
	uaString := `Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_SearchBot {
		t.Errorf("Expected UAFamily_SearchBot but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentAhrefs(t *testing.T) {
	uaString := `Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_SEOBot {
		t.Errorf("Expected UAFamily_SEOBot but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentBytespider(t *testing.T) {
	uaString := `Mozilla/5.0 (Linux; Android 8.0; Pixel 2 Build/OPD3.170816.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.1511.1269 Mobile Safari/537.36; Bytespider`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_SocialBot {
		t.Errorf("Expected UAFamily_SocialBot but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentBytespider2(t *testing.T) {
	uaString := `Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_SocialBot {
		t.Errorf("Expected UAFamily_SocialBot but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentDalvikZTE(t *testing.T) {
	uaString := `Dalvik/2.1.0 (Linux; U; Android 9.0; ZTE BA520 Build/MRA58K)`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Mobile {
		t.Errorf("Expected DeviceType_Mobile but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_Other {
		t.Errorf("Expected UAFamily_Other but got %v", ua.Family)
	}
	if ua.Human != Human_Unknown {
		t.Errorf("Expected Human_Unknown but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Android {
		t.Errorf("Expected OSFamily_Android but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentFacebook(t *testing.T) {
	uaString := `facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_SocialBot {
		t.Errorf("Expected UAFamily_SocialBot but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentFacebook2(t *testing.T) {
	uaString := `facebook/1.1`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_OtherBot {
		t.Errorf("Expected UAFamily_OtherBot but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentFacebookAI(t *testing.T) {
	uaString := `meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_AIBot {
		t.Errorf("Expected UAFamily_AIBot but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentZgrab(t *testing.T) {
	uaString := `Mozilla/5.0 zgrab/0.x`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_Scanner {
		t.Errorf("Expected UAFamily_Scanner but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.Intent != RequestIntent_Scanning {
		t.Errorf("Expected RequestIntent_Scanning but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentExpanse(t *testing.T) {
	uaString := `Expanse, a Palo Alto Networks company, searches across the global IPv4 space multiple times per day to identify customers&#39; presences on the Internet. If you would like to be excluded from our scans, please send IP addresses/domains to: scaninfo@paloaltonetworks.com`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_Scanner {
		t.Errorf("Expected UAFamily_Scanner but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.Intent != RequestIntent_Scanning {
		t.Errorf("Expected RequestIntent_Scanning but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}

func TestParseUserAgentAmazonbot(t *testing.T) {
	uaString := `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36`

	ua := NewSBOUserAgent(uaString)
	fmt.Printf("DeviceType: %v Family:%v Human:%v OS:%v \n", ua.DeviceType, ua.Family, ua.Human, ua.OS)
	if ua.DeviceType != DeviceType_Script {
		t.Errorf("Expected DeviceType_Script but got %v", ua.DeviceType)
	}

	if ua.Family != UAFamily_AIBot {
		t.Errorf("Expected UAFamily_AIBot but got %v", ua.Family)
	}
	if ua.Human != Human_No {
		t.Errorf("Expected Human_No but got %v", ua.Human)
	}

	if ua.OS != OSFamily_Other {
		t.Errorf("Expected OSFamily_Other but got %v", ua.OS)
	}

	if ua.Intent != RequestIntent_Processing {
		t.Errorf("Expected RequestIntent_Scanning but got %v", ua.OS)
	}

	if ua.FullName != uaString {
		t.Errorf("FullName not set")
	}
}
