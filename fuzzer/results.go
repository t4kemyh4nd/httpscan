package fuzzer

import (
	"fmt"
	"strings"
)

//Generate URL encoded payloads here
func GenerateURLEncodedPayloads() []string {
	payloads := []string{"%00", "%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08", "%09", "%0a", "%0b", "%0c", "%0d", "%0e", "%0f"}
	for i := 16; i <= 256; i++ {
		h := fmt.Sprintf("%%"+"%x", i)
		payloads = append(payloads, h)
	}
	return payloads
}

func GenerateHexBytesPayloads() []string {
	payloads := []string{"\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0a", "\x0b", "\x0c", "\x0d", "\x0e", "\x0f"}
	for i := 16; i <= 256; i++ {
		h := fmt.Sprintf("\\x"+"%x", i)
		payloads = append(payloads, h)
	}
	return payloads
}

//Exported function to check if invalid request hits the server or just the proxy
func HitsServer(sc string, res string) bool {
	if sc != "200" && sc[0] == '4' {
		if strings.Contains(res, "Server: ") {
			return true
		}
	}
	return false
}

type HostBehavior struct {
	MultipleHostsAllowed       [3]bool
	WhichHostProcessed         [3]int
	ValidCharsInHostHeader     [3][]string
	ValidCharsInHostHeaderPort [3][]string
	NoHost                     [3]bool
}

type BasicBehavior struct {

	// Content length section

	// Based on the array indices:
	// 0 - HTTP 1.1
	// 1 - HTTP 1.0
	// 2 - HTTP 0.9
	NoCL             [3][]bool
	MultipleCLFirst  [3][]bool
	MultipleCLSecond [3][]bool
	SmallCL          [3][]bool
	LargeCL          [3][]bool

	// Invalid HTTP version section
	/*	V100			bool
	 */
}

type ParametersBehavior struct {
	FormencodedToMultipart                    [3]bool
	FormencodedToMultipartMissingLastBoundary [3]bool
	FormencodedToMultipartWithLF              [3]bool
	FormencodedToMultipartWithoutFormdata     [3]bool
	FormencodedToMultipartNameBeforeFD        [3]bool
	MultipleGETParametersSameName             [3]int
	MultiplePOSTParametersSameName            [3]int
	MultipleCookiesParametersSameName         [3]int
	ValidSeparatorsForGETParameters           [3][]string
	IgnoredCharsInCookieParameters            [3][]string
	IgnoredCharsInCookieParametersValue       [3][]string
	URLEncodedCharsInCookieParameters         [3]bool
	URLEncodedCharsInCookieParametersValue    [3]bool
	IgnoredCharsBeforeGETParameters           [3][]string
	IgnoredCharsBetweenGETParameters          [3][]string
	IgnoredCharsAfterGETParameters            [3][]string
}

type HeadersBehavior struct {
	IgnoredCharsBetweenHeaderValue [3][]string
	ValidCharsBeforeHeaders        [3][]string
	ValidCharsBeforeColon          [3][]string
	ValidCharsAfterColon           [3][]string
	ValidHeaderSeparators          [3][]string
	ValidCharsInHeaderName         [3][]string
	ValidCharsInHeaderValue        [3][]string
}
