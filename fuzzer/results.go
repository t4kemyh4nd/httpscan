package fuzzer

import "strings"

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
	MultipleHostsAllowed       bool
	WhichHostProcessed         int
	ValidCharsInHostHeader     []string
	ValidCharsInHostHeaderPort []string
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
