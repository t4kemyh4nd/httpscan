package main

import (
	"fmt"

	"github.com/httpscan/fuzzer"
)

func main() {

	hb := &fuzzer.HostBehavior{}
	hb = fuzzHostHeader("127.0.0.1:80")
	fmt.Println(hb)

	bb := &fuzzer.BasicBehavior{}
	bb = fuzzBasic("127.0.0.1:80", "input2=Testing&input3=Fuzzer", "application/x-www-form-urlencoded")
	fmt.Println(bb)

}

func fuzzHostHeader(URL string) *fuzzer.HostBehavior {
	HostResults := &fuzzer.HostBehavior{}
	HostResults.MultipleHostsAllowed = fuzzer.MultipleHostsAllowed(URL)
	if HostResults.MultipleHostsAllowed == true {
		HostResults.WhichHostProcessed = fuzzer.WhichHostProcessed(URL)
	}
	HostResults.ValidCharsInHostHeader = fuzzer.ValidCharsInHostHeader(URL)
	HostResults.ValidCharsInHostHeaderPort = fuzzer.ValidCharsInHostHeaderPort(URL)

	return HostResults
}

func fuzzBasic(URL string, postData string, contentType string) *fuzzer.BasicBehavior {

	BasicResults := &fuzzer.BasicBehavior{}

	// This array SHOULD be consistent with the BasicBehavior struct in results.go
	HTTPVersion := []string{"1.1", "1.0", "0.9"}

	for i := 0; i < len(HTTPVersion); i++ {
		BasicResults.NoCL[i] = fuzzer.NoContentLength(URL, postData, contentType, HTTPVersion[i])
		BasicResults.MultipleCLFirst[i] = fuzzer.MultipleWrongFirst(URL, postData, contentType, HTTPVersion[i])
		BasicResults.MultipleCLSecond[i] = fuzzer.MultipleWrongSecond(URL, postData, contentType, HTTPVersion[i])
		BasicResults.SmallCL[i] = fuzzer.SmallerCL(URL, postData, contentType, HTTPVersion[i])
		// Checks POST requests with the a larger content-length
		// IMPLEMENT A TIMEOUT FOR THE FUNCTION
		//BasicResults.LargeCL[i] = fuzzer.LargerCL(URL,postData,contentType,HTTPVersion[i])
	}

	return BasicResults
}

// COMPLETE LATER
func initiateInvalidHTTP(URL string, postData string) {

	// Add invalid HTTP values
	//BasicResults := &fuzzer.BasicBehavior{}

	InvalidVersions := []string{"1.1", "1.10000000", "1.19", "2.0", ".9", "0.99", "9.9", "00000001.1", "1.10"}

	for i := 0; i < len(InvalidVersions); i++ {
		fmt.Println("\nTesting " + InvalidVersions[i])
		fmt.Println(fuzzer.InvalidHTTPv(URL, InvalidVersions[i], "GET", ""))
	}
}
