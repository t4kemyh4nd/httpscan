package main

import (
	"fmt"

	"github.com/httpscan/fuzzer"
)

func main() {

	/*
		hb := &fuzzer.HostBehavior{}
		hb = fuzzHostHeader("127.0.0.1:80")
		fmt.Println(hb)

		bb := &fuzzer.BasicBehavior{}
		bb = fuzzBasic("127.0.0.1:80", "input2=Testing&input3=Fuzzer", "application/x-www-form-urlencoded")
		fmt.Println(bb)

		pb := &fuzzer.ParametersBehavior{}
		pb = fuzzParameters("127.0.0.1:80")
		fmt.Println(pb)
	*/

	ohb := &fuzzer.HeadersBehavior{}
	ohb = fuzzHeaders("127.0.0.1:80")
	fmt.Println(ohb)
}

func fuzzHostHeader(URL string) *fuzzer.HostBehavior {
	fmt.Println("--------FUZZING HOST BEHAVIOR NOW--------")
	HostResults := &fuzzer.HostBehavior{}

	HTTPVersion := []string{"1.1", "1.0", "0.9"}

	for i := 0; i < len(HTTPVersion); i++ {
		fmt.Println("Checking for HTTP version " + HTTPVersion[i])
		HostResults.MultipleHostsAllowed[i] = fuzzer.MultipleHostsAllowed(URL, HTTPVersion[i])
		if HostResults.MultipleHostsAllowed[i] == true {
			HostResults.WhichHostProcessed[i] = fuzzer.WhichHostProcessed(URL, HTTPVersion[i])
		}
		HostResults.ValidCharsInHostHeader[i] = fuzzer.ValidCharsInHostHeader(URL, HTTPVersion[i])
		HostResults.ValidCharsInHostHeaderPort[i] = fuzzer.ValidCharsInHostHeaderPort(URL, HTTPVersion[i])
		HostResults.NoHost[i] = fuzzer.NoHost(URL, HTTPVersion[i])
	}

	return HostResults
}

func fuzzBasic(URL string, postData string, contentType string) *fuzzer.BasicBehavior {
	fmt.Println("--------FUZZING HTTP BASIC BEHAVIOR NOW--------")
	BasicResults := &fuzzer.BasicBehavior{}

	// This array SHOULD be consistent with the BasicBehavior struct in results.go
	HTTPVersion := []string{"1.1", "1.0", "0.9"}

	for i := 0; i < len(HTTPVersion); i++ {
		fmt.Println("Checking for HTTP version " + HTTPVersion[i])
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

func fuzzParameters(URL string) *fuzzer.ParametersBehavior {
	fmt.Println("--------FUZZING PARAMETER BEHAVIOR NOW--------")
	ParameterResults := &fuzzer.ParametersBehavior{}

	HTTPVersion := []string{"1.1", "1.0", "0.9"}

	for i := 0; i < len(HTTPVersion); i++ {
		fmt.Println("Checking for HTTP version " + HTTPVersion[i])
		ParameterResults.FormencodedToMultipart[i] = fuzzer.FormencodedToMultipart(URL, HTTPVersion[i])
		if ParameterResults.FormencodedToMultipart[i] {
			ParameterResults.FormencodedToMultipartMissingLastBoundary[i] = fuzzer.FormencodedToMultipartMissingLastBoundary(URL, HTTPVersion[i])
			ParameterResults.FormencodedToMultipartWithLF[i] = fuzzer.FormencodedToMultipartWithLF(URL, HTTPVersion[i])
			ParameterResults.FormencodedToMultipartWithoutFormdata[i] = fuzzer.FormencodedToMultipartWithoutFormdata(URL, HTTPVersion[i])
			ParameterResults.FormencodedToMultipartNameBeforeFD[i] = fuzzer.FormencodedToMultipartNameBeforeFD(URL, HTTPVersion[i])
		}
		ParameterResults.MultipleGETParametersSameName[i] = fuzzer.MultipleGETParametersSameName(URL, HTTPVersion[i])
		ParameterResults.MultiplePOSTParametersSameName[i] = fuzzer.MultiplePOSTParametersSameName(URL, HTTPVersion[i])
		ParameterResults.MultipleCookiesParametersSameName[i] = fuzzer.MultipleCookiesParametersSameName(URL, HTTPVersion[i])
		ParameterResults.ValidSeparatorsForGETParameters[i] = fuzzer.ValidSeparatorsForGETParameters(URL, HTTPVersion[i])
		ParameterResults.IgnoredCharsInCookieParameters[i] = fuzzer.IgnoredCharsInCookieParameters(URL, HTTPVersion[i])
		ParameterResults.URLEncodedCharsInCookieParameters[i] = fuzzer.URLEncodedCharsInCookieParameters(URL, HTTPVersion[i])
		ParameterResults.URLEncodedCharsInCookieParametersValue[i] = fuzzer.URLEncodedCharsInCookieParametersValue(URL, HTTPVersion[i])
		ParameterResults.IgnoredCharsBeforeGETParameters[i] = fuzzer.IgnoredCharsBeforeGETParameters(URL, HTTPVersion[i])
		ParameterResults.IgnoredCharsBetweenGETParameters[i] = fuzzer.IgnoredCharsBetweenGETParameters(URL, HTTPVersion[i])
		ParameterResults.IgnoredCharsAfterGETParameters[i] = fuzzer.IgnoredCharsAfterGETParameters(URL, HTTPVersion[i])
	}

	return ParameterResults
}

func fuzzHeaders(URL string) *fuzzer.HeadersBehavior {
	fmt.Println("--------FUZZING HEADERS BEHAVIOR NOW--------")
	HeaderResults := &fuzzer.HeadersBehavior{}

	// This array SHOULD be consistent with the BasicBehavior struct in results.go
	HTTPVersion := []string{"1.1", "1.0", "0.9"}

	for i := 0; i < len(HTTPVersion); i++ {
		fmt.Println("Checking for HTTP version " + HTTPVersion[i])
		HeaderResults.IgnoredCharsBetweenHeaderValue[i] = fuzzer.IgnoredCharsBetweenHeaderValue(URL, HTTPVersion[i])
		HeaderResults.ValidCharsBeforeHeaders[i] = fuzzer.ValidCharsBeforeHeaders(URL, HTTPVersion[i])
		HeaderResults.ValidCharsBeforeColon[i] = fuzzer.ValidCharsBeforeColon(URL, HTTPVersion[i])
		HeaderResults.ValidCharsAfterColon[i] = fuzzer.ValidCharsAfterColon(URL, HTTPVersion[i])
		HeaderResults.ValidHeaderSeparators[i] = fuzzer.ValidHeaderSeparators(URL, HTTPVersion[i])
	}

	return HeaderResults
}
