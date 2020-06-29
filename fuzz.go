package main

import (
	"fmt"

	"github.com/httpscan/fuzzer"
)

func main() {

	target := "127.0.0.1:80"
	data := "input2=Testing&input3=Fuzzer"
	contentType := "application/x-www-form-urlencoded"
	rootPath := "/"
	getPath := "/GET"		// all GET requests will be routed to this path
	postPath := "/POST"		// all POST requests will be routed to this path

	hb := &fuzzer.HostBehavior{}
	hb = fuzzHostHeader(target)
	fmt.Println(hb)

	pb := &fuzzer.ParametersBehavior{}
	pb = fuzzParameters(target)
	fmt.Println(pb)

	ohb := &fuzzer.HeadersBehavior{}
	ohb = fuzzHeaders(target)
	fmt.Println(ohb)

	bb := &fuzzer.BasicBehavior{}
	bb = fuzzBasic(target,data,contentType,getPath,postPath,rootPath)
	fmt.Println(bb)
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

func fuzzBasic(URL string, postData string, contentType string, getPath string, postPath string, rootPath string) *fuzzer.BasicBehavior {
	fmt.Println("--------FUZZING HTTP BASIC BEHAVIOR NOW--------")
	BasicResults := &fuzzer.BasicBehavior{}

	// This array SHOULD be consistent with the BasicBehavior struct in results.go
	HTTPVersion := []string{"1.1", "1.0", "0.9"}

	for i := 0; i < len(HTTPVersion); i++ {
		fmt.Println("Checking for HTTP version " + HTTPVersion[i])
		BasicResults.NoCL[i] = fuzzer.NoContentLength(URL, postData, contentType, HTTPVersion[i],postPath)
		BasicResults.MultipleCLFirst[i] = fuzzer.MultipleWrongFirst(URL, postData, contentType, HTTPVersion[i],postPath,"POST")
		BasicResults.MultipleCLSecond[i] = fuzzer.MultipleWrongSecond(URL, postData, contentType, HTTPVersion[i],postPath,"POST")
		BasicResults.SmallCL[i] = fuzzer.SmallerCL(URL, postData, contentType, HTTPVersion[i],postPath,"POST")
		BasicResults.GetAsPost[i] = fuzzer.GetAsPost(URL, postPath, postData , contentType , HTTPVersion[i])
		BasicResults.GetMultipleCLFirst[i] = fuzzer.GetAsPostCLFirst(URL, postPath, postData , contentType , HTTPVersion[i])
		BasicResults.GetMultipleCLSecond[i] = fuzzer.GetAsPostCLSecond(URL, postPath, postData , contentType , HTTPVersion[i])
		BasicResults.GetSmallCL[i] = fuzzer.GetAsPostSmall(URL, postPath, postData , contentType , HTTPVersion[i])
		BasicResults.GetLargeCL[i] = fuzzer.GetAsPostLarge(URL, postPath, postData , contentType , HTTPVersion[i])
		// IMPLEMENT A TIMEOUT FOR THE FUNCTION
		//BasicResults.LargeCL[i] = fuzzer.LargerCL(URL,postData,contentType,HTTPVersion[i],postPath,"POST")
	}
	BasicResults.GetRelative[0] = fuzzer.RelativePath(URL,postData,contentType,getPath,"GET")
	BasicResults.GetAbsolute[0] = fuzzer.AbsolutePath(URL,postData,contentType,getPath,"GET")
	BasicResults.PostRelative[0] = fuzzer.RelativePath(URL,postData,contentType,postPath,"POST")
	BasicResults.PostAbsolute[0] = fuzzer.AbsolutePath(URL,postData,contentType,postPath,"POST")
	BasicResults.XAsPostGetPath[0] = fuzzer.PostAsGet(URL,postData,getPath)
	BasicResults.XAsPostPostPath[0] = fuzzer.PostAsGet(URL,postData,postPath)
	BasicResults.AllowedCharVerb = fuzzer.InvalidHTTPVerb(URL, postPath, postData, contentType)
	BasicResults.AllowedCharVerbPath = fuzzer.ValidBetweenVerbPath(URL, getPath)
	//Implement timeout for this functions
	//BasicResults.AllowedInvalidGetHTTP, BasicResults.AllowedInvalidPostHTTP = initiateInvalidHTTP(URL,postData,getPath,postPath)
	return BasicResults
}

func initiateInvalidHTTP(URL string, postData string, getPath string, postPath string) ([][]bool, [][]bool){
	// This is tied to the BasicBehavior struct in results.go 
	InvalidVersions := []string{"00000001.1","1.10","0.123","1.10000000","1.19","2.0",".9","0.99","9.9","ABC"}

	GetResults := [][]bool{}
	PostResults := [][]bool{}

	for i:=0;i<len(InvalidVersions);i++{
		fmt.Println("\nTesting HTTP version: " + InvalidVersions[i])
		// Implement timeouts for both of these functions
		GetResults = append(GetResults, fuzzer.InvalidHTTPv(URL,InvalidVersions[i],"GET", "", getPath))
		PostResults = append(PostResults, fuzzer.InvalidHTTPv(URL,InvalidVersions[i],"POST", postData, postPath))
	}
	return GetResults, PostResults
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
		HeaderResults.ValidCharsInHeaderName[i] = fuzzer.ValidCharsInHeaderName(URL, HTTPVersion[i])
		HeaderResults.ValidCharsInHeaderValue[i] = fuzzer.ValidCharsInHeaderValue(URL, HTTPVersion[i])
	}

	return HeaderResults
}
