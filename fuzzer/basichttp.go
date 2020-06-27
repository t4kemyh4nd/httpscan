package fuzzer

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Generates a TCPeditor instance to be used for all functions defined in this file
// It should return a reference of TCPeditor
// IMPLEMENT THIS ONLY AFTER THIS FILE IS COMPLETE
func generateTCPeditor(URL string, postData string, contentType string, HTTPv string) *TCPeditor{
	// Function not yet complete
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = "/"
	r.HttpVersion = HTTPv

	if postData == "" {
		r.Body = ""
	} else{
		r.Body = postData
	}
		
	return &r
}


// Vanilla POST request for testing purposes
/*
func TestRequest(URL string, postData string, contentType string, HTTPv string){
	r := generateTCPeditor(URL string, postData string, contentType string, HTTPv string)
	
}
*/

//	Checks for invalid HTTP versions
func InvalidHTTPv(URL string, HTTPv string, method string, postData string) bool{

	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = method
	r.HttpVersion = HTTPv

	if method == "POST"{
		r.Path = "/POST"
		payloadSize :=  strconv.Itoa(int(reflect.TypeOf(postData).Size()))
		r.Headers = []string{"Content-Type: application/x-www-form-urlencoded", "Content-Length: " + payloadSize}
	} else{
		r.Path = "/"
	}

	sc, res := r.MakeRequest()
	fmt.Print(res)

	// CHECKING IF RESPONSE CAME FROM SERVER
	if(strings.Contains(res,"Server: ")){
		// set boolean value here
		fmt.Println("Response received from server.")
	} else{
		// set boolean value here
		fmt.Println("Response received from proxy.")
	}

	if sc == "200" {
		return true
	}
	return false	
}

//	Sends a POST request without the Content-Length header, URL encodes parameters for application/x-www-form-urlencoded
func NoContentLength(URL string, postData string, contentType string, HTTPv string) bool {

	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = HTTPv

	r.Headers = []string{"Content-Type: " + contentType}
	r.Body = postData

	if contentType == "application/x-www-form-urlencoded" {
		// IMPLEMENT URL ENCODING FOR PARAMETER VALUES
	}

	sc, res := r.MakeRequest()
	fmt.Println("\n"+res)


	// CHECKING IF RESPONSE CAME FROM SERVER
	if(strings.Contains(res,"Server: ")){
		// set boolean value here
		fmt.Println("Response received from server.")
	} else{
		// set boolean value here
		fmt.Println("Response received from proxy.")
	}
	
	if sc == "200" {
		return true
	}
	return false
}


// Sends a POST request wherein the FIRST Content-Length header is incorrect
func MultipleWrongFirst(URL string, postData string, contentType string, HTTPv string) bool {

	payloadSize :=  strconv.Itoa(int(reflect.TypeOf(postData).Size()))

	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: 1", "Content-Length: " + payloadSize}
	sc, res := r.MakeRequest()
	fmt.Println(res)

	// CHECKING IF RESPONSE CAME FROM SERVER
	if(strings.Contains(res,"Server: ")){
		// set boolean value here
		fmt.Println("Response received from server.")
	} else{
		// set boolean value here
		fmt.Println("Response received from proxy.")
	}

	if sc == "200" {
		return true
	}

	return false
	
}

// Sends a POST request wherein the SECOND Content-Length header is incorrect
func MultipleWrongSecond(URL string, postData string, contentType string, HTTPv string) bool {

	payloadSize :=  strconv.Itoa(int(reflect.TypeOf(postData).Size()))

	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + payloadSize, "Content-Length: 1" }
	sc, res := r.MakeRequest()
	fmt.Println(res)
	// CHECKING IF RESPONSE CAME FROM SERVER
	if(strings.Contains(res,"Server: ")){
		// set boolean value here
		fmt.Println("Response received from server.")
	} else{
		// set boolean value here
		fmt.Println("Response received from proxy.")
	}

	if sc == "200" {
		return true
	}
	return false
	
}

// Checks POST requests with a smaller content-length
func SmallerCL(URL string, postData string, contentType string, HTTPv string) bool{
	payloadSize :=  strconv.Itoa(int(reflect.TypeOf(postData).Size())-3)

	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + payloadSize}
	sc, res := r.MakeRequest()
	fmt.Println(res)
	// CHECKING IF RESPONSE CAME FROM SERVER
	if(strings.Contains(res,"Server: ")){
		// set boolean value here
		fmt.Println("Response received from server.")
	} else{
		// set boolean value here
		fmt.Println("Response received from proxy.")
	}

	if sc == "200" {
		return true
	}
	return false
}

//	TO-DO : The server seems to wait for more bytes to come and freezes the client so, implement a timeout
func LargerCL(URL string, postData string, contentType string, HTTPv string) bool{
	payloadSize :=  strconv.Itoa(int(reflect.TypeOf(postData).Size())+100)

	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + payloadSize}
	sc, res := r.MakeRequest()
	fmt.Println(res)
	// CHECKING IF RESPONSE CAME FROM SERVER
	if(strings.Contains(res,"Server: ")){
		// set boolean value here
		fmt.Println("Response received from server.")
	} else{
		// set boolean value here
		fmt.Println("Response received from proxy.")
	}

	if sc == "200" {
		return true
	}
	return false
	
}