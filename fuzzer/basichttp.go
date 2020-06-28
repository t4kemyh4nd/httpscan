package fuzzer

import (
	"fmt"
	"reflect"
	"strconv"
)

//	Checks for invalid HTTP versions
func InvalidHTTPv(URL string, HTTPv string, method string, postData string) []bool {
	fmt.Println("Checking invalid HTTP versions...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = method
	r.HttpVersion = HTTPv

	if method == "POST" {
		r.Path = "/POST"
		payloadSize := strconv.Itoa(int(reflect.TypeOf(postData).Size()))
		r.Headers = []string{"Content-Type: application/x-www-form-urlencoded", "Content-Length: " + payloadSize}
	} else {
		r.Path = "/"
	}

	sc, res := r.MakeRequest()

	defer fmt.Println("Done...")

	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

//	Sends a POST request without the Content-Length header, URL encodes parameters for application/x-www-form-urlencoded
func NoContentLength(URL string, postData string, contentType string, HTTPv string) []bool {
	fmt.Println("Checking behaviour with absense of CL header...")
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

	defer fmt.Println("Done...")

	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Sends a POST request wherein the FIRST Content-Length header is incorrect
func MultipleWrongFirst(URL string, postData string, contentType string, HTTPv string) []bool {
	fmt.Println("Checking for priority in CL headers...")
	payloadSize := strconv.Itoa(int(reflect.TypeOf(postData).Size()))

	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: 1", "Content-Length: " + payloadSize}
	sc, res := r.MakeRequest()

	defer fmt.Println("Done...")

	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Sends a POST request wherein the SECOND Content-Length header is incorrect
func MultipleWrongSecond(URL string, postData string, contentType string, HTTPv string) []bool {
	fmt.Println("Checking for priority in CL headers...")
	payloadSize := strconv.Itoa(int(reflect.TypeOf(postData).Size()))

	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + payloadSize, "Content-Length: 1"}
	sc, res := r.MakeRequest()

	defer fmt.Println("Done...")

	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Checks POST requests with a smaller content-length
func SmallerCL(URL string, postData string, contentType string, HTTPv string) []bool {
	fmt.Println("Checking for smaller CL header...")
	payloadSize := strconv.Itoa(int(reflect.TypeOf(postData).Size()) - 3)

	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + payloadSize}
	sc, res := r.MakeRequest()

	defer fmt.Println("Done...")

	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

//	TO-DO : The server seems to wait for more bytes to come and freezes the client so, implement a timeout
func LargerCL(URL string, postData string, contentType string, HTTPv string) []bool {
	fmt.Println("Checking for larger CL header...")
	payloadSize := strconv.Itoa(int(reflect.TypeOf(postData).Size()) + 100)

	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + payloadSize}
	sc, res := r.MakeRequest()

	defer fmt.Println("Done...")

	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}
