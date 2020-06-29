package fuzzer

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

//	Checks for invalid HTTP versions
func InvalidHTTPv(URL string, HTTPv string, method string, postData string, path string) []bool {
	fmt.Println("Checking invalid HTTP versions...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = method
	r.HttpVersion = HTTPv
	r.Path = path
	if method == "POST" {
		r.Headers = []string{"Content-Type: application/x-www-form-urlencoded", "Content-Length: " + strconv.Itoa(len(postData))}
	}

	sc, res := r.MakeRequest()
	defer fmt.Println("Done...")
	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

//	Sends a POST request without the Content-Length header
func NoContentLength(URL string, postData string, contentType string, HTTPv string, path string) []bool {
	fmt.Println("Checking behaviour with absense of CL header...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = path
	r.HttpVersion = HTTPv
	r.Headers = []string{"Content-Type: " + contentType}
	r.Body = postData

	sc, res := r.MakeRequest()
	defer fmt.Println("Done...")
	if sc == "200" {
		if strings.Contains(res, "input2=Testing, input3=Fuzzer") {
			return []bool{true, true}
		}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Sends a POST request where the FIRST Content-Length header is incorrect
func MultipleWrongFirst(URL string, postData string, contentType string, HTTPv string, path string, method string) []bool {
	fmt.Println("Checking for priority in CL headers...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = method
	r.Path = path
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: 1", "Content-Length: " + strconv.Itoa(len(postData))}

	sc, res := r.MakeRequest()
	defer fmt.Println("Done...")
	if sc == "200" {
		if strings.Contains(res, "input2=Testing, input3=Fuzzer") {
			return []bool{true, true}
		}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Sends a POST request wherein the SECOND Content-Length header is incorrect
func MultipleWrongSecond(URL string, postData string, contentType string, HTTPv string, path string, method string) []bool {
	fmt.Println("Checking for priority in CL headers...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = method
	r.Path = path
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + strconv.Itoa(len(postData)), "Content-Length: 1"}

	sc, res := r.MakeRequest()
	defer fmt.Println("Done...")
	if sc == "200" {
		if strings.Contains(res, "input2=Testing, input3=Fuzzer") {
			return []bool{true, true}
		}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Checks POST requests with a smaller content-length
func SmallerCL(URL string, postData string, contentType string, HTTPv string, path string, method string) []bool {
	fmt.Println("Checking for smaller CL header...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = method
	r.Path = path
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + strconv.Itoa(len(postData)-3)}
	sc, res := r.MakeRequest()

	defer fmt.Println("Done...")
	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

//	TO-DO : The server seems to wait for more bytes to come and freezes the client so, implement a timeout
func LargerCL(URL string, postData string, contentType string, HTTPv string, path string, method string) []bool {
	fmt.Println("Checking for larger CL header...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = method
	r.Path = path
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + strconv.Itoa(len(postData)+100)}
	sc, res := r.MakeRequest()

	defer fmt.Println("Done...")
	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Sends a header as Content_Length
func InvalidCLHeader(URL string, postData string, contentType string, HTTPv string, path string, method string) []bool {
	fmt.Println("Checking for larger CL header as Content_Length...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = method
	r.Path = path
	r.HttpVersion = HTTPv
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content_Length: " + strconv.Itoa(len(postData))}
	sc, res := r.MakeRequest()

	defer fmt.Println("Done...")
	if sc == "200" {
		if strings.Contains(res, "input2=Testing, input3=Fuzzer") {
			return []bool{true, true}
		}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Tests for GET/POST requests with a relative URL with HTTP 0.9
func RelativePath(URL string, postData string, contentType string, path string, method string) []bool {
	fmt.Println("Checking for " + method + " requests on a relative path with HTTP 0.9...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = method
	r.HttpVersion = "0.9"
	r.Path = path

	if method == "GET" {
		r.Body = ""
	} else {
		r.Body = postData
		r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + strconv.Itoa(len(postData))}
	}
	sc, res := r.MakeRequest()
	defer fmt.Println("Done...")

	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Tests for GET/POST requests with an absolute URL with HTTP 0.9
func AbsolutePath(URL string, postData string, contentType string, path string, method string) []bool {
	fmt.Println("Checking for " + method + " requests on an absolute path with HTTP 0.9...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = method
	r.HttpVersion = "0.9"
	r.Path = URL + path // Absolute path
	r.Body = postData
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + strconv.Itoa(len(postData))}
	sc, res := r.MakeRequest()

	defer fmt.Println("Done...")

	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Lines 385

func XAsPost(URL string, postData string, contentType string, path string) []bool {
	fmt.Println("Sending POST with verb as TEST...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "TEST"
	r.Path = path
	r.HttpVersion = "1.1"
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + strconv.Itoa(len(postData))}
	r.Body = postData

	sc, res := r.MakeRequest()
	defer fmt.Println("Done...")
	if sc == "200" {
		if strings.Contains(res, "input2=Testing, input3=Fuzzer") {
			return []bool{true, true}
		}
	}
	return []bool{false, HitsServer(sc, res)}
}

func PostAsGet(URL string, postData string, path string) []bool {
	fmt.Println("Sending POST as a GET request...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "POST"
	r.Path = path + "?" + postData
	r.HttpVersion = "1.1"
	r.Body = ""

	sc, res := r.MakeRequest()
	defer fmt.Println("Done...")
	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

//	sends invalid characters as the POST verb with a POST body
//	Even if characters are allowed it doesn't mean that the server processes the requests correctly further investigation is required
func InvalidHTTPVerb(URL string, path string, postData string, contentType string) []string {
	fmt.Println("Checking allowed character verbs...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.HttpVersion = "1.1"
	r.Path = path
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + strconv.Itoa(len(postData))}
	invalidPostVerbs := []string{"[]", "'", "&", "$", "&", "*", "()"}
	allowedChars := []string{}

	for i := 0; i < len(invalidPostVerbs); i++ {
		r.Method = url.QueryEscape(invalidPostVerbs[i])
		sc, _ := r.MakeRequest()
		if sc == "200" {
			allowedChars = append(allowedChars, invalidPostVerbs[i])
		}
	}
	return allowedChars
}

// Sends a GET request with body and correct content length and type
// Checks whether the server is able to access the POST parameters or not
func GetAsPost(URL string, path string, postData string, contentType string, HTTPv string) []bool {
	fmt.Println("Sending GET as a POST request with " + HTTPv + " ...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.HttpVersion = HTTPv
	r.Path = path
	r.Headers = []string{"Content-Type: " + contentType, "Content-Length: " + strconv.Itoa(len(postData))}
	r.Body = postData
	sc, res := r.MakeRequest()

	defer fmt.Println("Done...")
	if sc == "200" {
		if strings.Contains(res, "input2=Testing, input3=Fuzzer") {
			return []bool{true, true}
		}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Sends a GET request with body and 2 content lengths where the first is wrong
func GetAsPostCLFirst(URL string, path string, postData string, contentType string, HTTPv string) []bool {
	fmt.Println("Sending GET with Content-length and body with " + HTTPv + " ...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.HttpVersion = HTTPv
	r.Path = path
	r.Headers = []string{"Content-Type: " + contentType + "Content-Length: 1" + "Content-Length: " + strconv.Itoa(len(postData))}
	r.Body = postData

	sc, res := r.MakeRequest()
	if sc == "200" {
		if strings.Contains(res, "input2=Testing, input3=Fuzzer") {
			return []bool{true, true}
		}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Sends a GET request with body and 2 content lengths where the second is wrong
func GetAsPostCLSecond(URL string, path string, postData string, contentType string, HTTPv string) []bool {
	fmt.Println("Sending GET with Content-length and body with " + HTTPv + " ...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.HttpVersion = HTTPv
	r.Path = path
	r.Headers = []string{"Content-Type: " + contentType + "Content-Length: " + strconv.Itoa(len(postData)) + "Content-Length: 1"}
	r.Body = postData

	sc, res := r.MakeRequest()
	defer fmt.Println("Done...")
	if sc == "200" {
		if strings.Contains(res, "input2=Testing, input3=Fuzzer") {
			return []bool{true, true}
		}
	}
	return []bool{false, HitsServer(sc, res)}
}

// Sends a GET request with body with a smaller content-legnth than required
func GetAsPostSmall(URL string, path string, postData string, contentType string, HTTPv string) []bool {
	fmt.Println("Sending GET with small Content-length than body with " + HTTPv + " ...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.HttpVersion = HTTPv
	r.Path = path
	r.Headers = []string{"Content-Type: " + contentType + "Content-Length: " + strconv.Itoa(len(postData)-3)}
	r.Body = postData

	sc, res := r.MakeRequest()
	defer fmt.Println("Done...")
	if sc == "200" {
		return []bool{true, true}
	}
	return []bool{false, HitsServer(sc, res)}
}

func GetAsPostLarge(URL string, path string, postData string, contentType string, HTTPv string) []bool {
	fmt.Println("Sending GET with a large Content-length and body with " + HTTPv + " ...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.HttpVersion = HTTPv
	r.Path = path
	r.Headers = []string{"Content-Type: " + contentType + "Content-Length: 1" + "Content-Length: " + strconv.Itoa(len(postData)+100)}
	r.Body = postData

	sc, res := r.MakeRequest()
	defer fmt.Println("Done...")
	if sc == "200" {
		if strings.Contains(res, "input2=Testing, input3=Fuzzer") {
			return []bool{true, true}
		}
	}
	return []bool{false, HitsServer(sc, res)}
}

func ValidBetweenVerbPath(URL string, path string) []string {
	fmt.Println("Fuzzing for allowed characters between Verb and path...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Path = path
	r.Method = "GET"
	r.HttpVersion = "1.1"
	r.Body = ""
	payloads := GenerateHexBytesPayloads()
	allowedChars := []string{}

	defer fmt.Println("Done...")
	for i := 0; i < len(payloads); i++ {
		r.Method = "GET " + payloads[i]
		sc, res := r.MakeRequest()
		if sc == "200" {
			if strings.Contains(res, "input2=Testing, input3=Fuzzer") {
				allowedChars = append(allowedChars, payloads[i])
			}
		}
	}
	return allowedChars
}
