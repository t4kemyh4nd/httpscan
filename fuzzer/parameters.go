package fuzzer

import (
	"fmt"
	"net/url"
	"strings"
)

func FormencodedToMultipart(server, httpv string) bool {
	fmt.Println("Checking if x-www-form-urlencoded to multipart allowed...")
	r := TCPeditor{}

	r.Server = server
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = httpv
	r.Host = server
	r.Headers = []string{"Content-Length: 163", "Content-Type: multipart/form-data; boundary=----f4zmrxkir"}
	r.Body = "------f4zmrxkir\r\nContent-Disposition: form-data; name=\"input2\"\r\n\r\ntest\r\n------f4zmrxkir\r\nContent-Disposition: form-data; name=\"input3\"\r\n\r\nfuzzer\r\n------f4zmrxkir--"

	sc, res := r.MakeRequest()

	if sc == "200" && strings.Contains(res, "test") && strings.Contains(res, "fuzzer") {
		return true
	}
	return false
}

func FormencodedToMultipartMissingLastBoundary(server, httpv string) bool {
	fmt.Println("Checking if x-www-form-urlencoded to multipart allowed with missing last boundary...")
	r := TCPeditor{}

	r.Server = server
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = httpv
	r.Host = server
	r.Headers = []string{"Content-Length: 144", "Content-Type: multipart/form-data; boundary=----f4zmrxkir"}
	r.Body = "------f4zmrxkir\r\nContent-Disposition: form-data; name=\"input2\"\r\n\r\ntest\r\n------f4zmrxkir\r\nContent-Disposition: form-data; name=\"input3\"\r\n\r\nfuzzer\r\n\r\n"

	sc, res := r.MakeRequest()

	if sc == "200" && strings.Contains(res, "test") && strings.Contains(res, "fuzzer") {
		return true
	}
	return false
}

func FormencodedToMultipartWithLF(server, httpv string) bool {
	fmt.Println("Checking if x-www-form-urlencoded to multipart allowed with LF...")
	r := TCPeditor{}

	r.Server = server
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = httpv
	r.Host = server
	r.Headers = []string{"Content-Length: 161", "Content-Type: multipart/form-data; boundary=----f4zmrxkir"}
	r.Body = "------f4zmrxkir\nContent-Disposition: form-data; name=\"input2\"\r\n\r\ntest\r\n------f4zmrxkir\nContent-Disposition: form-data; name=\"input3\"\r\n\r\nfuzzer\r\n------f4zmrxkir--"

	sc, res := r.MakeRequest()

	if sc == "200" && strings.Contains(res, "test") && strings.Contains(res, "fuzzer") {
		return true
	}
	return false
}

func FormencodedToMultipartWithoutFormdata(server, httpv string) bool {
	fmt.Println("Checking if x-www-form-urlencoded to multipart allowed without form-data...")
	r := TCPeditor{}

	r.Server = server
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = httpv
	r.Host = server
	r.Headers = []string{"Content-Length: 139", "Content-Type: multipart/form-data; boundary=----f4zmrxkir"}
	r.Body = "------f4zmrxkir\nContent-Disposition: name=\"input2\"\r\n\r\ntest\r\n------f4zmrxkir\nContent-Disposition: name=\"input3\"\r\n\r\nfuzzer\r\n------f4zmrxkir--"

	sc, res := r.MakeRequest()

	if sc == "200" && strings.Contains(res, "test") && strings.Contains(res, "fuzzer") {
		return true
	}
	return false
}

func FormencodedToMultipartNameBeforeFD(server, httpv string) bool {
	fmt.Println("Checking if x-www-form-urlencoded to multipart allowed...")
	r := TCPeditor{}

	r.Server = server
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = httpv
	r.Host = server
	r.Headers = []string{"Content-Length: 163", "Content-Type: multipart/form-data; boundary=----f4zmrxkir"}
	r.Body = "------f4zmrxkir\nContent-Disposition: name=\"input2\"; form-data\r\n\r\ntest\r\n------f4zmrxkir\nContent-Disposition: name=\"input3\"; form-data\r\n\r\nfuzzer\r\n------f4zmrxkir--\n"

	sc, res := r.MakeRequest()

	if sc == "200" && strings.Contains(res, "test") && strings.Contains(res, "fuzzer") {
		return true
	}
	return false
}

func MultipleGETParametersSameName(server, httpv string) int {
	fmt.Println("Checking behavior with same GET parameters...")

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.Path = "/GET?input0=test&input0=fuzzer&input1=random"
	r.HttpVersion = httpv
	r.Host = server

	sc, res := r.MakeRequest()

	if sc == "200" && strings.Contains(res, "test") {
		return 1
	} else if sc == "200" && strings.Contains(res, "fuzzer") {
		return 2
	}
	return 0
}

func MultiplePOSTParametersSameName(server, httpv string) int {
	fmt.Println("Checking behavior with same POST parameters...")
	r := TCPeditor{}

	r.Server = server
	r.Method = "POST"
	r.Path = "/POST"
	r.Headers = []string{"Content-Type: application/x-www-form-urlencoded", "Content-Length: 22"}
	r.HttpVersion = httpv
	r.Host = server
	r.Body = "input2=test&input2=foo&input3=random"

	sc, res := r.MakeRequest()

	if sc == "200" && strings.Contains(res, "test") {
		return 1
	} else if sc == "200" && strings.Contains(res, "foo") {
		return 2
	}
	return 0
}

func MultipleCookiesParametersSameName(server, httpv string) int {
	fmt.Println("Checking behavior with same Cookie parameters...")
	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.Path = "/cookie"
	r.Headers = []string{"Cookie: input4=foo; input4=bar"}
	r.HttpVersion = httpv
	r.Host = server

	sc, res := r.MakeRequest()

	if sc == "200" && strings.Contains(res, "foo") {
		return 1
	} else if sc == "200" && strings.Contains(res, "bar") {
		return 2
	}
	return 0
}

func ValidSeparatorsForGETParameters(server, httpv string) []string {
	fmt.Println("Checking for valid separators in GET parameters...")

	payloads := GenerateURLEncodedPayloads() //Chars to test here
	results := []string{}

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.HttpVersion = httpv
	r.Host = server
	for _, chars := range payloads {
		char, _ := url.PathUnescape(chars)
		r.Path = "/GET?input0=foo" + char + "input1=bar"
		sc, res := r.MakeRequest()

		if sc == "200" && strings.Contains(res, "foo") && strings.Contains(res, "bar") {
			results = append(results, chars)
		}
	}

	return results
}

func ValidSeparatorsForPOSTParameters(server, httpv string) []string {
	fmt.Println("Checking for valid separators in POST parameters...")

	payloads := GenerateURLEncodedPayloads() //Chars to test here
	results := []string{}

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.HttpVersion = httpv
	r.Host = server
	r.Path = "/POST"
	r.Headers = []string{"Content-Type: application/x-www-form-urlencoded", "Content-Length: 21"}

	for _, chars := range payloads {
		char, _ := url.PathUnescape(chars)
		r.Body = "input2=foo" + char + "input3=bar"
		sc, res := r.MakeRequest()

		if sc == "200" && strings.Contains(res, "foo") && strings.Contains(res, "bar") {
			results = append(results, chars)
		}
	}

	return results
}

func IgnoredCharsInCookieParameters(server, httpv string) []string {
	fmt.Println("Checking for ignored chars in cookie names...")

	payloads := GenerateURLEncodedPayloads() //Chars to test here
	results := []string{}

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.HttpVersion = httpv
	r.Host = server
	r.Path = "/cookie"
	for _, chars := range payloads {
		char, _ := url.PathUnescape(chars)
		r.Headers = []string{"Cookie: inpu" + char + "t4: foobar"}
		sc, res := r.MakeRequest()

		if sc == "200" && strings.Contains(res, "foobar") {
			results = append(results, chars)
		}
	}

	return results
}

func IgnoredCharsInCookieParametersValue(server, httpv string) []string {
	fmt.Println("Checking for ignored chars in cookie values...")

	payloads := GenerateURLEncodedPayloads() //Chars to test here
	results := []string{}

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.HttpVersion = httpv
	r.Host = server
	r.Path = "/cookie"
	for _, chars := range payloads {
		char, _ := url.PathUnescape(chars)
		r.Headers = []string{"Cookie: input4: fo" + char + "obar"}
		sc, res := r.MakeRequest()

		if sc == "200" && strings.Contains(res, "foobar") {
			results = append(results, chars)
		}
	}

	return results
}

func URLEncodedCharsInCookieParameters(server, httpv string) bool {
	fmt.Println("Checking if URL encoding allowed in cookie name...")

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.HttpVersion = httpv
	r.Host = server
	r.Path = "/cookie"
	r.Headers = []string{"Cookie: %69%6e%70%75%74%34: foobar"}
	sc, res := r.MakeRequest()

	if sc == "200" && strings.Contains(res, "foobar") {
		return true
	}

	return false
}

func URLEncodedCharsInCookieParametersValue(server, httpv string) bool {
	fmt.Println("Checking if URL encoding allowed in cookie value...")

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.HttpVersion = httpv
	r.Host = server
	r.Path = "/cookie"
	r.Headers = []string{"Cookie: input4: %66%6f%6f%62%61%72"}
	sc, res := r.MakeRequest()

	if sc == "200" && strings.Contains(res, "foobar") {
		return true
	}

	return false
}

func IgnoredCharsBeforeGETParameters(server, httpv string) []string {
	fmt.Println("Checking for ignored chars before GET parameters...")

	payloads := GenerateURLEncodedPayloads() //Chars to test here
	results := []string{}

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.HttpVersion = httpv
	r.Host = server
	for _, chars := range payloads {
		char, _ := url.PathUnescape(chars)
		r.Path = "/GET?" + char + "input0=foo&input1=bar"
		sc, res := r.MakeRequest()

		if sc == "200" && strings.Contains(res, "foo") && strings.Contains(res, "bar") {
			results = append(results, chars)
		}
	}

	return results
}

func IgnoredCharsBetweenGETParameters(server, httpv string) []string {
	fmt.Println("Checking for ignored chars between GET parameters...")

	payloads := GenerateURLEncodedPayloads() //Chars to test here
	results := []string{}

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.HttpVersion = httpv
	r.Host = server
	for _, chars := range payloads {
		char, _ := url.PathUnescape(chars)
		r.Path = "/GET?inp" + char + "ut0=foo&input1=bar"
		sc, res := r.MakeRequest()

		if sc == "200" && strings.Contains(res, "foo") && strings.Contains(res, "bar") {
			results = append(results, chars)
		}
	}

	return results
}

func IgnoredCharsAfterGETParameters(server, httpv string) []string {
	fmt.Println("Checking for ignored chars after GET parameters...")

	payloads := GenerateURLEncodedPayloads() //Chars to test here
	results := []string{}

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.HttpVersion = httpv
	r.Host = server
	for _, chars := range payloads {
		char, _ := url.PathUnescape(chars)
		r.Path = "/GET?input0=foo&input1=bar" + char
		sc, res := r.MakeRequest()

		//Checks if the response body ENDS with "bar"
		if sc == "200" && strings.Contains(res, "foo") && strings.HasSuffix(res, "bar") {
			results = append(results, chars)
		}
	}

	return results
}
