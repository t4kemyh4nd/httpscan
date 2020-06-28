package fuzzer

import (
	"fmt"
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
