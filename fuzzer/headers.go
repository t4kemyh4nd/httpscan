package fuzzer

import (
	"fmt"
	"net/url"
	"strings"
)

func IgnoredCharsBetweenHeaderValue(server, httpv string) []string {
	fmt.Println("Now checking for ignored chars in middle of headers values...")
	payloads := GenerateHexBytesPayloads()
	acceptedChars := []string{}
	r := TCPeditor{}
	r.Server = server
	r.Method = "GET"
	r.Path = "/headers"
	r.HttpVersion = httpv
	r.Host = server
	for _, char := range payloads {
		r.Headers = []string{"Foo: barb" + string(char) + "az"}
		sc, res := r.MakeRequest()
		if sc == "200" {
			lines := strings.Split(res, "\r\n")
			for _, line := range lines {
				if strings.Contains(line, "barbaz") {
					acceptedChars = append(acceptedChars, url.PathEscape(char))
				}
			}
		}

	}
	fmt.Println("Done...")
	return acceptedChars
}

func ValidCharsBeforeHeaders(server, httpv string) []string {
	fmt.Println("Now checking for valid chars before headers...")
	payloads := []string{"\t", "\v", "\r", "\n", "\x00"}
	acceptedChars := []string{}
	r := TCPeditor{}
	r.Server = server
	r.Method = "GET"
	r.Path = "/headers"
	r.HttpVersion = httpv
	r.Host = server
	for _, char := range payloads {
		r.Headers = []string{string(char) + "Foo: barbaz"}
		sc, res := r.MakeRequest()
		if sc == "200" {
			lines := strings.Split(res, "\r\n")
			for _, line := range lines {
				if strings.Contains(line, "Foo: barbaz") {
					acceptedChars = append(acceptedChars, url.PathEscape(char))
				}
			}
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}

func ValidCharsBeforeColon(server, httpv string) []string {
	fmt.Println("Now checking for valid chars before colon...")
	payloads := []string{"\t", "\v", "\r", "\n", "\x00"}
	acceptedChars := []string{}
	r := TCPeditor{}
	r.Server = server
	r.Method = "GET"
	r.Path = "/headers"
	r.HttpVersion = httpv
	r.Host = server
	for _, char := range payloads {
		r.Headers = []string{"Foo" + string(char) + ": barbaz"}
		sc, res := r.MakeRequest()
		if sc == "200" {
			lines := strings.Split(res, "\r\n")
			for _, line := range lines {
				if strings.Contains(line, "Foo: barbaz") {
					acceptedChars = append(acceptedChars, url.PathEscape(char))
				}
			}
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}

func ValidCharsAfterColon(server, httpv string) []string {
	fmt.Println("Now checking for valid chars after colon...")
	payloads := []string{"\t", "\v", "\r", "\n", "\x00", "\x20"}
	acceptedChars := []string{}
	r := TCPeditor{}
	r.Server = server
	r.Method = "GET"
	r.Path = "/headers"
	r.HttpVersion = httpv
	r.Host = server
	for _, char := range payloads {
		r.Headers = []string{"Foo:" + string(char) + " barbaz"}
		sc, res := r.MakeRequest()
		if sc == "200" {
			lines := strings.Split(res, "\r\n")
			for _, line := range lines {
				if strings.Contains(line, "Foo: barbaz") {
					acceptedChars = append(acceptedChars, url.PathEscape(char))
				}
			}
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}

func ValidHeaderSeparators(server, httpv string) []string {
	fmt.Println("Now checking for valid header separators...")
	payloads := []string{"\t", "\v", "\r", "\n", "\x00", "\x20"}
	acceptedChars := []string{}
	r := TCPeditor{}
	r.Server = server
	r.Method = "GET"
	r.Path = "/headers"
	r.HttpVersion = httpv
	r.Host = server
	for _, char := range payloads {
		r.Headers = []string{"Foo: bar" + string(char) + "Baz: qux"}
		sc, res := r.MakeRequest()
		if sc == "200" && strings.Contains(res, "Foo: barbaz\r\n") && strings.Contains(res, "Baz: qux\r\n") {
			acceptedChars = append(acceptedChars, url.PathEscape(char))
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}

func ValidCharsInHeaderName(server, httpv string) []string {
	fmt.Println("Now checking for valid chars in header names...")
	payloads := GenerateURLEncodedPayloads()
	acceptedChars := []string{}
	r := TCPeditor{}
	r.Server = server
	r.Method = "GET"
	r.Path = "/headers"
	r.HttpVersion = httpv
	r.Host = server
	for _, chars := range payloads {
		char, _ := url.PathUnescape(chars)
		r.Headers = []string{"Fo" + string(char) + "o: bar"}
		sc, res := r.MakeRequest()
		if sc == "200" && strings.Contains(strings.ToLower(res), "fo"+string(char)+"o: bar") {
			acceptedChars = append(acceptedChars, url.PathEscape(char))
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}

func ValidCharsInHeaderValue(server, httpv string) []string {
	fmt.Println("Now checking for valid chars in header values...")
	payloads := GenerateURLEncodedPayloads()
	acceptedChars := []string{}
	r := TCPeditor{}
	r.Server = server
	r.Method = "GET"
	r.Path = "/headers"
	r.HttpVersion = httpv
	r.Host = server
	for _, chars := range payloads {
		char, _ := url.PathUnescape(chars)
		r.Headers = []string{"Foo: ba" + string(char) + "r"}
		sc, res := r.MakeRequest()
		if sc == "200" && strings.Contains(strings.ToLower(res), "foo: ba"+string(char)+"r") {
			acceptedChars = append(acceptedChars, url.PathEscape(char))
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}
