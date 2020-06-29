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
