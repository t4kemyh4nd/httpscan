package fuzzer

import (
	"fmt"
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
		if sc == "200" && strings.Contains(res, "barbaz") && strings.Contains(res, "foo") {
			acceptedChars = append(acceptedChars, char)
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}

func ValidCharsBeforeHeaders(server, httpv string) []string {
	fmt.Println("Now checking for valid chars before headers...")
	payloads := GenerateHexBytesPayloads()
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
		if sc == "200" && strings.Contains(res, "barbaz") && strings.Contains(res, "foo") {
			acceptedChars = append(acceptedChars, char)
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}

func ValidCharsBeforeColon(server, httpv string) []string {
	fmt.Println("Now checking for valid chars before colon...")
	payloads := GenerateHexBytesPayloads()
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
		if sc == "200" && strings.Contains(res, "barbaz") && strings.Contains(res, "foo"){
			acceptedChars = append(acceptedChars, char)
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}
