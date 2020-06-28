package fuzzer

import (
	"fmt"
	"strings"
)

func MultipleHostsAllowed(server string, httpv string) bool {
	fmt.Println("Checking if multiple hosts allowed...")
	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.Path = "/host"
	r.HttpVersion = httpv
	r.Host = server
	r.Headers = []string{"Host: " + server}

	sc, _ := r.MakeRequest()

	fmt.Println("Done...")
	return sc == "200"
}

func WhichHostProcessed(server string, httpv string) int {
	fmt.Println("Checking priority of host header...")
	host1 := "x.com"
	host2 := "y.com"

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.Path = "/host"
	r.HttpVersion = httpv
	r.Host = host1
	r.Headers = []string{"Host: " + host2}

	sc, res := r.MakeRequest()

	if sc == "200" {
		if strings.Contains(res, host1) && strings.Contains(res, host2) {
			return 3
		}
		if strings.Contains(res, host1) {
			return 1
		}
		if strings.Contains(res, host2) {
			return 2
		}
	}

	fmt.Println("Done...")
	return 0
}

func ValidCharsInHostHeader(server string, httpv string) []string {
	fmt.Println("Now fuzzing host header for accepted chars...")
	payloads := []string{"#", "@", "aa"} //add chars to be tested here
	acceptedChars := []string{}
	for _, char := range payloads {
		r := TCPeditor{}
		r.Server = server
		r.Method = "GET"
		r.Path = "/host"
		r.HttpVersion = httpv
		r.Host = strings.Split(server, ":")[0] + string(char)
		sc, res := r.MakeRequest()
		if sc == "200" && strings.Contains(strings.Split(res, "\r\n\r\n")[1], strings.Split(server, ":")[0]+string(char)) {
			acceptedChars = append(acceptedChars, char)
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}

func ValidCharsInHostHeaderPort(server string, httpv string) []string {
	fmt.Println("Now fuzzing host header port for accepted chars...")
	payloads := []string{"#", "@", "aa"} //add chars to be tested here
	acceptedChars := []string{}
	for _, char := range payloads {
		r := TCPeditor{}
		r.Server = server
		r.Method = "GET"
		r.Path = "/host"
		r.HttpVersion = httpv
		r.Host = server + string(char)
		sc, res := r.MakeRequest()
		if sc == "200" && strings.Contains(strings.Split(res, "\r\n\r\n")[1], server+string(char)) {
			acceptedChars = append(acceptedChars, char)
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}
