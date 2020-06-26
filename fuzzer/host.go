package fuzzer

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
)

func MultipleHostsAllowed(server string) bool {
	fmt.Println("Checking if multiple hosts allowed...")
	conn, err := net.Dial("tcp", server)
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	fmt.Fprintf(conn, "GET /host HTTP/1.1\r\nHost: %s\r\nHost: %s\r\n\r\n", server, server)

	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Done...")
	return strings.Contains(status, "200")
}

func WhichHostProcessed(server string) int {
	fmt.Println("Checking priority of host header...")
	host1 := "x.com"
	host2 := "y.com"

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.Path = "/host"
	r.HttpVersion = "1.1"
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

func ValidCharsInHostHeader(server string) []string {
	fmt.Println("Now fuzzing host header for accepted chars...")
	payloads := []string{"#", "@", "aa"} //add chars to be tested here
	acceptedChars := []string{}
	for _, char := range payloads {
		r := TCPeditor{}
		r.Server = server
		r.Method = "GET"
		r.Path = "/host"
		r.HttpVersion = "1.1"
		r.Host = strings.Split(server, ":")[0] + string(char)
		sc, res := r.MakeRequest()
		if sc == "200" && strings.Contains(res, strings.Split(server, ":")[0]+string(char)) {
			acceptedChars = append(acceptedChars, char)
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}

func ValidCharsInHostHeaderPort(server string) []string {
	fmt.Println("Now fuzzing host header port for accepted chars...")
	payloads := []string{"#", "@", "aa"} //add chars to be tested here
	acceptedChars := []string{}
	for _, char := range payloads {
		r := TCPeditor{}
		r.Server = server
		r.Method = "GET"
		r.Path = "/host"
		r.HttpVersion = "1.1"
		r.Host = server + string(char)
		sc, res := r.MakeRequest()
		if sc == "200" && strings.Contains(res, server+string(char)) {
			acceptedChars = append(acceptedChars, char)
		}
	}

	fmt.Println("Done...")
	return acceptedChars
}
