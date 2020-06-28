package fuzzer

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
)

type TCPeditor struct {
	Server      string
	Method      string
	Host        string
	Path        string
	Headers     []string
	HttpVersion string
	Body        string
	HitsProxy   bool
}

func (t TCPeditor) MakeRequest() (string, string) {
	conn, err := net.Dial("tcp", t.Server)
	if err != nil {
		log.Fatal(err)
	}

	var request strings.Builder
	if t.HttpVersion == "1.1" {
		request.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\nConnection: close\r\n", t.Method, t.Path))
	} else {
		request.WriteString(fmt.Sprintf("%s %s HTTP/%s\r\n", t.Method, t.Path, t.HttpVersion))
	}
	request.WriteString(fmt.Sprintf("Host: %s\r\n", t.Host))
	if len(t.Headers) != 0 {
		for _, v := range t.Headers {
			request.WriteString(v + "\r\n")
		}
	}

	if t.Body == "" {
		request.WriteString("\r\n") //ending HTTP request without a body
	} else {
		request.WriteString("\r\n")
		request.WriteString(t.Body)
	}

	defer conn.Close()

	fmt.Fprintf(conn, request.String())

	response, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Fatal(err)
	}

	lines := strings.Split(string(response), "\n")

	if len(response) > 0 {
		return strings.Split(lines[0], " ")[1], string(response)
	}
	return "000", ""
}
