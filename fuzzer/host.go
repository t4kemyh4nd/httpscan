package fuzzer

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
)

func MultipleHostsAllowed(url string) bool {
	conn, err := net.Dial("tcp", url)
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	fmt.Fprintf(conn, "GET /host HTTP/1.1\r\nHost: %s\r\nHost: %s\r\n\r\n", url, url)

	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}

	return strings.Contains(status, "200")
}

func WhichHostProcessed(server string) int {
	host1 := "x.com"
	host2 := "y.com"

	r := TCPeditor{}

	r.Server = server
	r.Method = "GET"
	r.Path = "/?hub.challenge=1"
	r.HttpVersion = "1.1"
	r.Host = host1
	r.Headers = []string{"Host: " + host2}

	sc, res := r.MakeRequest()
	fmt.Println(res)

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
	return 0
}
