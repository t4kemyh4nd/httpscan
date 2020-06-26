package fuzzer

import (
	"bufio"
	"fmt"
	"io"
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

func WhichHostProcessed(url string) int {
	host1 := "x.com"
	host2 := "y.com"

	conn, err := net.Dial("tcp", url)
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	fmt.Fprintf(conn, "GET /?hub.challenge=1 HTTP/1.1\r\nHost: %s\r\nHost: %s\r\n\r\n", host1, host2)

	status, err := bufio.NewReader(conn).ReadString('\n')

	if err != nil {
		log.Fatal(err)
	}

	if strings.Contains(status, "200") {

		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 256)
		for {
			n, err := conn.Read(tmp)
			if err != nil {
				if err != io.EOF {
					log.Println("read error:", err)
				}
				break
			}
			buf = append(buf, tmp[:n]...)
		}
		if strings.Contains(string(buf), host1) && strings.Contains(string(buf), host1) {
			return 3
		} else if strings.Contains(string(buf), host1) {
			return 1
		} else if strings.Contains(string(buf), host2) {
			return 2
		} else {
			return 0
		}
	}
	return 0
}
