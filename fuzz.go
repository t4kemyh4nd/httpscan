package main

import (
	"fmt"

	"github.com/httpscan/fuzzer"
)

func main() {
	r := fuzzer.TCPeditor{Host: "127.0.0.1:8000", Path: "/POST", HttpVersion: "1.1", Headers: []string{"Content-Type: application/x-www-form-urlencoded", "Content-Length: 12"}, Method: "POST", Body: "input2=ameya"}
	var sc, resp = r.MakeRequest()
	fmt.Println(sc, string(resp))
}

func fuzzHostHeader(url string) *fuzzer.HostBehavior {
	HostResults := &fuzzer.HostBehavior{}
	HostResults.MultipleHostsAllowed = fuzzer.MultipleHostsAllowed(url)
	HostResults.WhichHostProcessed = fuzzer.WhichHostProcessed(url)

	return HostResults
}
