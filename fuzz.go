package main

import (
	"fmt"

	"github.com/httpscan/fuzzer"
)

func main() {
	r := fuzzer.TCPeditor{Host: "127.0.0.1:8000", Path: "/headers", HttpVersion: "1.1", Headers: []string{}, Method: "GET"}
	var sc, resp = r.MakeRequest()
	fmt.Println(sc, string(resp))
}

func fuzzHostHeader(url string) *fuzzer.HostBehavior {
	HostResults := &fuzzer.HostBehavior{}
	HostResults.MultipleHostsAllowed = fuzzer.MultipleHostsAllowed(url)
	HostResults.WhichHostProcessed = fuzzer.WhichHostProcessed(url)

	return HostResults
}
