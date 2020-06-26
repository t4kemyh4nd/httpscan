package main

import (
	"fmt"

	"github.com/httpscan/fuzzer"
)

func main() {
	hb := &fuzzer.HostBehavior{}
	hb = fuzzHostHeader("127.0.0.1:80")
	fmt.Println(hb)
}

func fuzzHostHeader(url string) *fuzzer.HostBehavior {
	HostResults := &fuzzer.HostBehavior{}
	HostResults.MultipleHostsAllowed = fuzzer.MultipleHostsAllowed(url)
	if HostResults.MultipleHostsAllowed == true {
		HostResults.WhichHostProcessed = fuzzer.WhichHostProcessed(url)
	}
	HostResults.ValidCharsInHostHeader = fuzzer.ValidCharsInHostHeader(url)
	HostResults.ValidCharsInHostHeaderPort = fuzzer.ValidCharsInHostHeaderPort(url)

	return HostResults
}
