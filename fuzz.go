package main

import (
	"fmt"

	"github.com/httpscan/fuzzer"
)

func main() {
	HostResults := &fuzzer.HostBehavior{}
	HostResults.WhichHostProcessed = fuzzer.WhichHostProcessed("127.0.0.1:80")
	fmt.Println(HostResults.WhichHostProcessed)
}

func fuzzHostHeader(url string) *fuzzer.HostBehavior {
	HostResults := &fuzzer.HostBehavior{}
	HostResults.MultipleHostsAllowed = fuzzer.MultipleHostsAllowed(url)
	HostResults.WhichHostProcessed = fuzzer.WhichHostProcessed(url)

	return HostResults
}
