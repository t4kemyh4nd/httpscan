package fuzzer

type HostBehavior struct {
	MultipleHostsAllowed       bool
	WhichHostProcessed         int
	ValidCharsInHostHeader     []string
	ValidCharsInHostHeaderPort []string
}
