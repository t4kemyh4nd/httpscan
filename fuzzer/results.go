package fuzzer

type HostBehavior struct {
	MultipleHostsAllowed       bool
	WhichHostProcessed         int
	ValidCharsInHostHeader     []string
	ValidCharsInHostHeaderPort []string
}

type BasicBehavior struct {

// Content length section

	// Based on the array indices:
	// 0 - HTTP 1.1
	// 1 - HTTP 1.0
	// 2 - HTTP 0.9
	NoCL	        	[3]bool
	MultipleCLFirst 	[3]bool
	MultipleCLSecond 	[3]bool
	SmallCL      		[3]bool
	LargeCL		      	[3]bool

// Invalid HTTP version section

/*	V100			bool
	V001			bool
	V110			bool
	V119			bool
	V20			bool
	V9			bool
	V099			bool
	V99			bool

	PV100			bool
	PV001			bool
	PV110			bool
	PV119			bool
	PV20			bool
	PV9			bool
	PV099			bool
	PV99			bool
*/
}
