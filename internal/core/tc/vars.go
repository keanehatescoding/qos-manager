package tc

import (
	"github.com/kakeetopius/qosm/internal/core/filter"
)

//1: Root (The HTB classfull qdisc to be attached at egress)
//└── 1:1 ParentClass (parent of the all classes.)
//    ├── 1:10 HighClass (high priority class. Only Packets matched by HighPrioClassFilter reach here.)
//    ├── 1:19 LowClass  (low priority class. Only Packets matched by LowPrioClassFilter reach here.)
//    └── 1:15 DefaultClass (class where packets go if no filter matches on them)

var Root = HTBQdisc{
	Handle:       HTBQDISCHANDLE,
	Parent:       ROOTHANDLE,
	DefaultClass: uint32(HTBDEFAULTCLASS),
}

var ParentClass = HTBClass{
	Handle:       HTBPARENTCLASSHANDLE,
	ParentHandle: HTBQDISCHANDLE,
	Rate:         bytesPerSecFromMBsPerSec(100),
	Burst:        minBurst(100),
}

var HighClass = HTBClass{
	Handle:       HTBHIGHPRIOCLASSHANDLE,
	ParentHandle: HTBPARENTCLASSHANDLE,
	Priority:     Priority(HTBHIGHCLASSPRIO),
	Rate:         bytesPerSecFromMBsPerSec(50),
	Burst:        minBurst(50),
}

var LowClass = HTBClass{
	Handle:       HTBLOWPRIOCLASSHANDLE,
	ParentHandle: HTBPARENTCLASSHANDLE,
	Priority:     Priority(HTBLOWCLASSPRIO),
	Rate:         bytesPerSecFromMBsPerSec(10),
	Burst:        minBurst(10),
}

var DefaultClass = HTBClass{
	Handle:       HTBDEFAULTCLASSHANDLE,
	ParentHandle: HTBPARENTCLASSHANDLE,
	Priority:     Priority(HTBDEFAULTCLASSPRIO),
	Rate:         bytesPerSecFromMBsPerSec(40),
	Burst:        minBurst(40),
}

var HighPrioClassFilter = FWFilter{
	Handle:       filter.HIGHPRIOMARK,
	ParentHandle: HTBQDISCHANDLE,
	ClassID:      HTBHIGHPRIOCLASSHANDLE,
}

var LowPrioClassFilter = FWFilter{
	Handle: filter.LOWPRIOMARK,

	ParentHandle: HTBQDISCHANDLE,
	ClassID:      HTBLOWPRIOCLASSHANDLE,
}

func bytesPerSecFromMBsPerSec(megaBitsPerSecond uint32) uint32 {
	return (megaBitsPerSecond * 1_000_000) / 8
}

func minBurst(megaBitsPerSecond uint32) uint32 {
	const hz = 100
	const mtu = 1500
	return bytesPerSecFromMBsPerSec(megaBitsPerSecond)/hz + mtu
}
