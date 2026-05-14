package tc

import (
	"log"

	"github.com/florianl/go-tc/core"
	"github.com/kakeetopius/qosm/internal/core/filter"
)

//1: Root (The HTB classfull qdisc to be attached at egress)
//└── 1:1 ParentClass (parent of the all classes.)
//    ├── 1:10 HighClass (high priority class. Only Packets matched by HighPrioClassFilter reach here.)
//    ├── 1:19 LowClass  (low priority class. Only Packets matched by LowPrioClassFilter reach here.)
//    └── 1:15 DefaultClass (class where packets go if no filter matches on them)

func Root() *HTBQdisc {
	return &HTBQdisc{
		Handle:       HTBQDISCHANDLE,
		Parent:       ROOTHANDLE,
		DefaultClass: uint32(HTBDEFAULTCLASS),
	}
}

func ParentClass() *HTBClass {
	return &HTBClass{
		Handle:       HTBPARENTCLASSHANDLE,
		ParentHandle: HTBQDISCHANDLE,
		Rate:         bytesPerSecFromMBsPerSec(100),
		Burst:        minBurst(100),
		Cburst:       minBurst(100),
	}
}

func HighClass() *HTBClass {
	return &HTBClass{
		Handle:       HTBHIGHPRIOCLASSHANDLE,
		ParentHandle: HTBPARENTCLASSHANDLE,
		Priority:     Priority(HTBHIGHCLASSPRIO),
		Rate:         bytesPerSecFromMBsPerSec(50),
		Burst:        minBurst(50),
		Cburst:       minBurst(50),
	}
}

func LowClass() *HTBClass {
	return &HTBClass{
		Handle:       HTBLOWPRIOCLASSHANDLE,
		ParentHandle: HTBPARENTCLASSHANDLE,
		Priority:     Priority(HTBLOWCLASSPRIO),
		Rate:         bytesPerSecFromMBsPerSec(10),
		Burst:        minBurst(10),
		Cburst:       minBurst(10),
	}
}

func DefaultClass() *HTBClass {
	return &HTBClass{
		Handle:       HTBDEFAULTCLASSHANDLE,
		ParentHandle: HTBPARENTCLASSHANDLE,
		Priority:     Priority(HTBDEFAULTCLASSPRIO),
		Rate:         bytesPerSecFromMBsPerSec(40),
		Burst:        minBurst(40),
		Cburst:       minBurst(40),
	}
}

func HighPrioClassFilter() *FWFilter {
	return &FWFilter{
		Handle:       filter.HIGHPRIOMARK,
		ParentHandle: HTBQDISCHANDLE,
		ClassID:      HTBHIGHPRIOCLASSHANDLE,
	}
}

func LowPrioClassFilter() *FWFilter {
	return &FWFilter{
		Handle: filter.LOWPRIOMARK,

		ParentHandle: HTBQDISCHANDLE,
		ClassID:      HTBLOWPRIOCLASSHANDLE,
	}
}

func bytesPerSecFromMBsPerSec(megaBitsPerSecond uint32) uint32 {
	return (megaBitsPerSecond * 1_000_000) / 8
}

func minBurst(megabitsPerSecond uint32) uint32 {
	if !core.IsClockInitialized() {
		err := core.InitializeClock()
		if err != nil {
			log.Println(err)
		}
	}

	// convert Mb/s → bytes/s
	rateBytesPerSec := bytesPerSecFromMBsPerSec(megabitsPerSecond)

	const (
		mtu = 1500
		hz  = 1000
	)

	burstBytes := uint32(rateBytesPerSec/uint32(hz)) + mtu

	// how much time in microseconds does it take to transmit the burstBytes at the given rate
	xmitTime := core.XmitTime(uint64(rateBytesPerSec), uint32(burstBytes))

	// convert time to kernel ticks
	ticks := core.Time2Tick(xmitTime)

	return ticks
}
