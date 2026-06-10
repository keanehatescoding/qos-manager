package htb

import (
	"log"

	"github.com/florianl/go-tc/core"
	"github.com/kakeetopius/qosm/internal/core/nft"
	"github.com/kakeetopius/qosm/internal/prio"
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
		Burst:        calcBurst(100),
		Cburst:       calcBurst(100),
	}
}

func HighClass() *HTBClass {
	return &HTBClass{
		Handle:       HTBHIGHPRIOCLASSHANDLE,
		ParentHandle: HTBPARENTCLASSHANDLE,
		Priority:     prio.Priority(HTBHIGHCLASSPRIO),
		Rate:         bytesPerSecFromMBsPerSec(50),
		Burst:        calcBurst(50),
		Cburst:       calcBurst(50),
	}
}

func LowClass() *HTBClass {
	return &HTBClass{
		Handle:       HTBLOWPRIOCLASSHANDLE,
		ParentHandle: HTBPARENTCLASSHANDLE,
		Priority:     prio.Priority(HTBLOWCLASSPRIO),
		Rate:         bytesPerSecFromMBsPerSec(10),
		Burst:        calcBurst(10),
		Cburst:       calcBurst(10),
	}
}

func DefaultClass() *HTBClass {
	return &HTBClass{
		Handle:       HTBDEFAULTCLASSHANDLE,
		ParentHandle: HTBPARENTCLASSHANDLE,
		Priority:     prio.Priority(HTBDEFAULTCLASSPRIO),
		Rate:         bytesPerSecFromMBsPerSec(40),
		Burst:        calcBurst(40),
		Cburst:       calcBurst(40),
	}
}

func HighPrioClassFilter() *FWFilter {
	return &FWFilter{
		Handle:       nft.HIGHPRIOMARK,
		ParentHandle: HTBQDISCHANDLE,
		ClassID:      HTBHIGHPRIOCLASSHANDLE,
	}
}

func LowPrioClassFilter() *FWFilter {
	return &FWFilter{
		Handle: nft.LOWPRIOMARK,

		ParentHandle: HTBQDISCHANDLE,
		ClassID:      HTBLOWPRIOCLASSHANDLE,
	}
}

func bytesPerSecFromMBsPerSec(megaBitsPerSecond uint32) uint32 {
	return uint32(megaBitsPerSecond*1_000_000) / 8
}

func calcBurst(megabitsPerSecond uint32) uint32 {
	if !core.IsClockInitialized() {
		err := core.InitializeClock()
		if err != nil {
			log.Println(err)
		}
	}

	// convert Mb/s to bytes/s
	rateBytesPerSec := bytesPerSecFromMBsPerSec(megabitsPerSecond)

	// allow a burst worth of 5ms at the given rate
	burstBytes := rateBytesPerSec * 5 / 1000

	// how much time in ticks does it take to transmit the burstBytes at the given rate
	xmitTime := core.XmitTime(uint64(rateBytesPerSec), burstBytes)

	// we return ticks burst as duration not size. That is what tc wants.
	return xmitTime
}
