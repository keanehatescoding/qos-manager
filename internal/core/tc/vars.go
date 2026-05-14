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
		Burst:        calcBurst(100),
		Cburst:       calcBurst(100),
	}
}

func HighClass() *HTBClass {
	return &HTBClass{
		Handle:       HTBHIGHPRIOCLASSHANDLE,
		ParentHandle: HTBPARENTCLASSHANDLE,
		Priority:     Priority(HTBHIGHCLASSPRIO),
		Rate:         bytesPerSecFromMBsPerSec(50),
		Burst:        calcBurst(50),
		Cburst:       calcBurst(50),
	}
}

func LowClass() *HTBClass {
	return &HTBClass{
		Handle:       HTBLOWPRIOCLASSHANDLE,
		ParentHandle: HTBPARENTCLASSHANDLE,
		Priority:     Priority(HTBLOWCLASSPRIO),
		Rate:         bytesPerSecFromMBsPerSec(10),
		Burst:        calcBurst(10),
		Cburst:       calcBurst(10),
	}
}

func DefaultClass() *HTBClass {
	return &HTBClass{
		Handle:       HTBDEFAULTCLASSHANDLE,
		ParentHandle: HTBPARENTCLASSHANDLE,
		Priority:     Priority(HTBDEFAULTCLASSPRIO),
		Rate:         bytesPerSecFromMBsPerSec(40),
		Burst:        calcBurst(40),
		Cburst:       calcBurst(40),
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

	const (
		mtu = 1500
	)

	// GetTickInUSec returns how many kernel ticks are in one microsecond.
	// The conversion below determines how many ticks are in one second which is the kernel frequency(hz)
	hz := uint64(1_000_000.0 / core.GetTickInUSec())

	// burstBytes is how many bytes can accumulate for each time interval when the schedular is asleep.(schedular wakeups hz times per second)
	// duration of time the schedular is asleep is 1 / freq so numBytes = speed x time = speed x (1/freq)
	burstBytes := (uint64(rateBytesPerSec) / hz) + mtu

	// how much time in microseconds does it take to transmit the burstBytes at the given rate
	xmitTime := core.XmitTime(uint64(rateBytesPerSec), uint32(burstBytes))

	// convert time to kernel ticks
	ticks := core.Time2Tick(xmitTime)

	// we return ticks as the burst because the kerenl doesnt store burst as bytesPerSecond rather as
	// transmission duration ie how long can this class transmit at full rate before bucket empties.
	return ticks
}
