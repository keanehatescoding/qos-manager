// Package tc is used to interface with the traffic control subsystem to manipulate rules.
package tc

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/kakeetopius/qosm/internal/core/filter"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Priority int

const (
	PRIORITYHIGH Priority = iota + 1
	PRIORITYLOW
)

const (
	ROOTHANDLE = tc.HandleRoot
)

var (
	HTBQDISCHANDLE         = core.BuildHandle(0x01, 0x00)
	HTBHIGHPRIOCLASSHANDLE = core.BuildHandle(0x01, 0x10)
	HTBLOWPRIOCLASSHANDLE  = core.BuildHandle(0x01, 0x20)
	HTBDEFAULTCLASSHANDLE  = core.BuildHandle(0x01, 0x30)
	HTBDEFAULTCLASS        = 30
)

var errQdiscNotFound = errors.New("qdisc not found")

func AddRule(iface string, target netip.Prefix, priority Priority) (err error) {
	conn, _, err := InitQdisc(iface)
	if err != nil {
		return err
	}

	defer func() {
		closeErr := conn.Close()
		if closeErr != nil {
			err = fmt.Errorf("%w", closeErr)
		}
	}()

	switch priority {
	case PRIORITYHIGH:
		err = filter.AddTargetToHighPriority(target.Addr())
	case PRIORITYLOW:
		err = filter.AddTargetToLowPriority(target.Addr())
	default:
		return fmt.Errorf("unknown priority %v", priority)
	}
	if err != nil {
		return err
	}

	return nil
}

func InitQdisc(iface string) (*tc.Tc, *tc.Object, error) {
	var err error
	conn, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, nil, err
	}

	qdisc, err := getQdisc(conn)
	if err != nil {
		if errors.Is(err, errQdiscNotFound) {
			qdisc, err = createQdisc(conn, iface)
		}
		if err != nil {
			return nil, nil, err
		}
	}

	return conn, qdisc, nil
}

func createQdisc(tcnl *tc.Tc, iface string) (*tc.Object, error) {
	if iface == "" {
		return nil, fmt.Errorf("no interface given")
	}
	devID, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	err = tcnl.SetOption(netlink.ExtendedAcknowledge, true) // for better error messages
	if err != nil {
		return nil, err
	}

	rootQdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  HTBQDISCHANDLE,
			Parent:  ROOTHANDLE,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "htb",
			Htb: &tc.Htb{
				Init: &tc.HtbGlob{
					Version: 0x3,
					Defcls:  uint32(HTBDEFAULTCLASS),
				},
			},
		},
	}

	fmt.Println("Adding Root Qdisc")
	if err := tcnl.Qdisc().Add(&rootQdisc); err != nil {
		return nil, err
	}

	highClass := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  HTBHIGHPRIOCLASSHANDLE,
			Parent:  HTBQDISCHANDLE,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "htb",
			Htb: &tc.Htb{
				Parms: &tc.HtbOpt{
					Rate: tc.RateSpec{
						Rate: 5000000,
					},
					Ceil: tc.RateSpec{
						Rate: 5000000,
					},
				},
			},
		},
	}
	fmt.Println("Adding High Class")
	if err := tcnl.Class().Add(&highClass); err != nil {
		return nil, err
	}

	lowClass := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  HTBLOWPRIOCLASSHANDLE,
			Parent:  HTBQDISCHANDLE,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "htb",
			Htb: &tc.Htb{
				Parms: &tc.HtbOpt{
					Rate: tc.RateSpec{
						Rate: 1000000,
					},
					Ceil: tc.RateSpec{
						Rate: 1000000,
					},
				},
			},
		},
	}
	fmt.Println("Adding Low Class")
	if err := tcnl.Class().Add(&lowClass); err != nil {
		return nil, err
	}

	defaultClass := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  HTBDEFAULTCLASSHANDLE,
			Parent:  HTBQDISCHANDLE,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "htb",
			Htb: &tc.Htb{
				Parms: &tc.HtbOpt{
					Rate: tc.RateSpec{
						Rate: 1000000,
					},
					Ceil: tc.RateSpec{
						Rate: 1000000,
					},
				},
			},
		},
	}

	fmt.Println("Adding default Class")
	if err := tcnl.Class().Add(&defaultClass); err != nil {
		return nil, err
	}

	highPriofilter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  filter.HIGHPRIOMARK,
			Parent:  HTBQDISCHANDLE,
			Info:    core.FilterInfo(1, unix.ETH_P_IP),
		},
		Attribute: tc.Attribute{
			Kind: "fw",
			Fw: &tc.Fw{
				ClassID: &HTBHIGHPRIOCLASSHANDLE,
			},
		},
	}
	fmt.Println("Adding high filter")
	if err := tcnl.Filter().Add(&highPriofilter); err != nil {
		return nil, err
	}

	lowPrioFilter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  filter.LOWPRIOMARK,
			Parent:  HTBQDISCHANDLE,
			Info:    core.FilterInfo(1, unix.ETH_P_IP),
		},
		Attribute: tc.Attribute{
			Kind: "fw",
			Fw: &tc.Fw{
				ClassID: &HTBLOWPRIOCLASSHANDLE,
			},
		},
	}

	fmt.Println("Adding low filter")
	if err := tcnl.Filter().Add(&lowPrioFilter); err != nil {
		return nil, err
	}

	return &rootQdisc, nil
}

func getQdisc(tcnl *tc.Tc) (*tc.Object, error) {
	qdiscs, err := tcnl.Qdisc().Get()
	if err != nil {
		return nil, err
	}

	if len(qdiscs) == 0 {
		return nil, errQdiscNotFound
	}

	for _, qdisc := range qdiscs {
		if qdisc.Kind != "htb" {
			continue
		}
		if qdisc.Handle != HTBQDISCHANDLE {
			continue
		}
		fmt.Println("Qdisc found")
		return &qdisc, nil
	}

	return nil, errQdiscNotFound
}
