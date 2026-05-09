// Package tc is used to interface with the traffic control subsystem to manipulate rules.
package tc

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/kakeetopius/qosm/internal/core/filter"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func AddRule(iface string, target netip.Prefix, priority string) error {
	err := filter.MarkPacket(target.Addr())
	if err != nil {
		return err
	}

	err = createQdisc(iface)
	if err != nil {
		return err
	}
	return nil
}

func createQdisc(iface string) error {
	if iface == "" {
		return fmt.Errorf("no interface given")
	}
	devID, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}

	fmt.Println()
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return err
	}

	err = tcnl.SetOption(netlink.ExtendedAcknowledge, true)
	if err != nil {
		return err
	}

	rootQdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  core.BuildHandle(0x1, 0x0),
			Parent:  tc.HandleRoot,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "htb",
			Htb: &tc.Htb{
				Init: &tc.HtbGlob{
					Version: 0x3,
					Defcls:  30,
				},
			},
		},
	}

	fmt.Println("Adding Root Qdisc")
	if err := tcnl.Qdisc().Add(&rootQdisc); err != nil {
		return err
	}

	highClass := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  core.BuildHandle(0x1, 0x10),
			Parent:  core.BuildHandle(0x1, 0x0),
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
		return err
	}

	lowClass := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  core.BuildHandle(0x1, 0x30),
			Parent:  core.BuildHandle(0x1, 0x0),
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
		return err
	}

	highHandle := core.BuildHandle(0x1, 0x10)
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  10,
			Parent:  core.BuildHandle(0x1, 0x0),
			Info:    core.FilterInfo(1, unix.ETH_P_IP),
		},
		Attribute: tc.Attribute{
			Kind: "fw",
			Fw: &tc.Fw{
				ClassID: &highHandle,
			},
		},
	}
	fmt.Println("Adding filter")
	if err := tcnl.Filter().Add(&filter); err != nil {
		return err
	}

	return nil
}
