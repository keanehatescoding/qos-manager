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

func AddRule(iface string, target netip.Prefix, priority Priority) (err error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return err
	}
	defer tcnl.Close()

	_, err = RootQdisc(tcnl, iface)
	if err != nil {
		if !errors.Is(err, ErrQdiscNotFound) {
			return err
		}
		_, err = createQdisc(tcnl, iface)
		if err != nil {
			return err
		}
	}

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

func RootQdisc(conn *tc.Tc, iface string) (*tc.Object, error) {
	qdiscs, err := conn.Qdisc().Get()
	if err != nil {
		return nil, err
	}

	for _, qdisc := range qdiscs {
		if qdisc.Kind != "htb" {
			continue
		}
		if qdisc.Handle != HTBQDISCHANDLE {
			continue
		}
		return &qdisc, nil
	}

	return nil, ErrQdiscNotFound
}

func GetHTBCtx(iface string) (*HTBCtx, error) {
	var err error
	conn, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}

	htbCtx, err := getQdisc(conn, iface)
	if err != nil {
		return nil, err
	}
	htbCtx.Conn = conn

	return htbCtx, nil
}

func createQdisc(tcnl *tc.Tc, iface string) (*HTBCtx, error) {
	if iface == "" {
		return nil, fmt.Errorf("no interface given")
	}
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	err = tcnl.SetOption(netlink.ExtendedAcknowledge, true) // for better error messages
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding root qdisc")
	rootHtbQdisc, err := addRootQdisc(tcnl, dev)
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding Parent Class.")
	htbParentClass, err := addHtbClass(tcnl, dev, &ParentClass)
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding High Class")
	highClass, err := addHtbClass(tcnl, dev, &HighClass)
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding Low Class")
	lowClass, err := addHtbClass(tcnl, dev, &LowClass)
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding default Class")
	defaultClass, err := addHtbClass(tcnl, dev, &DefaultClass)
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding High Priority Filter")
	highPriofilter, err := addFWFilter(tcnl, dev, &HighPrioClassFilter)
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding low filter")
	lowPrioFilter, err := addFWFilter(tcnl, dev, &LowPrioClassFilter)
	if err != nil {
		return nil, err
	}

	return &HTBCtx{
		Conn:            tcnl,
		Root:            rootHtbQdisc,
		ParentClass:     htbParentClass,
		HighClass:       highClass,
		LowClass:        lowClass,
		DefaultClass:    defaultClass,
		LowClassFilter:  lowPrioFilter,
		HighClassFilter: highPriofilter,
	}, nil
}

func addRootQdisc(tcnl *tc.Tc, iface *net.Interface) (*tc.Object, error) {
	rootHtbQdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  Root.Handle,
			Parent:  Root.Parent,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "htb",
			Htb: &tc.Htb{
				Init: &tc.HtbGlob{
					Version: 0x3,
					Defcls:  Root.DefaultClass,
				},
			},
		},
	}

	fmt.Println("Adding Root Qdisc")
	err := tcnl.Qdisc().Add(&rootHtbQdisc)
	if err != nil {
		return nil, err
	}

	return &rootHtbQdisc, nil
}

func addHtbClass(tcnl *tc.Tc, iface *net.Interface, class *HTBClass) (*tc.Object, error) {
	classObj := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  class.Handle,
			Parent:  class.ParentHandle,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "htb",
			Htb: &tc.Htb{
				Parms: &tc.HtbOpt{
					Rate: tc.RateSpec{
						Rate: class.Rate,
					},
					Ceil: tc.RateSpec{
						Rate: class.Rate,
					},
					Buffer: class.Burst,
				},
			},
		},
	}

	if class.Priority != 0 {
		classObj.Htb.Parms.Prio = uint32(class.Priority)
	}

	err := tcnl.Class().Add(&classObj)
	if err != nil {
		return nil, err
	}

	return &classObj, nil
}

func addFWFilter(tcnl *tc.Tc, iface *net.Interface, filter *FWFilter) (*tc.Object, error) {
	filterObj := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  filter.Handle,
			Parent:  filter.ParentHandle,
			Info:    core.FilterInfo(1, unix.ETH_P_IP),
		},
		Attribute: tc.Attribute{
			Kind: "fw",
			Fw: &tc.Fw{
				ClassID: &filter.ClassID,
			},
		},
	}
	err := tcnl.Filter().Add(&filterObj)
	if err != nil {
		return nil, err
	}

	return &filterObj, nil
}

func getQdisc(tcnl *tc.Tc, iface string) (*HTBCtx, error) {
	qdiscs, err := tcnl.Qdisc().Get()
	if err != nil {
		return nil, err
	}

	if len(qdiscs) == 0 {
		return nil, ErrQdiscNotFound
	}

	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	htbCtx := HTBCtx{}
	for _, qdisc := range qdiscs {
		if qdisc.Kind != "htb" {
			continue
		}
		if qdisc.Handle != HTBQDISCHANDLE {
			continue
		}
		fmt.Println("Qdisc found")
		htbCtx.Root = &qdisc
	}
	if htbCtx.Root == nil {
		return nil, ErrQdiscNotFound
	}

	msg := tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: uint32(dev.Index),
	}

	classes, err := tcnl.Class().Get(&msg)
	if err != nil {
		return nil, err
	}

	for _, class := range classes {
		if class.Kind != "htb" {
			continue
		}
		switch class.Handle {
		case HTBPARENTCLASSHANDLE:
			fmt.Println("Parent class found")
			htbCtx.ParentClass = &class
		case HTBHIGHPRIOCLASSHANDLE:
			fmt.Println("High Class found")
			htbCtx.HighClass = &class
		case HTBLOWPRIOCLASSHANDLE:
			fmt.Println("Low Class found")
			htbCtx.LowClass = &class
		case HTBDEFAULTCLASSHANDLE:
			fmt.Println("Default Class found")
			htbCtx.DefaultClass = &class
		default:
			continue
		}
	}

	switch {
	case htbCtx.ParentClass == nil:
		return nil, ErrClassNotFound{
			ClassName:   "parent",
			ClassHandle: HTBPARENTCLASSHANDLE,
		}
	case htbCtx.HighClass == nil:
		return nil, ErrClassNotFound{
			ClassName:   "high_class",
			ClassHandle: HTBHIGHPRIOCLASSHANDLE,
		}
	case htbCtx.LowClass == nil:
		return nil, ErrClassNotFound{
			ClassName:   "low_class",
			ClassHandle: HTBLOWPRIOCLASSHANDLE,
		}
	case htbCtx.DefaultClass == nil:
		return nil, ErrClassNotFound{
			ClassName:   "default",
			ClassHandle: HTBDEFAULTCLASSHANDLE,
		}
	}

	filters, err := tcnl.Filter().Get(&msg)
	if err != nil {
		return nil, err
	}

	for _, htbFilter := range filters {
		if htbFilter.Kind != "fw" {
			continue
		}

		switch htbFilter.Handle {
		case filter.HIGHPRIOMARK:
			fmt.Println("High Class Filter found")
			htbCtx.HighClassFilter = &htbFilter
		case filter.LOWPRIOMARK:
			fmt.Println("Low Class Filter found")
			htbCtx.LowClassFilter = &htbFilter
		default:
			continue
		}
	}

	switch {
	case htbCtx.LowClassFilter == nil:
		return nil, ErrFilterNotFound{
			FilterName:   "low_class_filter",
			FilterHandle: filter.LOWPRIOMARK,
		}
	case htbCtx.HighClassFilter == nil:
		return nil, ErrFilterNotFound{
			FilterName:   "high_class_filter",
			FilterHandle: filter.HIGHPRIOMARK,
		}
	}

	return &htbCtx, nil
}
