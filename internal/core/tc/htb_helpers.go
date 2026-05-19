// Package tc is used to interface with the traffic control subsystem to manipulate rules.
package tc

import (
	"fmt"
	"net"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/kakeetopius/qosm/internal/core/nft"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// findRootQdisc searches for the root HTB  queue discipline
// on the specified network interface. It queries all qdiscs on the system and matches
// by interface, qdisc kind (htb), and the root qdisc handle (HTBQDISCHANDLE).
// Returns a pointer to the matching qdisc object if found, or ErrQdiscNotFound if not present.
// Returns an error if the qdisc query fails.
func findRootQdisc(conn *tc.Tc, dev *net.Interface) (*tc.Object, error) {
	qdiscs, err := conn.Qdisc().Get()
	if err != nil {
		return nil, err
	}

	rootQdisc := findQdiscByHandle(qdiscs, HTBQDISCHANDLE, dev)
	if rootQdisc == nil {
		return nil, ErrQdiscNotFound
	}

	return rootQdisc, nil
}

// addRootQdisc adds a root HTB  queue discipline to the
// specified network interface.
// Returns a pointer to the created qdisc object or an error if the operation fails.
func addRootQdisc(tcnl *tc.Tc, iface *net.Interface) (*tc.Object, error) {
	rootQdisc := Root()
	rootHtbQdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  rootQdisc.Handle,
			Parent:  rootQdisc.Parent,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "htb",
			Htb: &tc.Htb{
				Init: &tc.HtbGlob{
					Version: 0x3,
					Defcls:  rootQdisc.DefaultClass,
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

// addHtbClass adds an HTB  traffic class to the specified network interface.
// If priority in the class is non-zero, it is set on the class
// Returns a pointer to the created class object or an error if the operation fails.
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
					Buffer:  class.Burst,
					Cbuffer: class.Cburst,
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

// addFWFilter adds a firewall (fw) filter to the specified network interface.
// Returns a pointer to the created filter object or an error if the operation fails.
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

// createQdisc initializes a complete HTB  queue discipline
// hierarchy on the specified network interface. It creates the root qdisc, parent class,
// and three traffic classes (high priority, low priority, and default). It also adds
// firewall filters to route marked packets to the appropriate classes.
// Returns a populated HTBCtx struct containing all created objects and the netlink connection,
// or an error if any step of the initialization fails.
func createQdisc(tcnl *tc.Tc, dev *net.Interface) (*HTBCtx, error) {
	err := tcnl.SetOption(netlink.ExtendedAcknowledge, true) // for better error messages
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding root qdisc")
	rootHtbQdisc, err := addRootQdisc(tcnl, dev)
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding Parent Class.")
	htbParentClass, err := addHtbClass(tcnl, dev, ParentClass())
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding High Class")
	highClass, err := addHtbClass(tcnl, dev, HighClass())
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding Low Class")
	lowClass, err := addHtbClass(tcnl, dev, LowClass())
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding default Class")
	defaultClass, err := addHtbClass(tcnl, dev, DefaultClass())
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding High Priority Filter")
	highPriofilter, err := addFWFilter(tcnl, dev, HighPrioClassFilter())
	if err != nil {
		return nil, err
	}

	fmt.Println("Adding low filter")
	lowPrioFilter, err := addFWFilter(tcnl, dev, LowPrioClassFilter())
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

// getQdisc retrieves the complete qosm HTB queue discipline
// configuration for the specified network interface. It queries all qdiscs, classes,
// and filters on the system and assembles them into an HTBCtx struct.
// The function validates that all required components (root qdisc, parent class,
// high/low/default classes, and high/low priority filters) are present.
// Returns a populated HTBCtx struct or an error if any required component is missing
// or if any query operation fails.
func getQdisc(tcnl *tc.Tc, dev *net.Interface) (*HTBCtx, error) {
	qdiscs, qerr := tcnl.Qdisc().Get()
	if qerr != nil {
		return nil, qerr
	}

	if len(qdiscs) == 0 {
		return nil, ErrQdiscNotFound
	}

	htbCtx := HTBCtx{}

	htbCtx.Root = findQdiscByHandle(qdiscs, HTBQDISCHANDLE, dev)
	if htbCtx.Root == nil {
		return nil, ErrQdiscNotFound
	}

	msg := tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: uint32(dev.Index),
	}

	classes, qerr := tcnl.Class().Get(&msg)
	if qerr != nil {
		return nil, qerr
	}

	classMap := mapClassesByHandle(classes, dev)
	htbCtx.ParentClass = classMap[HTBPARENTCLASSHANDLE]
	htbCtx.HighClass = classMap[HTBHIGHPRIOCLASSHANDLE]
	htbCtx.LowClass = classMap[HTBLOWPRIOCLASSHANDLE]
	htbCtx.DefaultClass = classMap[HTBDEFAULTCLASSHANDLE]

	if err := validateClasses(&htbCtx); err != nil {
		return nil, err
	}

	filters, qerr := tcnl.Filter().Get(&msg)
	if qerr != nil {
		return nil, qerr
	}

	filterMap := mapFiltersByHandle(filters, dev)
	htbCtx.HighClassFilter = filterMap[nft.HIGHPRIOMARK]
	htbCtx.LowClassFilter = filterMap[nft.LOWPRIOMARK]

	if err := validateFilters(&htbCtx); err != nil {
		return nil, err
	}

	return &htbCtx, nil
}

// findQdiscByHandle searches for an HTB qdisc with the specified handle.
// Returns a pointer to the qdisc if found, nil otherwise.
func findQdiscByHandle(qdiscs []tc.Object, handle uint32, iface *net.Interface) *tc.Object {
	for i, qdisc := range qdiscs {
		if qdisc.Kind == "htb" && qdisc.Handle == handle && qdisc.Ifindex == uint32(iface.Index) {
			fmt.Println("Qdisc found")
			return &qdiscs[i]
		}
	}
	return nil
}

// mapClassesByHandle creates a map of HTB classes indexed by their handles.
func mapClassesByHandle(classes []tc.Object, iface *net.Interface) map[uint32]*tc.Object {
	classMap := make(map[uint32]*tc.Object)
	for i, class := range classes {
		if class.Kind != "htb" || class.Ifindex != uint32(iface.Index) {
			continue
		}
		switch class.Handle {
		case HTBPARENTCLASSHANDLE:
			fmt.Println("Parent class found")
			classMap[class.Handle] = &classes[i]
		case HTBHIGHPRIOCLASSHANDLE:
			fmt.Println("High Class found")
			classMap[class.Handle] = &classes[i]
		case HTBLOWPRIOCLASSHANDLE:
			fmt.Println("Low Class found")
			classMap[class.Handle] = &classes[i]
		case HTBDEFAULTCLASSHANDLE:
			fmt.Println("Default Class found")
			classMap[class.Handle] = &classes[i]
		}
	}
	return classMap
}

// validateClasses checks that all required HTB classes are present.
// Returns an error if any required class is missing.
func validateClasses(htbCtx *HTBCtx) error {
	switch {
	case htbCtx.ParentClass == nil:
		return ErrClassNotFound{
			ClassName:   "parent",
			ClassHandle: HTBPARENTCLASSHANDLE,
		}
	case htbCtx.HighClass == nil:
		return ErrClassNotFound{
			ClassName:   "high_class",
			ClassHandle: HTBHIGHPRIOCLASSHANDLE,
		}
	case htbCtx.LowClass == nil:
		return ErrClassNotFound{
			ClassName:   "low_class",
			ClassHandle: HTBLOWPRIOCLASSHANDLE,
		}
	case htbCtx.DefaultClass == nil:
		return ErrClassNotFound{
			ClassName:   "default",
			ClassHandle: HTBDEFAULTCLASSHANDLE,
		}
	}
	return nil
}

// mapFiltersByHandle creates a map of firewall filters indexed by their handles.
func mapFiltersByHandle(filters []tc.Object, iface *net.Interface) map[uint32]*tc.Object {
	filterMap := make(map[uint32]*tc.Object)
	for i, htbFilter := range filters {
		if htbFilter.Kind != "fw" || htbFilter.Ifindex != uint32(iface.Index) {
			continue
		}
		switch htbFilter.Handle {
		case nft.HIGHPRIOMARK:
			fmt.Println("High Class Filter found")
			filterMap[htbFilter.Handle] = &filters[i]
		case nft.LOWPRIOMARK:
			fmt.Println("Low Class Filter found")
			filterMap[htbFilter.Handle] = &filters[i]
		}
	}
	return filterMap
}

// validateFilters checks that all required firewall filters are present.
// Returns an error if any required filter is missing.
func validateFilters(htbCtx *HTBCtx) error {
	switch {
	case htbCtx.LowClassFilter == nil:
		return ErrFilterNotFound{
			FilterName:   "low_class_filter",
			FilterHandle: nft.LOWPRIOMARK,
		}
	case htbCtx.HighClassFilter == nil:
		return ErrFilterNotFound{
			FilterName:   "high_class_filter",
			FilterHandle: nft.HIGHPRIOMARK,
		}
	}
	return nil
}

func deleteQdisc(tcnl *tc.Tc, qdisc *tc.Object) error {
	fmt.Println("Deleting qdisc on root.")
	err := tcnl.Qdisc().Delete(qdisc)
	if err != nil {
		return err
	}

	return nil
}
