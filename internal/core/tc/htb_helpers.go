// Package tc is used to interface with the traffic control subsystem to manipulate rules.
package tc

import (
	"log/slog"
	"net"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/kakeetopius/qosm/internal/core/nft"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func (c *HTBCtx) Debug(msg string, args ...any) {
	if c.Logger != nil {
		c.Logger.Debug(msg, args...)
		return
	}

	slog.Debug(msg, args...)
}

func (c *HTBCtx) Info(msg string, args ...any) {
	if c.Logger != nil {
		c.Logger.Info(msg, args...)
		return
	}

	slog.Info(msg, args...)
}

func (c *HTBCtx) Warn(msg string, args ...any) {
	if c.Logger != nil {
		c.Logger.Warn(msg, args...)
		return
	}

	slog.Warn(msg, args...)
}

func (c *HTBCtx) Error(msg string, args ...any) {
	if c.Logger != nil {
		c.Logger.Error(msg, args...)
		return
	}

	slog.Error(msg, args...)
}

func (c *HTBCtx) createQdisc(dev *net.Interface) (*HTBIface, error) {
	err := c.Conn.SetOption(netlink.ExtendedAcknowledge, true) // for better error messages
	if err != nil {
		return nil, err
	}

	c.Debug("tc: adding root qdisc", "name", "root")
	rootHtbQdisc, err := c.addRootQdisc(dev)
	if err != nil {
		return nil, err
	}

	c.Debug("tc: adding class", "name", "htb_parent_class")
	htbParentClass, err := c.addHtbClass(dev, ParentClass())
	if err != nil {
		return nil, err
	}

	c.Debug("tc: adding class", "name", "high_priority_class")
	highClass, err := c.addHtbClass(dev, HighClass())
	if err != nil {
		return nil, err
	}

	c.Debug("tc: adding class", "name", "low_priority_class")
	lowClass, err := c.addHtbClass(dev, LowClass())
	if err != nil {
		return nil, err
	}

	c.Debug("tc: adding class", "name", "default_class")
	defaultClass, err := c.addHtbClass(dev, DefaultClass())
	if err != nil {
		return nil, err
	}

	c.Debug("tc: adding filter", "name", "high_priority_filter")
	highPriofilter, err := c.addFWFilter(dev, HighPrioClassFilter())
	if err != nil {
		return nil, err
	}

	c.Debug("tc: adding filter", "name", "low_priority_filter")
	lowPrioFilter, err := c.addFWFilter(dev, LowPrioClassFilter())
	if err != nil {
		return nil, err
	}

	return &HTBIface{
		Root:            rootHtbQdisc,
		ParentClass:     htbParentClass,
		HighClass:       highClass,
		LowClass:        lowClass,
		DefaultClass:    defaultClass,
		LowClassFilter:  lowPrioFilter,
		HighClassFilter: highPriofilter,
	}, nil
}

func (c *HTBCtx) getQdisc(dev *net.Interface) (*HTBIface, error) {
	qdiscs, qerr := c.Conn.Qdisc().Get()
	if qerr != nil {
		return nil, qerr
	}

	if len(qdiscs) == 0 {
		return nil, ErrQdiscNotFound
	}

	htbCtx := HTBIface{}

	htbCtx.Root = findQdiscByHandle(qdiscs, HTBQDISCHANDLE, dev)
	if htbCtx.Root == nil {
		return nil, ErrQdiscNotFound
	}

	msg := tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: uint32(dev.Index),
	}

	classes, qerr := c.Conn.Class().Get(&msg)
	if qerr != nil {
		return nil, qerr
	}

	classMap := c.mapClassesByHandle(classes, dev)
	htbCtx.ParentClass = classMap[HTBPARENTCLASSHANDLE]
	htbCtx.HighClass = classMap[HTBHIGHPRIOCLASSHANDLE]
	htbCtx.LowClass = classMap[HTBLOWPRIOCLASSHANDLE]
	htbCtx.DefaultClass = classMap[HTBDEFAULTCLASSHANDLE]

	if err := validateClasses(&htbCtx); err != nil {
		return nil, err
	}

	filters, qerr := c.Conn.Filter().Get(&msg)
	if qerr != nil {
		return nil, qerr
	}

	filterMap := c.mapFiltersByHandle(filters, dev)
	htbCtx.HighClassFilter = filterMap[nft.HIGHPRIOMARK]
	htbCtx.LowClassFilter = filterMap[nft.LOWPRIOMARK]

	if err := validateFilters(&htbCtx); err != nil {
		return nil, err
	}

	return &htbCtx, nil
}

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
func (c *HTBCtx) addRootQdisc(iface *net.Interface) (*tc.Object, error) {
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

	err := c.Conn.Qdisc().Add(&rootHtbQdisc)
	if err != nil {
		return nil, err
	}

	return &rootHtbQdisc, nil
}

// addHtbClass adds an HTB  traffic class to the specified network interface.
// If priority in the class is non-zero, it is set on the class
// Returns a pointer to the created class object or an error if the operation fails.
func (c *HTBCtx) addHtbClass(iface *net.Interface, class *HTBClass) (*tc.Object, error) {
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

	err := c.Conn.Class().Add(&classObj)
	if err != nil {
		return nil, err
	}

	return &classObj, nil
}

// addFWFilter adds a firewall (fw) filter to the specified network interface.
// Returns a pointer to the created filter object or an error if the operation fails.
func (c *HTBCtx) addFWFilter(iface *net.Interface, filter *FWFilter) (*tc.Object, error) {
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
	err := c.Conn.Filter().Add(&filterObj)
	if err != nil {
		return nil, err
	}

	return &filterObj, nil
}

// findQdiscByHandle searches for an HTB qdisc with the specified handle.
// Returns a pointer to the qdisc if found, nil otherwise.
func findQdiscByHandle(qdiscs []tc.Object, handle uint32, iface *net.Interface) *tc.Object {
	for i, qdisc := range qdiscs {
		if qdisc.Kind == "htb" && qdisc.Handle == handle && qdisc.Ifindex == uint32(iface.Index) {
			return &qdiscs[i]
		}
	}
	return nil
}

// mapClassesByHandle creates a map of HTB classes indexed by their handles.
func (c *HTBCtx) mapClassesByHandle(classes []tc.Object, iface *net.Interface) map[uint32]*tc.Object {
	classMap := make(map[uint32]*tc.Object)
	for i, class := range classes {
		if class.Kind != "htb" || class.Ifindex != uint32(iface.Index) {
			continue
		}
		switch class.Handle {
		case HTBPARENTCLASSHANDLE:
			c.Debug("tc: class found", "name", "parent_class")
			classMap[class.Handle] = &classes[i]
		case HTBHIGHPRIOCLASSHANDLE:
			c.Debug("tc: class found", "name", "high_priority_class")
			classMap[class.Handle] = &classes[i]
		case HTBLOWPRIOCLASSHANDLE:
			c.Debug("tc: class found", "name", "low_priority_class")
			classMap[class.Handle] = &classes[i]
		case HTBDEFAULTCLASSHANDLE:
			c.Debug("tc: class found", "name", "default_class")
			classMap[class.Handle] = &classes[i]
		}
	}
	return classMap
}

// validateClasses checks that all required HTB classes are present.
// Returns an error if any required class is missing.
func validateClasses(htbCtx *HTBIface) error {
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
func (c *HTBCtx) mapFiltersByHandle(filters []tc.Object, iface *net.Interface) map[uint32]*tc.Object {
	filterMap := make(map[uint32]*tc.Object)
	for i, htbFilter := range filters {
		if htbFilter.Kind != "fw" || htbFilter.Ifindex != uint32(iface.Index) {
			continue
		}
		switch htbFilter.Handle {
		case nft.HIGHPRIOMARK:
			c.Debug("tc: filter found", "name", "high_priority_filter")
			filterMap[htbFilter.Handle] = &filters[i]
		case nft.LOWPRIOMARK:
			c.Debug("tc: filter found", "name", "low_priority_filter")
			filterMap[htbFilter.Handle] = &filters[i]
		}
	}
	return filterMap
}

// validateFilters checks that all required firewall filters are present.
// Returns an error if any required filter is missing.
func validateFilters(htbCtx *HTBIface) error {
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

func (c *HTBCtx) deleteQdisc(qdisc *tc.Object) error {
	err := c.Conn.Qdisc().Delete(qdisc)
	if err != nil {
		return err
	}

	return nil
}
