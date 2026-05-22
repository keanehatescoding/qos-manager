package tc

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/florianl/go-tc"
	"github.com/kakeetopius/qosm/internal/core/nft"
)

func InitHTBQdisc(iface string) (*HTBCtx, error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}

	if iface == "" {
		return nil, fmt.Errorf("no interface given")
	}
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	htbCtx := HTBCtx{}
	var htbIface *HTBIface
	_, err = findRootQdisc(tcnl, dev)
	if err != nil {
		if !errors.Is(err, ErrQdiscNotFound) {
			return nil, err
		}
		htbIface, err = createQdisc(tcnl, dev)
	} else {
		htbIface, err = getQdisc(tcnl, dev)
	}

	if err != nil {
		return nil, err
	}

	htbCtx.HTBIfaces = make(map[int]HTBIface)
	htbCtx.HTBIfaces[dev.Index] = *htbIface

	htbCtx.Conn = tcnl

	return &htbCtx, nil
}

func (c *HTBCtx) InitHTBFilter() error {
	nftCtx, err := nft.NewNFTCtx()
	if err != nil {
		return err
	}
	c.NFTFilter = &nftCtx

	for ifIndex := range c.HTBIfaces {
		err := c.NFTFilter.AddIfaceRules(ifIndex)
		if err != nil {
			return err
		}
	}
	return nil
}

func HasHTBQdisc(iface *net.Interface) (bool, error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return false, err
	}

	_, err = findRootQdisc(tcnl, iface)
	if err != nil {
		if errors.Is(err, ErrQdiscNotFound) {
			return false, nil
		}
		return false, err
	} else {
		return true, nil
	}
}

func (c *HTBCtx) AddRule(target []netip.Prefix, priority Priority) (err error) {
	if c.NFTFilter == nil {
		return fmt.Errorf(" HTB filter uninitialised")
	}

	switch priority {
	case PRIORITYHIGH:
		err = c.NFTFilter.AddTargetsToHighPriority(target)
	case PRIORITYLOW:
		err = c.NFTFilter.AddTargetsToLowPriority(target)
	default:
		return fmt.Errorf("unknown priority %v", priority)
	}
	if err != nil {
		return err
	}

	return nil
}

func (c *HTBCtx) Close() error {
	return c.Conn.Close()
}

func (c *HTBCtx) FlushQdisc(ifIndex int) error {
	qdisc := c.HTBIfaces[ifIndex]
	if qdisc.Root == nil {
		return nil
	}
	return deleteQdisc(c.Conn, qdisc.Root)
}

func FlushQdiscandFilters(iface string) error {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return err
	}

	defer func() {
		closeErr := tcnl.Close()
		if closeErr != nil {
			err = fmt.Errorf("%w", closeErr)
		}
	}()

	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}

	qdisc, err := findRootQdisc(tcnl, dev)
	if err != nil {
		if !errors.Is(err, ErrQdiscNotFound) {
			return err
		}
	}
	if qdisc != nil {
		err = deleteQdisc(tcnl, qdisc)
		if err != nil {
			return err
		}
	}
	return nil
}
