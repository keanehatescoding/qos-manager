package tc

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/florianl/go-tc"
	"github.com/kakeetopius/qosm/internal/core/nft"
)

func NewHTBCtx() (*HTBCtx, error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}

	htbCtx := HTBCtx{}

	htbCtx.Conn = tcnl

	return &htbCtx, nil
}

func (c *HTBCtx) InitHTBIface(ifaces ...string) error {
	if len(ifaces) == 0 {
		return fmt.Errorf("no interface given")
	}

	if c.HTBIfaces == nil {
		c.HTBIfaces = make(map[int]HTBIface)
	}
	for _, iface := range ifaces {
		dev, err := net.InterfaceByName(iface)
		if err != nil {
			return err
		}

		var htbIface *HTBIface
		_, err = findRootQdisc(c.Conn, dev)
		if err != nil {
			if !errors.Is(err, ErrQdiscNotFound) {
				return err
			}
			htbIface, err = c.createQdisc(dev)
		} else {
			htbIface, err = c.getQdisc(dev)
		}

		if err != nil {
			return err
		}

		c.HTBIfaces[dev.Index] = *htbIface
	}

	return nil
}

func (c *HTBCtx) WithLogger(l *slog.Logger) {
	c.Logger = l
}

func (c *HTBCtx) InitHTBFilter(createIfNotExists bool) error {
	nftCtx, err := nft.NewNFTCtx(nft.NFTOpts{
		CreateIfNotExists: createIfNotExists,
		Logger:            c.Logger,
	})
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

func (c *HTBCtx) FlushQdisc(ifIndex int) error {
	c.Info("tc: delete_qdisc", "ifIndex", ifIndex)
	qdisc := c.HTBIfaces[ifIndex]
	if qdisc.Root == nil {
		return nil
	}
	return c.deleteQdisc(qdisc.Root)
}

func (c *HTBCtx) Close() error {
	return c.Conn.Close()
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

func FindHTBEnabledIfaces() ([]string, error) {
	devs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	htbEnabledIfaces := make([]string, 0, len(devs))
	for _, dev := range devs {
		htbEnabled, err := HasHTBQdisc(&dev)
		if err != nil {
			return nil, err
		}
		if htbEnabled {
			htbEnabledIfaces = append(htbEnabledIfaces, dev.Name)
		}
	}

	return htbEnabledIfaces, nil
}

func FlushQdisc(iface string) error {
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
		return err
	}

	htbCtx := HTBCtx{
		Conn: tcnl,
	}
	if qdisc != nil {
		err = htbCtx.deleteQdisc(qdisc)
		if err != nil {
			return err
		}
	}
	return nil
}
