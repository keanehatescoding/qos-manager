package tc

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/florianl/go-tc"
	"github.com/kakeetopius/qosm/internal/core/filter"
)

// NewHTBCtx creates a new HTB (Hierarchical Token Bucket) qdisc context for the given interface.
// It initializes the traffic control qdisc and filter, creating a new one if it doesn't exist.
func NewHTBCtx(iface string) (*HTBCtx, error) {
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

	var htbCtx *HTBCtx
	_, err = findRootQdisc(tcnl, dev)
	if err != nil {
		if !errors.Is(err, ErrQdiscNotFound) {
			return nil, err
		}
		htbCtx, err = createQdisc(tcnl, dev)
	} else {
		htbCtx, err = getQdisc(tcnl, dev)
	}

	if err != nil {
		return nil, err
	}

	htbCtx.Conn = tcnl

	htbCtx.Filter, err = filter.NewNFTCtx()
	if err != nil {
		return nil, err
	}

	return htbCtx, nil
}

// AddRule adds a traffic rule for the given network prefixes with the specified priority level.
func (c *HTBCtx) AddRule(target []netip.Prefix, priority Priority) (err error) {
	switch priority {
	case PRIORITYHIGH:
		err = c.Filter.AddTargetsToHighPriority(target)
	case PRIORITYLOW:
		err = c.Filter.AddTargetsToLowPriority(target)
	default:
		return fmt.Errorf("unknown priority %v", priority)
	}
	if err != nil {
		return err
	}

	return nil
}

// Close closes the underlying traffic control connection.
func (c *HTBCtx) Close() error {
	return c.Conn.Close()
}

// FlushQdisc removes the qdisc and its associated filter rules.
func (c *HTBCtx) FlushQdisc() error {
	err := deleteQdisc(c.Conn, c.Root)
	if err != nil {
		return err
	}
	return c.Filter.DeleteTable()
}

// FlushQdisc removes the qdisc and filter rules for the given interface.
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
	return filter.DeleteTable()
}
