package htb

import (
	"errors"
	"log/slog"
	"net"

	"github.com/florianl/go-tc"
)

func InitHTBOnIface(tcnl *tc.Tc, iface net.Interface, logger *slog.Logger) (HTBIface, error) {
	var htbIface HTBIface
	_, err := findRootQdisc(tcnl, iface.Index)
	if err != nil {
		if !errors.Is(err, ErrQdiscNotFound) {
			return htbIface, err
		}
		htbIface, err = createQdisc(tcnl, &iface, logger)
	} else {
		htbIface, err = getQdisc(tcnl, &iface, logger)
	}

	if err != nil {
		return htbIface, err
	}

	return htbIface, nil
}

func FlushQdiscFromIface(tcnl *tc.Tc, ifIndex int) error {
	root, err := findRootQdisc(tcnl, ifIndex)
	if err != nil {
		return err
	}
	return deleteQdisc(tcnl, root)
}

func (c *HTBCtx) Close() error {
	return c.Conn.Close()
}

func HasHTBQdisc(iface *net.Interface) (bool, error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return false, err
	}

	_, err = findRootQdisc(tcnl, iface.Index)
	if err != nil {
		if errors.Is(err, ErrQdiscNotFound) {
			return false, nil
		}
		return false, err
	} else {
		return true, nil
	}
}

func FindHTBEnabledIfaces() ([]net.Interface, error) {
	devs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	htbEnabledIfaces := make([]net.Interface, 0, len(devs))
	for _, dev := range devs {
		htbEnabled, err := HasHTBQdisc(&dev)
		if err != nil {
			return nil, err
		}
		if htbEnabled {
			htbEnabledIfaces = append(htbEnabledIfaces, dev)
		}
	}

	return htbEnabledIfaces, nil
}
