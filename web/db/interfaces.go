package db

import (
	"net"

	"github.com/kakeetopius/qosm/internal/core/tc"
)

type Interface struct {
	Name    string
	Enabled bool
	HTBCtx  *tc.HTBCtx
}

func GetInterfaces() (map[string]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	ifaceMap := make(map[string]Interface)

	for _, iface := range ifaces {
		exists, err := tc.HasHTBQdisc(&iface)
		if err != nil {
			return nil, err
		}
		qosIface := Interface{
			Name:    iface.Name,
			Enabled: exists,
		}
		if exists {
			htb, err := tc.InitHTBQdisc(iface.Name)
			if err != nil {
				return nil, err
			}
			qosIface.HTBCtx = htb
		}
		ifaceMap[iface.Name] = qosIface
	}

	return ifaceMap, nil
}
