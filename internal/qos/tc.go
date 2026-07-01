package qos

import (
	"database/sql"
	"fmt"
	"net"

	"github.com/kakeetopius/qosm/internal/core/htb"
	"github.com/kakeetopius/qosm/internal/db"
)

func (m *QoSManager) EnableTcOnInterface(ifaceName string, dbConn *sql.DB) (err error) {
	if m.Ifaces == nil {
		m.Ifaces = make(map[string]Interface)
	}

	if m.Classifier == nil {
		return fmt.Errorf("nft classifier not intialised")
	}

	defer func() {
		if err != nil {
			db.AddErrorLog(dbConn, err, "")
		} else {
			addTCEnabledLog(dbConn, ifaceName)
		}
	}()

	iface, found := m.Ifaces[ifaceName]
	if !found {
		netIface, neterr := net.InterfaceByName(ifaceName)
		if neterr != nil {
			return neterr
		}
		iface.Interface = *netIface
	}
	if iface.Enabled {
		return nil
	}

	htbIface, err := htb.InitHTBOnIface(m.TcConn, iface.Interface, m.Logger)
	if err != nil {
		return err
	}

	err = m.Classifier.AddIfaceRules(iface.Index)
	if err != nil {
		return err
	}

	err = db.AddInterface(dbConn, db.DBInterface{
		Name:       iface.Name,
		IfaceIndex: iface.Index,
		Enabled:    true,
	})
	if err != nil {
		return err
	}

	iface.HTBIface = htbIface
	iface.Enabled = true
	m.Ifaces[iface.Name] = iface

	return nil
}

func (m *QoSManager) DisableTcOnInterface(ifaceName string, dbConn *sql.DB) (err error) {
	if m.Classifier == nil {
		return fmt.Errorf("nft classifier not intialised")
	}

	defer func() {
		if err != nil {
			db.AddErrorLog(dbConn, err, "")
		} else {
			addTCDisabledLog(dbConn, ifaceName)
		}
	}()

	iface, found := m.Ifaces[ifaceName]
	if !found {
		netIface, netErr := net.InterfaceByName(ifaceName)
		if netErr != nil {
			return netErr
		}
		iface = Interface{
			Interface: *netIface,
		}
	}

	if !iface.Enabled {
		return nil
	}

	err = htb.FlushQdiscFromIface(m.TcConn, iface.Index)
	if err != nil {
		return err
	}

	if m.Classifier != nil {
		err = m.Classifier.DeleteIfaceRules(iface.Index)
		if err != nil {
			return err
		}
	}

	err = db.DisableInterface(dbConn, iface.Name)
	if err != nil {
		return err
	}

	iface.Enabled = false
	m.Ifaces[ifaceName] = iface

	return nil
}

func (m *QoSManager) InitSavedInterfaceSettings(dbConn *sql.DB) error {
	if m.Classifier == nil {
		return fmt.Errorf("nft filter not intialised")
	}
	enabledIfaces, err := db.GetEnabledInterfaces(dbConn)
	if err != nil {
		return err
	}

	for _, iface := range enabledIfaces {
		err = m.EnableTcOnInterface(iface.Name, dbConn)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *QoSManager) EnabledInterfaces() []Interface {
	enabled := make([]Interface, 0, len(m.Ifaces))
	for _, iface := range m.Ifaces {
		if iface.Enabled {
			enabled = append(enabled, iface)
		}
	}

	return enabled
}
