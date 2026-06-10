package qos

import (
	"database/sql"
	"fmt"
	"net"

	"github.com/kakeetopius/qosm/internal/core/htb"
	"github.com/kakeetopius/qosm/internal/db"
)

func (m *QoSManager) EnableTcOnInterface(iface net.Interface, dbConn *sql.DB) (err error) {
	defer func() {
		if err != nil {
			db.AddErrorLog(dbConn, err, "")
		} else {
			addTCEnabledLog(dbConn, iface.Name)
		}
	}()

	htbIface, err := htb.InitHTBOnIface(m.TcConn, iface, m.Logger)
	if err != nil {
		return err
	}
	if m.HTBIfaces == nil {
		m.HTBIfaces = make(map[int]htb.HTBIface)
	}
	m.HTBIfaces[iface.Index] = htbIface

	if m.Classifier == nil {
		return fmt.Errorf("nft classifier not intialised")
	}

	err = m.Classifier.AddIfaceRules(iface.Index)
	if err != nil {
		return err
	}

	err = db.AddInterface(dbConn, db.Interface{
		Name:       iface.Name,
		IfaceIndex: iface.Index,
		Enabled:    true,
	})
	if err != nil {
		return err
	}

	return nil
}

func (m *QoSManager) DisableTcOnInterface(iface net.Interface, dbConn *sql.DB) (err error) {
	defer func() {
		if err != nil {
			db.AddErrorLog(dbConn, err, "")
		} else {
			addTCDisabledLog(dbConn, iface.Name)
		}
	}()

	if m.Classifier == nil {
		return fmt.Errorf("nft classifier not intialised")
	}
	err = htb.FlushQdiscFromIface(m.TcConn, iface.Index)
	if err != nil {
		return err
	}
	delete(m.HTBIfaces, iface.Index)

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

	return nil
}

func (m *QoSManager) InitSavedInterfaceSettings(dbConn *sql.DB) error {
	if m.Classifier == nil {
		return fmt.Errorf("nft filter not intialised")
	}
	enableIfaces, err := db.GetEnabledInterfaces(dbConn)
	if err != nil {
		return err
	}

	for _, iface := range enableIfaces {
		dev, err := net.InterfaceByName(iface.Name)
		if err != nil {
			return err
		}

		if m.HTBIfaces == nil {
			m.HTBIfaces = make(map[int]htb.HTBIface)
		}
		htbIface, err := htb.InitHTBOnIface(m.TcConn, *dev, m.Logger)
		if err != nil {
			return err
		}
		m.HTBIfaces[dev.Index] = htbIface

		err = m.Classifier.AddIfaceRules(iface.IfaceIndex)
		if err != nil {
			return err
		}
	}

	return nil
}
