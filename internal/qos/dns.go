package qos

import (
	"database/sql"
	"errors"
	"net"
	"net/netip"

	"github.com/kakeetopius/qosm/internal/db"
	"github.com/kakeetopius/qosm/internal/util"
)

var ErrNoDomainIPs = errors.New("no domain ips to refresh")

func (m *QoSManager) RefreshAllDomains(dbConn *sql.DB) error {
	domains, err := db.GetAllDomainRules(dbConn)
	if err != nil {
		return err
	}
	util.Debug(m.Logger, "dns: refreshing domains in database")

	if len(domains) == 0 {
		return ErrNoDomainIPs
	}

	for _, domain := range domains {
		util.Debug(m.Logger, "dns: refreshing domain ips", "domain_name", domain.DomainName)
		oldIPs, err := domain.IPsAsPrefix()
		if err != nil {
			return err
		}

		addrs, err := net.LookupIP(domain.DomainName)
		if err != nil {
			util.Error(m.Logger, "resolve_error", "domain_name", domain.DomainName, "error", err.Error())
			return err
		}
		newIPs := util.NetIPtoNetIPPRefix(addrs)

		err = m.clearOldIPs(dbConn, &domain, oldIPs)
		if err != nil {
			return err
		}

		err = m.addNewIPs(dbConn, &domain, newIPs)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *QoSManager) clearOldIPs(dbConn *sql.DB, domain *db.DomainRule, oldIPs []netip.Prefix) error {
	err := m.Classifier.DeleteTargetsFromPriority(oldIPs, domain.Priority)
	if err != nil {
		return err
	}

	err = db.DeleteDomainIPsByDomainID(dbConn, domain.ID)
	if err != nil {
		return err
	}

	return nil
}

func (m *QoSManager) addNewIPs(dbConn *sql.DB, domain *db.DomainRule, newIPs []netip.Prefix) error {
	err := m.Classifier.AddTargetsToPriority(newIPs, domain.Priority)
	if err != nil {
		return err
	}

	err = db.AddDomainIPstoDB(dbConn, domain.DomainName, newIPs)
	if err != nil {
		return err
	}

	return nil
}
