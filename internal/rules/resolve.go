package rules

import (
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"net/netip"

	"github.com/kakeetopius/qosm/internal/core/htb"
	"github.com/kakeetopius/qosm/internal/db"
	"github.com/kakeetopius/qosm/internal/util"
)

var ErrNoDomainIPs = errors.New("no domain ips to refresh")

func RefreshAllDomains(dbConn *sql.DB, htbCtx *htb.HTBCtx, logger *slog.Logger) error {
	domains, err := db.GetAllDomainRules(dbConn)
	if err != nil {
		return err
	}
	util.Debug(logger, "dns: refreshing domains in database")

	if len(domains) == 0 {
		return ErrNoDomainIPs
	}

	for _, domain := range domains {
		util.Debug(logger, "dns: refreshing domain ips", "domain_name", domain.DomainName)
		oldIPs, err := domain.IPsAsPrefix()
		if err != nil {
			return err
		}

		addrs, err := net.LookupIP(domain.DomainName)
		if err != nil {
			util.Error(logger, "resolve_error", "domain_name", domain.DomainName, "error", err.Error())
			return err
		}
		newIPs := util.NetIPtoNetIPPRefix(addrs)

		err = clearOldIPs(dbConn, htbCtx, &domain, oldIPs)
		if err != nil {
			return err
		}

		err = addNewIPs(dbConn, htbCtx, &domain, newIPs)
		if err != nil {
			return err
		}
	}

	return nil
}

func clearOldIPs(dbConn *sql.DB, htbCtx *htb.HTBCtx, domain *db.DomainRule, oldIPs []netip.Prefix) error {
	prio, err := htb.PriorityFromString(domain.Priority)
	if err != nil {
		return err
	}

	err = htbCtx.DelRule(oldIPs, prio)
	if err != nil {
		return err
	}

	err = db.DeleteDomainIPsByDomainID(dbConn, domain.ID)
	if err != nil {
		return err
	}

	return nil
}

func addNewIPs(dbConn *sql.DB, htbCtx *htb.HTBCtx, domain *db.DomainRule, newIPs []netip.Prefix) error {
	prio, err := htb.PriorityFromString(domain.Priority)
	if err != nil {
		return err
	}

	err = htbCtx.AddRule(newIPs, prio)
	if err != nil {
		return err
	}

	err = db.AddDomainIPstoDB(dbConn, domain.DomainName, newIPs)
	if err != nil {
		return err
	}

	return nil
}
