package qos

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/kakeetopius/qosm/internal/core/nft"
	"github.com/kakeetopius/qosm/internal/db"
	"github.com/kakeetopius/qosm/internal/util"
)

type Rule struct {
	ID        int
	Target    string
	Type      string
	Priority  string
	CreatedAt time.Time
}

func (m *QoSManager) AddDomainRule(dbCon *sql.DB, domain string, priority string) (rule Rule, err error) {
	defer func() {
		if err != nil {
			db.AddErrorLog(dbCon, err, "")
		} else {
			addRuleSuccessLog(dbCon, domain, priority)
		}
	}()

	exists, err := db.CheckDomainRuleExists(dbCon, domain)
	if err != nil {
		return rule, err
	}
	if exists {
		return rule, fmt.Errorf("rule for %v already exists", domain)
	}

	_, err = netip.ParseAddr(domain)
	if err == nil {
		return Rule{}, fmt.Errorf("%v seems to be an IP address not a domain", domain)
	}

	util.Debug(m.Logger, "resolving_domain", "domain_name", domain)
	ips, err := net.LookupIP(domain)
	if err != nil {
		util.Debug(m.Logger, "resolve_error", "domain_name", domain, "error", err.Error())
		return Rule{}, err
	}

	db.AddLog(dbCon, db.Log{
		EventType:   "DNS",
		Description: "Resolved domain " + domain + " to " + ipSliceToString(ips),
	})

	addrs := util.NetIPtoNetIPPRefix(ips)

	util.Debug(m.Logger, "add_rule", "target", domain, "priority", priority)

	err = m.Classifier.AddTargetsToPriority(addrs, priority)
	if err != nil {
		return Rule{}, err
	}

	err = db.AddDomainToPriority(dbCon, domain, priority, addrs)
	if err != nil {
		return rule, err
	}

	domainRule, err := db.GetDomainRuleNameByWithoutIPs(dbCon, domain)
	if err != nil {
		return rule, err
	}

	return Rule{
		Type:      "domain",
		Priority:  domainRule.Priority,
		Target:    domainRule.DomainName,
		ID:        domainRule.ID,
		CreatedAt: domainRule.CreatedAt,
	}, nil
}

func (m *QoSManager) AddIPRule(dbCon *sql.DB, ip string, priority string) (rule Rule, err error) {
	defer func() {
		if err != nil {
			db.AddErrorLog(dbCon, err, "")
		} else {
			addRuleSuccessLog(dbCon, ip, priority)
		}
	}()

	addrs, err := util.TargetsFromString(ip)
	if err != nil {
		return Rule{}, fmt.Errorf("invalid IP address: %v", ip)
	}

	exists, err := db.CheckIPRuleExists(dbCon, addrs[0].String())
	if err != nil {
		return rule, err
	}
	if exists {
		return rule, fmt.Errorf("rule for %v already exists", ip)
	}

	util.Debug(m.Logger, "add_rule", "target", ip, "priority", priority)

	err = m.Classifier.AddTargetsToPriority(addrs, priority)
	if err != nil {
		return Rule{}, err
	}

	ipString := addrs[0].String()
	err = db.AddIPToPriority(dbCon, ipString, priority)
	if err != nil {
		return rule, err
	}

	ipRule, err := db.GetIPRuleByName(dbCon, ipString)
	if err != nil {
		return rule, err
	}

	return Rule{
		Type:      "ip",
		Priority:  ipRule.Priority,
		Target:    ipRule.IP,
		ID:        ipRule.ID,
		CreatedAt: ipRule.CreatedAt,
	}, nil
}

func (m *QoSManager) InitSavedRules(dbCon *sql.DB) error {
	ipRules, err := db.GetAllIPRules(dbCon)
	if err != nil {
		return err
	}

	for _, rule := range ipRules {
		ip, ipErr := netip.ParsePrefix(rule.IP)
		if ipErr != nil {
			return ipErr
		}
		ipErr = m.Classifier.AddTargetsToPriority([]netip.Prefix{ip}, rule.Priority)
		if ipErr != nil {
			return ipErr
		}
	}

	domainRules, err := db.GetAllDomainRules(dbCon)
	if err != nil {
		return err
	}

	for _, rule := range domainRules {
		ips, err := rule.IPsAsPrefix()
		if err != nil {
			return err
		}
		err = m.Classifier.AddTargetsToPriority(ips, rule.Priority)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *QoSManager) DeleteDomainRuleByID(dbConn *sql.DB, domainRuleID int) (err error) {
	domainRule, err := db.GetDomainRuleByID(dbConn, domainRuleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no rules to delete for domain with ID %v", domainRuleID)
		}
		return err
	}

	defer func() {
		if err != nil {
			db.AddErrorLog(dbConn, err, "")
		} else {
			addRuleDeletedLog(dbConn, domainRule.DomainName, domainRule.Priority)
		}
	}()

	err = db.DeleteDomainRuleByID(dbConn, domainRuleID, domainRule.Priority)
	if err != nil {
		return err
	}

	return m.deleteDomainAddrs(domainRule)
}

func (m *QoSManager) DeleteDomainRuleByName(dbConn *sql.DB, name string) error {
	domainRule, err := db.GetDomainRuleByName(dbConn, name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no rules to delete for domain %v", name)
		}
		return err
	}

	defer func() {
		if err != nil {
			db.AddErrorLog(dbConn, err, "")
		} else {
			addRuleDeletedLog(dbConn, domainRule.DomainName, domainRule.Priority)
		}
	}()

	err = db.DeleteDomainRuleByName(dbConn, name, domainRule.Priority)
	if err != nil {
		return err
	}

	return m.deleteDomainAddrs(domainRule)
}

func (m *QoSManager) DeleteIPRuleByID(dbConn *sql.DB, ipRuleID int) error {
	ipRule, err := db.GetIPRuleByID(dbConn, ipRuleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no rules to delete for IP rule with ID %v", ipRuleID)
		}
		return err
	}

	defer func() {
		if err != nil {
			db.AddErrorLog(dbConn, err, "")
		} else {
			addRuleDeletedLog(dbConn, ipRule.IP, ipRule.Priority)
		}
	}()

	err = db.DeleteIPRuleByID(dbConn, ipRuleID, ipRule.Priority)
	if err != nil {
		return err
	}

	addr, err := netip.ParsePrefix(ipRule.IP)
	if err != nil {
		return err
	}

	return m.Classifier.DeleteTargetsFromPriority([]netip.Prefix{addr}, ipRule.Priority)
}

func (m *QoSManager) DeleteIPRuleByName(dbConn *sql.DB, ipRuleName string) error {
	ipRule, err := db.GetIPRuleByName(dbConn, ipRuleName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no rules to delete for ip %v", ipRuleName)
		}
		return err
	}

	defer func() {
		if err != nil {
			db.AddErrorLog(dbConn, err, "")
		} else {
			addRuleDeletedLog(dbConn, ipRule.IP, ipRule.Priority)
		}
	}()

	err = db.DeleteIPRuleByName(dbConn, ipRuleName, ipRule.Priority)
	if err != nil {
		return err
	}

	addr, err := netip.ParsePrefix(ipRule.IP)
	if err != nil {
		return err
	}
	return m.Classifier.DeleteTargetsFromPriority([]netip.Prefix{addr}, ipRule.Priority)
}

func (m *QoSManager) DeleteAllRules(dbConn *sql.DB) error {
	var err error
	if m.Classifier != nil {
		err = m.Classifier.DeleteTable()
	} else {
		err = nft.DeleteTable()
	}

	if err != nil {
		if !errors.Is(err, nft.ErrTableNotFound) {
			return err
		}
	}

	err = db.FlushDomainRules(dbConn)
	if err != nil {
		return err
	}

	err = db.FlushIPRules(dbConn)
	if err != nil {
		return err
	}

	return nil
}

func (m *QoSManager) GetAllRules(dbCon *sql.DB) ([]Rule, error) {
	ipRules, err := db.GetAllIPRules(dbCon)
	if err != nil {
		return nil, err
	}
	domainRules, err := db.GetAllDomainRulesWithoutIPs(dbCon)
	if err != nil {
		return nil, err
	}

	return joinIPAndDomainRules(ipRules, domainRules), nil
}

func (m *QoSManager) GetHighPriority(dbCon *sql.DB) ([]Rule, error) {
	highPrioIPRules, err := db.GetHighPrioIPs(dbCon)
	if err != nil {
		return nil, err
	}
	highPrioDomainRules, err := db.GetHighPrioDomains(dbCon)
	if err != nil {
		return nil, err
	}

	return joinIPAndDomainRules(highPrioIPRules, highPrioDomainRules), nil
}

func (m *QoSManager) GetLowPriority(dbCon *sql.DB) ([]Rule, error) {
	lowPrioIPRules, err := db.GetLowPrioIPs(dbCon)
	if err != nil {
		return nil, err
	}
	lowPrioDomainRules, err := db.GetLowPrioDomains(dbCon)
	if err != nil {
		return nil, err
	}

	return joinIPAndDomainRules(lowPrioIPRules, lowPrioDomainRules), nil
}

func (m *QoSManager) deleteDomainAddrs(domainRule db.DomainRule) error {
	addrs := make([]netip.Prefix, 0, len(domainRule.IPs))
	for _, addr := range domainRule.IPs {
		ip, iperr := netip.ParsePrefix(addr.IP)
		if iperr != nil {
			return iperr
		}
		addrs = append(addrs, ip)
	}

	return m.Classifier.DeleteTargetsFromPriority(addrs, domainRule.Priority)
}
