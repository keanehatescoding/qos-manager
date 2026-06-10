package qos

import (
	"database/sql"
	"fmt"
	"net"
	"strings"

	"github.com/kakeetopius/qosm/internal/db"
)

func addRuleSuccessLog(dbCon *sql.DB, target string, priority string) error {
	return db.AddLog(
		dbCon,
		db.Log{
			EventType:   "RULE",
			Description: fmt.Sprintf("added %s to %s priority", target, strings.ToUpper(priority)),
		},
	)
}

func addRuleDeletedLog(dbCon *sql.DB, target string, priority string) error {
	return db.AddLog(
		dbCon,
		db.Log{
			EventType:   "RULE",
			Description: fmt.Sprintf("deleted %s prioriy rule to %s", strings.ToUpper(priority), target),
		},
	)
}

func addTCEnabledLog(dbCon *sql.DB, iface string) error {
	return db.AddLog(
		dbCon,
		db.Log{
			EventType:   "TC",
			Description: fmt.Sprintf("enabled traffic control on interface %s", iface),
		},
	)
}

func addTCDisabledLog(dbCon *sql.DB, iface string) error {
	return db.AddLog(
		dbCon,
		db.Log{
			EventType:   "TC",
			Description: fmt.Sprintf("disabled traffic control on interface %s", iface),
		},
	)
}

func ipSliceToString(ips []net.IP) string {
	if len(ips) == 0 {
		return ""
	}

	stringBuilder := strings.Builder{}
	for i, ip := range ips {
		stringBuilder.WriteString(ip.String())
		if i != len(ips)-1 {
			stringBuilder.WriteString(", ")
		}
	}

	return stringBuilder.String()
}

func joinIPAndDomainRules(ipRules []db.IPRule, domainRules []db.DomainRule) []Rule {
	allRules := make([]Rule, 0, len(ipRules)+len(domainRules))
	for _, rule := range ipRules {
		allRules = append(allRules, Rule{
			ID:        rule.ID,
			Priority:  rule.Priority,
			Target:    rule.IP,
			Type:      "ip",
			CreatedAt: rule.CreatedAt,
		})
	}

	for _, rule := range domainRules {
		allRules = append(allRules, Rule{
			ID:        rule.ID,
			Priority:  rule.Priority,
			Target:    rule.DomainName,
			Type:      "domain",
			CreatedAt: rule.CreatedAt,
		})
	}

	return allRules
}
