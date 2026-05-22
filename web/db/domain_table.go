package db

import (
	"database/sql"
	"fmt"
	"net/netip"
	"time"
)

type DomainRule struct {
	ID             int
	DomainName     string
	Priority       string
	CreatedAt      time.Time
	LastResolvedAt time.Time
	IPs            []DomainIP
}

type DomainIP struct {
	ID       int
	IP       string
	DomainID int
}

func CheckDomainRuleExists(db *sql.DB, domain string) (bool, error) {
	var exists bool

	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM domainrules WHERE domain_name = ?
		)
	`, domain).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func GetHighPrioDomains(db *sql.DB) ([]DomainRule, error) {
	return getDomainsOfPriority(db, "high")
}

func GetLowPrioDomains(db *sql.DB) ([]DomainRule, error) {
	return getDomainsOfPriority(db, "low")
}

func AddDomainToPriority(db *sql.DB, domainName string, priority string, ips []netip.Prefix) error {
	if priority != "high" && priority != "low" {
		return fmt.Errorf("unknown priority: %v", priority)
	}

	err := addDomainRuleRow(db, DomainRule{DomainName: domainName, Priority: priority})
	if err != nil {
		return err
	}

	return AddDomainIPstoDB(db, domainName, ips)
}

func AddDomainToHighPriority(db *sql.DB, domainName string, ips []netip.Prefix) error {
	err := addDomainRuleRow(db, DomainRule{DomainName: domainName, Priority: "high"})
	if err != nil {
		return err
	}

	return AddDomainIPstoDB(db, domainName, ips)
}

func AddDomainToLowPriority(db *sql.DB, domainName string, ips []netip.Prefix) error {
	err := addDomainRuleRow(db, DomainRule{DomainName: domainName, Priority: "low"})
	if err != nil {
		return err
	}

	return AddDomainIPstoDB(db, domainName, ips)
}

func AddDomainIPstoDB(db *sql.DB, domainName string, ips []netip.Prefix) error {
	domainRule, err := GetDomainRuleByName(db, domainName)
	if err != nil {
		return err
	}
	ipRow := DomainIP{DomainID: domainRule.ID}

	for _, ip := range ips {
		ipRow.IP = ip.String()
		err = addDomainIPRow(db, ipRow)
		if err != nil {
			return err
		}
	}

	return nil
}

func GetAllDomainRulesWithoutIPs(db *sql.DB) ([]DomainRule, error) {
	rows, err := db.Query(`
		SELECT id, domain_name, priority, created_at, last_resolved_at
		FROM domainrules
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []DomainRule

	var rule DomainRule
	for rows.Next() {
		err = rows.Scan(&rule.ID, &rule.DomainName, &rule.Priority, &rule.CreatedAt, &rule.LastResolvedAt)
		if err != nil {
			return nil, err
		}

		rules = append(rules, rule)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return rules, err
}

func GetAllDomainRules(db *sql.DB) ([]DomainRule, error) {
	rules, err := GetAllDomainRulesWithoutIPs(db)
	if err != nil {
		return nil, err
	}
	err = addDomainIPsToResult(db, rules)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

func GetDomainRuleNameByWithoutIPs(db *sql.DB, name string) (DomainRule, error) {
	row := db.QueryRow(`
		SELECT id, domain_name, priority, created_at, last_resolved_at
		FROM domainrules
		WHERE domain_name = ?
	`, name)

	var rule DomainRule
	err := row.Scan(&rule.ID, &rule.DomainName, &rule.Priority, &rule.CreatedAt, &rule.LastResolvedAt)
	if err != nil {
		return DomainRule{}, err
	}

	return rule, nil
}

func GetDomainRuleByName(db *sql.DB, name string) (DomainRule, error) {
	rule, err := GetDomainRuleNameByWithoutIPs(db, name)
	if err != nil {
		return DomainRule{}, err
	}
	err = addDomainIPsToResult(db, []DomainRule{rule})

	return rule, err
}

func DeleteDomainRuleByID(db *sql.DB, id int) error {
	_, err := db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		DELETE FROM domainrules
		WHERE id = ?
	`, id)

	return err
}

func DeleteDomainRuleByName(db *sql.DB, name string) error {
	_, err := db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		return err
	}
	_, err = db.Exec(`
		DELETE FROM domainrules
		WHERE domain_name = ?
	`, name)

	return err
}

func getDomainsOfPriority(db *sql.DB, priority string) ([]DomainRule, error) {
	rows, err := db.Query(`
		SELECT id, domain_name, priority, created_at, last_resolved_at
		FROM domainrules
		WHERE priority = ?
	`, priority)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []DomainRule
	for rows.Next() {
		var rule DomainRule
		err = rows.Scan(&rule.ID, &rule.DomainName, &rule.Priority, &rule.CreatedAt, &rule.LastResolvedAt)
		if err != nil {
			return nil, err
		}

		rules = append(rules, rule)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	err = addDomainIPsToResult(db, rules)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

func addDomainIPsToResult(db *sql.DB, rules []DomainRule) error {
	stmt, err := db.Prepare(`
	SELECT id, ip, domain_id 
	FROM domainips
	WHERE domain_id = ?
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rules {
		ips, err := getDomainIPs(stmt, rules[i].ID)
		if err != nil {
			return err
		}
		rules[i].IPs = ips
	}
	return nil
}

func getDomainIPs(stmt *sql.Stmt, domainID int) ([]DomainIP, error) {
	rows, err := stmt.Query(domainID)
	if err != nil {
		return nil, err
	}

	var ips []DomainIP

	for rows.Next() {
		var ip DomainIP
		err = rows.Scan(&ip.ID, &ip.IP, &ip.DomainID)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

func addDomainRuleRow(db *sql.DB, row DomainRule) error {
	_, err := db.Exec(
		`
		INSERT OR IGNORE INTO domainrules (
			domain_name,
			priority
		)
		VALUES (?, ?)
	`,
		row.DomainName,
		row.Priority,
	)

	return err
}

func addDomainIPRow(db *sql.DB, row DomainIP) error {
	_, err := db.Exec(
		`
		INSERT OR IGNORE INTO domainips (
			ip,
			domain_id
		)
		VALUES (?, ?)
	`,
		row.IP,
		row.DomainID,
	)

	return err
}
