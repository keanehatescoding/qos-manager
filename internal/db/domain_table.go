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

func (r DomainRule) IPsAsPrefix() ([]netip.Prefix, error) {
	addrs := make([]netip.Prefix, 0, len(r.IPs))

	for _, ip := range r.IPs {
		addr, err := netip.ParsePrefix(ip.IP)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}

	return addrs, nil
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

func GetAllDomainRules(db *sql.DB) ([]DomainRule, error) {
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

		err = addDomainIPs(db, &rule)
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

func GetDomainRuleByName(db *sql.DB, name string) (DomainRule, error) {
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
	err = addDomainIPs(db, &rule)
	if err != nil {
		return DomainRule{}, err
	}

	return rule, nil
}

func GetDomainRuleByID(db *sql.DB, id int) (DomainRule, error) {
	row := db.QueryRow(`
		SELECT id, domain_name, priority, created_at, last_resolved_at
		FROM domainrules
		WHERE id = ?
	`, id)

	var rule DomainRule
	err := row.Scan(&rule.ID, &rule.DomainName, &rule.Priority, &rule.CreatedAt, &rule.LastResolvedAt)
	if err != nil {
		return DomainRule{}, err
	}

	err = addDomainIPs(db, &rule)
	return rule, err
}

func DeleteDomainRuleByID(db *sql.DB, id int, priority string) error {
	_, err := db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		DELETE FROM domainrules
		WHERE id = ?
			AND priority = ?
	`, id, priority)

	return err
}

func DeleteDomainRuleByName(db *sql.DB, name string, priority string) error {
	_, err := db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		return err
	}
	_, err = db.Exec(`
		DELETE FROM domainrules
		WHERE domain_name = ?
			AND priority = ?
	`, name, priority)

	return err
}

func DeleteDomainIPsByDomainID(db *sql.DB, id int) error {
	_, err := db.Exec(`
		DELETE FROM domainips
		WHERE domain_id = ?
	`, id)

	return err
}

func FlushDomainRules(db *sql.DB) error {
	_, err := db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		return err
	}
	_, err = db.Exec(`
		DELETE FROM domainrules
	`)

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

		err = addDomainIPs(db, &rule)
		if err != nil {
			return nil, err
		}

		rules = append(rules, rule)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

func addDomainIPs(db *sql.DB, rule *DomainRule) error {
	stmt, err := db.Prepare(`
	SELECT id, ip, domain_id 
	FROM domainips
	WHERE domain_id = ?
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	rows, err := stmt.Query(rule.ID)
	if err != nil {
		return err
	}

	var ips []DomainIP
	for rows.Next() {
		var ip DomainIP
		err = rows.Scan(&ip.ID, &ip.IP, &ip.DomainID)
		if err != nil {
			return err
		}
		ips = append(ips, ip)
	}

	if err = rows.Err(); err != nil {
		return err
	}

	rule.IPs = ips
	return nil
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
