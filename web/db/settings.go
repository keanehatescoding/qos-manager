// Package db is used to interface with the db.
package db

import (
	"database/sql"
)

type Settings struct {
	QoSEnabled     bool   `form:"qos_enabled"`
	LoggingLevel   string `form:"logging_level"`
	MaxBandwidth   int    `form:"max_bandwidth"`
	Interface      string `form:"interface"`
	DNSOverride    bool   `form:"dns_override"`
	PrimaryDNS     string `form:"primary_dns"`
	SessionTimeout int    `form:"session_timeout"`
}

func LoadSettings(db *sql.DB) (*Settings, error) {
	exists, err := checkSettingsExists(db)
	if err != nil {
		return nil, err
	}

	if exists {
		return getSettingsRow(db)
	}

	defaultSettings := Settings{
		SessionTimeout: 5,
		LoggingLevel:   "Info",
		MaxBandwidth:   1000,
	}

	err = addSettingsRow(db, &defaultSettings)
	if err != nil {
		return nil, err
	}
	return &defaultSettings, nil
}

func UpdateSettings(db *sql.DB, s *Settings) error {
	_, err := db.Exec(
		`
    INSERT OR REPLACE INTO settings (
        id, qos_enabled, logging_level, max_bandwidth,
        interface, dns_override, primary_dns, session_timeout
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`,
		1,
		s.QoSEnabled,
		s.LoggingLevel,
		s.MaxBandwidth,
		s.Interface,
		s.DNSOverride,
		s.PrimaryDNS,
		s.SessionTimeout,
	)

	return err
}

func checkSettingsExists(db *sql.DB) (bool, error) {
	var exists bool

	err := db.QueryRow(`
        SELECT EXISTS(
            SELECT 1
            FROM settings
            WHERE id = 1
        )
    `).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func addSettingsRow(db *sql.DB, settings *Settings) error {
	_, err := db.Exec(
		`
    INSERT OR IGNORE INTO settings (
        id, qos_enabled, logging_level, max_bandwidth,
        interface, dns_override, primary_dns, session_timeout
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`,
		1,
		settings.QoSEnabled,
		settings.LoggingLevel,
		settings.MaxBandwidth,
		settings.Interface,
		settings.DNSOverride,
		settings.PrimaryDNS,
		settings.SessionTimeout,
	)

	return err
}

func getSettingsRow(db *sql.DB) (*Settings, error) {
	var (
		qosEnabled  int
		dnsOverride int
		s           Settings
	)

	row := db.QueryRow(`
        SELECT qos_enabled, logging_level, max_bandwidth,
               interface, dns_override, primary_dns,
               session_timeout
        FROM settings
        WHERE id = 1
    `)

	err := row.Scan(
		&qosEnabled,
		&s.LoggingLevel,
		&s.MaxBandwidth,
		&s.Interface,
		&dnsOverride,
		&s.PrimaryDNS,
		&s.SessionTimeout,
	)
	if err != nil {
		return nil, err
	}

	s.QoSEnabled = qosEnabled == 1
	s.DNSOverride = dnsOverride == 1

	return &s, nil
}
