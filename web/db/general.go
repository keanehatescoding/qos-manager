package db

import "database/sql"

func Connect() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "./qos.db")
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func SetUp(db *sql.DB) error {
	schema := `
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY,
        qos_enabled BOOLEAN,
        logging_level TEXT DEFAULT 'Info',
        max_bandwidth INTEGER DEFAULT '1000',
        interface TEXT,
        dns_override BOOLEAN,
        primary_dns TEXT,
        session_timeout INTEGER DEFAULT 5
    );

    CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        priority INTEGER,
        enabled BOOLEAN
    );
    `

	_, err := db.Exec(schema)
	if err != nil {
		return err
	}

	return nil
}
