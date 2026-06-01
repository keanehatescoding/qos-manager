package db

import "database/sql"

func Connect(dbpath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbpath)
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
        logging_level TEXT DEFAULT 'Info',
        max_bandwidth INTEGER DEFAULT '1000',
        dns_override BOOLEAN,
        primary_dns TEXT,
        session_timeout INTEGER DEFAULT 5
    );

	CREATE TABLE IF NOT EXISTS iprules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL UNIQUE,
		priority TEXT NOT NULL CHECK(priority IN ('high', 'low')),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS domainrules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain_name TEXT NOT NULL UNIQUE,
		priority TEXT NOT NULL CHECK(priority IN ('high', 'low')),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_resolved_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS domainips (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		domain_id INTEGER NOT NULL,

		UNIQUE(ip, domain_id),

		FOREIGN KEY (domain_id)
			REFERENCES domainrules(id)
			ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS interfaces (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		if_index INTEGER NOT NULL UNIQUE,
		name TEXT NOT NULL UNIQUE,
		enabled BOOLEAN NOT NULL
	);
    `

	_, err := db.Exec(schema)
	if err != nil {
		return err
	}

	return nil
}

func NewConn(dbpath string) (*sql.DB, error) {
	db, err := Connect(dbpath)
	if err != nil {
		return nil, err
	}
	err = SetUp(db)
	return db, err
}
