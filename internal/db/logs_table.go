package db

import (
	"database/sql"
	"os"
	"os/user"
	"strings"
	"time"
)

type Log struct {
	EventType   string
	UserName    string
	Description string
	TimeStamp   time.Time
}

type LogStats struct {
	Errors   int
	Warnings int
	Info     int
}

func AddLog(db *sql.DB, log Log) error {
	if log.UserName == "" {
		uName, uerr := getUserName()
		if uerr != nil {
			return uerr
		}
		log.UserName = uName
	}
	_, err := db.Exec(
		`
    INSERT OR IGNORE INTO logs (
		event_type, user_name, description
    )
    VALUES (?, ?, ?)
`,
		strings.ToUpper(log.EventType),
		log.UserName,
		log.Description,
	)

	return err
}

func AddErrorLog(db *sql.DB, err error, userName string) error {
	return AddLog(db, Log{
		EventType:   "ERROR",
		UserName:    userName,
		Description: err.Error(),
	})
}

func GetLogsWithStats(db *sql.DB) ([]Log, LogStats, error) {
	logs, err := GetLogs(db)
	if err != nil {
		return nil, LogStats{}, err
	}

	stats := LogStats{}
	for _, log := range logs {
		switch log.EventType {
		case "ERROR":
			stats.Errors++
		case "WARNING":
			stats.Warnings++
		default:
			stats.Info++

		}
	}

	return logs, stats, err
}

func GetLogs(db *sql.DB) ([]Log, error) {
	stmt, err := db.Prepare(`
        SELECT  event_type, user_name, description, created_at
        FROM logs
		ORDER BY created_at DESC;
    `)
	if err != nil {
		return nil, err
	}

	return getLogs(stmt)
}

func GetErrorLogs(db *sql.DB) ([]Log, error) {
	return GetLogsOfEvent(db, "ERROR")
}

func GetInfoLogs(db *sql.DB) ([]Log, error) {
	return GetLogsOfEvent(db, "INFO")
}

func GetDNSLogs(db *sql.DB) ([]Log, error) {
	return GetLogsOfEvent(db, "DNS")
}

func GetLogsOfEvent(db *sql.DB, eventType string) ([]Log, error) {
	stmt, err := db.Prepare(`
        SELECT  event_type, user_name, description, created_at
        FROM logs
		WHERE event_type = ?
		ORDER BY created_at DESC;
    `)
	if err != nil {
		return nil, err
	}

	return getLogs(stmt, strings.ToUpper(eventType))
}

func GetLogsOfUser(db *sql.DB, userName string) ([]Log, error) {
	stmt, err := db.Prepare(`
        SELECT  event_type, user_name, description, created_at
        FROM logs
		WHERE user_name = ?
		ORDER BY created_at DESC;
    `)
	if err != nil {
		return nil, err
	}

	return getLogs(stmt, userName)
}

func DeleteAllLogs(db *sql.DB) error {
	_, err := db.Exec(`
	DELETE FROM logs
	`)

	return err
}

func DeleteLogsOfEvent(db *sql.DB, eventType string) error {
	_, err := db.Exec(`
	DELETE FROM logs
	WHERE event_type = ?
	`, eventType)

	return err
}

func DeleteLogsOfUser(db *sql.DB, username string) error {
	_, err := db.Exec(`
	DELETE FROM logs
	WHERE user_name = ?
	`, username)

	return err
}

func getLogs(query *sql.Stmt, args ...any) ([]Log, error) {
	var rows *sql.Rows
	var err error

	rows, err = query.Query(args...)
	if err != nil {
		return nil, err
	}

	logs := make([]Log, 0, 5)
	for rows.Next() {
		var l Log
		err = rows.Scan(
			&l.EventType,
			&l.UserName,
			&l.Description,
			&l.TimeStamp,
		)
		if err != nil {
			return nil, err
		}

		logs = append(logs, l)
	}

	return logs, nil
}

func getUserName() (string, error) {
	if os.Geteuid() == 0 {
		// running as root
		sudoUser := os.Getenv("SUDO_USER")
		if sudoUser != "" {
			return sudoUser, nil
		}
	}

	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Name, nil
}
