package web

import (
	"database/sql"
	"log/slog"

	"github.com/kakeetopius/qosm/internal/core/tc"
)

type ServerCtx struct {
	db     sql.DB
	logger *slog.Logger
	htbctx tc.HTBCtx
}

type ServerOptions struct {
	Port   int
	DBPath string
}

type ServerError struct {
	StatusCode int
	Err        error
}

func (e ServerError) Error() string {
	return e.Err.Error()
}
