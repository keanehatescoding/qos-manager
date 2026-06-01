// Package web contains backend logic for http server.
package web

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/db"
	"github.com/kakeetopius/qosm/web/server"
	_ "modernc.org/sqlite"
)

//go:embed static
var staticFS embed.FS

type ServerOptions struct {
	Port            int
	Addr            string
	DBPath          string
	SessionsEncKey  string
	SessionsHashKey string
	Debug           bool
}

func Run(opts ServerOptions) error {
	router := gin.Default()

	renderer, err := createRenderer()
	if err != nil {
		return err
	}
	router.HTMLRender = renderer

	dbConn, err := db.NewConn(opts.DBPath)
	if err != nil {
		return err
	}

	settings, err := db.LoadSettings(dbConn)
	if err != nil {
		return err
	}

	var logOptions *slog.HandlerOptions
	if opts.Debug {
		logOptions = &slog.HandlerOptions{Level: slog.LevelDebug}
	}

	app := routes.ServerCtx{
		Logger:   slog.New(slog.NewJSONHandler(os.Stdout, logOptions)),
		DB:       dbConn,
		Settings: settings,
	}

	err = app.InitTcState()
	if err != nil {
		return err
	}

	app.SetUpSessionMiddleWare(router)
	app.AddRoutes(router)
	app.AddStaticRoutes(router, &staticFS)

	router.Run(getAddress(opts.Addr, opts.Port))
	return nil
}

func createRenderer() (multitemplate.Renderer, error) {
	tmplSubFS, err := fs.Sub(staticFS, "static/templates")
	if err != nil {
		return nil, err
	}

	commonTemplates := []string{"partials/meta.tmpl", "partials/sidebar.tmpl", "partials/topbar.tmpl"}
	pages := []string{"dashboard", "rules", "analytics", "logs", "settings"}

	r := multitemplate.NewRenderer()

	for _, page := range pages {
		files := append([]string{"layout/base.tmpl", "pages/" + page + ".tmpl"}, commonTemplates...)
		r.AddFromFS(page, tmplSubFS, files...)
	}

	r.AddFromFS("login", tmplSubFS, "pages/login.tmpl", "partials/meta.tmpl", "partials/fail.tmpl")
	r.AddFromFS("fail", tmplSubFS, "partials/fail.tmpl")
	r.AddFromFS("toast_success", tmplSubFS, "partials/toast_success.tmpl")
	r.AddFromFS("toast_error", tmplSubFS, "partials/toast_error.tmpl")
	r.AddFromFS("rule_table_row", tmplSubFS, "partials/rule_table_row.tmpl")
	return r, nil
}

func getAddress(addr string, port int) string {
	if addr == "" && port == 0 {
		return ":9000"
	}

	return fmt.Sprintf("%v:%v", addr, port)
}
