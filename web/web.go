// Package web contains backend logic for http server.
package web

import (
	"embed"
	"fmt"
	"html/template"
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
	SessionsAuthKey string
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

	app := server.Server{
		Logger:   slog.New(slog.NewJSONHandler(os.Stdout, logOptions)),
		DB:       dbConn,
		Settings: settings,
	}

	err = app.Init()
	if err != nil {
		return err
	}

	err = app.SetUpSessionMiddleWare(router, opts.SessionsAuthKey, opts.SessionsEncKey)
	if err != nil {
		return err
	}
	app.AddRoutes(router)
	app.AddStaticRoutes(router, &staticFS)

	router.Run(getAddress(opts.Addr, opts.Port))
	return nil
}

func createRenderer() (multitemplate.Renderer, error) {
	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}

	tmplSubFS, err := fs.Sub(staticFS, "static/templates")
	if err != nil {
		return nil, err
	}

	commonTemplates := []string{"partials/meta.tmpl", "partials/sidebar.tmpl", "partials/topbar.tmpl"}
	pages := []string{"dashboard", "rules", "analytics", "logs", "settings"}

	r := multitemplate.NewRenderer()

	for _, page := range pages {
		files := append([]string{"layout/base.tmpl", "pages/" + page + ".tmpl"}, commonTemplates...)
		if page == "logs" {
			files = append(files, "partials/logs_view.tmpl")
		}
		r.AddFromFSFuncs(page, funcMap, tmplSubFS, files...)
	}

	r.AddFromFSFuncs("login", funcMap, tmplSubFS, "pages/login.tmpl", "partials/meta.tmpl", "partials/fail.tmpl")
	r.AddFromFSFuncs("fail", funcMap, tmplSubFS, "partials/fail.tmpl")
	r.AddFromFSFuncs("toast_success", funcMap, tmplSubFS, "partials/toast_success.tmpl")
	r.AddFromFSFuncs("toast_error", funcMap, tmplSubFS, "partials/toast_error.tmpl")
	r.AddFromFSFuncs("rule_table_row", funcMap, tmplSubFS, "partials/rule_table_row.tmpl")
	r.AddFromFSFuncs("logs_view", funcMap, tmplSubFS, "partials/logs_view.tmpl")
	return r, nil
}

func getAddress(addr string, port int) string {
	if addr == "" && port == 0 {
		return ":9000"
	}

	return fmt.Sprintf("%v:%v", addr, port)
}
