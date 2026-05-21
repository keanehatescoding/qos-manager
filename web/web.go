// Package web contains backend logic for http server.
package web

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
)

//go:embed templates
var tmplFs embed.FS

//go:embed static
var staticFS embed.FS

func Run() error {
	router := gin.Default()

	renderer, err := createRenderer()
	if err != nil {
		return err
	}
	router.HTMLRender = renderer

	embedFiles(router)

	app := ServerCtx{
		logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	}
	addRoutes(router, &app)

	router.Run()
	return nil
}

func addRoutes(router *gin.Engine, app *ServerCtx) {
	router.Use(ErrorHandlerHTML())

	router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "hello from qosm")
	})

	router.GET("/login", app.login)
	router.POST("/login", app.loginPost)
	router.GET("/dashboard", app.dashboard)
	router.GET("/rules", app.rules)
	router.GET("/analytics", app.analytics)
	router.GET("/logs", app.logs)
	router.GET("/settings", app.settings)
	router.GET("/logout", app.logout)

	router.GET("/", app.dashboard)
}

func embedFiles(router *gin.Engine) error {
	staticSubFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}
	router.StaticFS("/static", http.FS(staticSubFS))

	return nil
}

func createRenderer() (multitemplate.Renderer, error) {
	tmplSubFS, err := fs.Sub(tmplFs, "templates")
	if err != nil {
		return nil, err
	}

	commonTemplates := []string{"partials/meta.tmpl", "partials/sidebar.tmpl", "partials/topbar.tmpl", "partials/fail.tmpl"}
	pages := []string{"dashboard", "rules", "analytics", "logs", "settings"}

	r := multitemplate.NewRenderer()

	for _, page := range pages {
		files := append([]string{"layout/base.tmpl", "pages/" + page + ".tmpl"}, commonTemplates...)
		r.AddFromFS(page, tmplSubFS, files...)
	}

	r.AddFromFS("login", tmplSubFS, "pages/login.tmpl", "partials/meta.tmpl", "partials/fail.tmpl")

	r.AddFromFS("fail", tmplSubFS, "partials/fail.tmpl")
	return r, nil
}
