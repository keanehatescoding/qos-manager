// Package web contains backend logic for http server.
package web

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-contrib/multitemplate"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/web/db"
	"github.com/kakeetopius/qosm/web/routes"
	_ "modernc.org/sqlite"
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

	setUpSessionMgmt(router)

	addEmbededFiles(router)

	dbConn, err := db.Connect()
	if err != nil {
		return err
	}
	err = db.SetUp(dbConn)
	if err != nil {
		return err
	}

	app := routes.ServerCtx{
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		DB:     dbConn,
	}

	settings, err := db.LoadSettings(dbConn)
	if err != nil {
		return err
	}
	app.ApplySettings(settings)

	addRoutes(router, &app)

	router.Run()
	return nil
}

func setUpSessionMgmt(router *gin.Engine) {
	store := cookie.NewStore([]byte("cookie-key"))

	router.Use(sessions.Sessions("qosm-session", store))
}

func addRoutes(router *gin.Engine, app *routes.ServerCtx) {
	router.Use(ErrorHandlerHTML())

	router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "hello from qosm")
	})

	auth := router.Group("/")
	auth.GET("/login", app.Login)
	auth.POST("/login", app.LoginPost)

	admin := router.Group("/", AuthRequired())
	admin.GET("/dashboard", app.Dashboard)
	admin.GET("/rules", app.Rules)
	admin.GET("/analytics", app.Analytics)
	admin.GET("/logs", app.Logs)
	admin.GET("/settings", app.SettingsPage)
	admin.POST("/settings/save", app.SaveSettings)
	admin.GET("/logout", app.Logout)
	admin.GET("/", app.Dashboard)
}

func addEmbededFiles(router *gin.Engine) error {
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
