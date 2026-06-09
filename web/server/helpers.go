package routes

import (
	"database/sql"
	"embed"
	"io/fs"
	"log/slog"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/core/htb"
	"github.com/kakeetopius/qosm/internal/db"
	"github.com/kakeetopius/qosm/internal/rules"
	"github.com/kakeetopius/qosm/internal/tc"
)

type Interface struct {
	net.Interface
	Enabled bool
}

type ServerCtx struct {
	DB       *sql.DB
	Logger   *slog.Logger
	Ifaces   map[string]Interface
	HTBCtx   *htb.HTBCtx
	Settings *db.Settings
}

type ServerError struct {
	StatusCode int
	Err        error
}

func (e ServerError) Error() string {
	return e.Err.Error()
}

func (app *ServerCtx) EnabledIfaces() []Interface {
	ifaces := make([]Interface, 0, 5)

	for _, iface := range app.Ifaces {
		if !iface.Enabled {
			continue
		}
		ifaces = append(ifaces, iface)
	}

	return ifaces
}

func (app *ServerCtx) InitTcState() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	allIfaces := make(map[string]Interface, len(ifaces))
	for _, iface := range ifaces {
		enabled, dbErr := db.InterfaceIsEnabled(app.DB, iface.Name)
		if dbErr != nil {
			return dbErr
		}
		allIfaces[iface.Name] = Interface{
			Interface: iface,
			Enabled:   enabled,
		}
	}

	htbCtx, err := htb.NewHTBCtx()
	if err != nil {
		return err
	}
	htbCtx.WithLogger(app.Logger)

	err = htbCtx.InitHTBFilter(true)
	if err != nil {
		return err
	}
	app.HTBCtx = htbCtx
	app.Ifaces = allIfaces

	err = rules.InitSavedRules(app.DB, app.HTBCtx, app.Logger)
	if err != nil {
		return err
	}

	err = tc.InitSavedInterfaceSettings(app.DB, htbCtx)
	if err != nil {
		return err
	}

	return nil
}

func (app *ServerCtx) AddRoutes(router *gin.Engine) {
	router.Use(ErrorHandlerHTML())

	auth := router.Group("/")
	auth.GET("/login", app.LoginPage)
	auth.POST("/login", app.LoginPost)

	admin := router.Group("/", AuthRequired(app), ErrorHandlerToast(app))
	admin.GET("/dashboard", app.DashboardPage)
	admin.GET("/rules", app.RulesPage)
	admin.GET("/analytics", app.AnalyticsPage)
	admin.GET("/logs", app.LogsPage)
	admin.GET("/logs/filter", app.LogsFilter)
	admin.DELETE("/logs/delete", app.LogsDelete)

	admin.GET("/settings", app.SettingsPage)
	admin.POST("/settings/system/save", app.PostSystemSettings)
	admin.POST("/settings/interface/save", app.PostInterfaceSettings)
	admin.POST("/settings/dns/save", app.PostDNSSettings)
	admin.POST("/settings/security/save", app.PostSecuritySettings)

	admin.POST("/rules/create", app.PostRules)
	admin.DELETE("/rules/:type/:id", app.DeleteRule)

	admin.GET("/logout", app.Logout)
	admin.GET("/", app.DashboardPage)
}

func (app *ServerCtx) AddStaticRoutes(router *gin.Engine, staticFS *embed.FS) error {
	staticSubFS, err := fs.Sub(staticFS, "static/js")
	if err != nil {
		return err
	}
	router.StaticFS("/static/js", http.FS(staticSubFS))

	staticSubFS, err = fs.Sub(staticFS, "static/css")
	if err != nil {
		return err
	}
	router.StaticFS("/static/css", http.FS(staticSubFS))

	staticSubFS, err = fs.Sub(staticFS, "static/pictures")
	if err != nil {
		return err
	}
	router.StaticFS("/static/pictures", http.FS(staticSubFS))

	return nil
}
