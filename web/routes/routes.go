// Package routes contains server's routes
package routes

import (
	"fmt"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/core/pam"
)

func (app *ServerCtx) LoginPost(ctx *gin.Context) {
	username := ctx.PostForm("username")
	password := ctx.PostForm("password")

	app.Logger.Info("login attempt", "username", username)

	if err := pam.AuthenticateUser(username, password); err != nil {
		app.Logger.Error("auth_failed", "username", username, "err", err)
		ctx.Error(ServerError{
			StatusCode: http.StatusOK,
			Err:        fmt.Errorf(" Invalid username or password"),
		})

		return
	}

	app.Logger.Info("auth_successful", "username", username)
	session := sessions.Default(ctx)
	session.Options(sessions.Options{
		MaxAge:   app.Settings.SessionTimeout * 60,
		HttpOnly: true, // Prevent JavaScript access
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	session.Set("username", username)
	session.Set("role", "administrator")
	session.Save()
	ctx.Header("HX-Redirect", "/dashboard")
	ctx.Status(http.StatusOK)
}

func (app *ServerCtx) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login", gin.H{
		"Title": "Login - QoS Manager",
	})
}

func (app *ServerCtx) DashboardPage(c *gin.Context) {
	session := sessions.Default(c)
	enabled := app.EnabledIfaces()

	c.HTML(http.StatusOK, "dashboard", gin.H{
		"Heading":     "Dashboard",
		"Description": "Overview of network traffic and QoS policies",
		"User":        session.Get("username"),
		"Role":        session.Get("role"),
		"Settings":    app.Settings,
		"Enabled":     len(enabled) > 0,
	})
}

func (app *ServerCtx) RulesPage(c *gin.Context) {
	session := sessions.Default(c)
	rules, err := getAllRules(app)
	if err != nil {
		c.Error(err)
		return
	}

	c.HTML(http.StatusOK, "rules", gin.H{
		"Heading":     "Rules",
		"Description": "Define how network traffic should be prioritized or limited",
		"User":        session.Get("username"),
		"Role":        session.Get("role"),
		"Rules":       rules,
	})
}

func (app *ServerCtx) AnalyticsPage(c *gin.Context) {
	session := sessions.Default(c)
	c.HTML(http.StatusOK, "analytics", gin.H{
		"Heading":     "Analytics",
		"Description": "Network usage insights and QoS effectiveness",
		"User":        session.Get("username"),
		"Role":        session.Get("role"),
	})
}

func (app *ServerCtx) LogsPage(c *gin.Context) {
	session := sessions.Default(c)
	c.HTML(http.StatusOK, "logs", gin.H{
		"Heading":     "Logs",
		"Description": "Real-time QoS engine and network activity logs",
		"User":        session.Get("username"),
		"Role":        session.Get("role"),
	})
}

func (app *ServerCtx) SettingsPage(c *gin.Context) {
	session := sessions.Default(c)
	c.HTML(http.StatusOK, "settings", gin.H{
		"Heading":     "Settings",
		"Description": "Configure QoS engine behavior and system preferences",
		"User":        session.Get("username"),
		"Role":        session.Get("role"),
		"Settings":    app.Settings,
		"Ifaces":      app.Ifaces,
	})
}

func (app *ServerCtx) Logout(c *gin.Context) {
	session := sessions.Default(c)

	session.Clear()
	session.Save()

	c.Redirect(http.StatusFound, "/login")
}
