// Package routes contains server's routes
package routes

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/core/pam"
	"github.com/kakeetopius/qosm/internal/db"
	"github.com/kakeetopius/qosm/internal/qos"
)

type DashBoardStats struct {
	HighPrioTargets int
	LowPrioTargets  int
	TotalTargets    int
	TotalDomains    int
	TotalIPs        int
}

func (app *ServerCtx) LoginPost(ctx *gin.Context) {
	username := ctx.PostForm("username")
	password := ctx.PostForm("password")

	db.AddLog(app.DB, db.Log{
		EventType:   "INFO",
		Description: "login attempt for " + username,
	})

	if err := pam.AuthenticateUser(username, password); err != nil {
		db.AddErrorLog(app.DB, err, "")

		ctx.Error(ServerError{
			StatusCode: http.StatusOK,
			Err:        fmt.Errorf(" Invalid username or password"),
		})

		return
	}

	db.AddLog(app.DB, db.Log{
		EventType:   "INFO",
		Description: "login successfull for " + username,
	})
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

	allRules, err := app.QoSManager.GetAllRules(app.DB)
	if err != nil {
		c.Error(err)
		return
	}
	slices.SortFunc(allRules, func(a, b qos.Rule) int {
		return -a.CreatedAt.Compare(b.CreatedAt)
	})

	rulesToDisplay := allRules
	if len(allRules) > 5 {
		rulesToDisplay = allRules[:5]
	}

	c.HTML(http.StatusOK, "dashboard", gin.H{
		"Title":       "DashBoard - QoS Manager",
		"Heading":     "Dashboard",
		"Description": "Overview of network traffic and QoS policies",
		"User":        session.Get("username"),
		"Role":        session.Get("role"),
		"Enabled":     len(enabled) > 0,
		"Rules":       rulesToDisplay,
		"Stats":       dashBoardStats(allRules),
		"Ifaces":      app.Ifaces,
	})
}

func dashBoardStats(rules []qos.Rule) DashBoardStats {
	stats := DashBoardStats{}

	for _, rule := range rules {
		switch rule.Type {
		case "domain":
			stats.TotalDomains++
		case "ip":
			stats.TotalIPs++
		}

		switch rule.Priority {
		case "high":
			stats.HighPrioTargets++
		case "low":
			stats.LowPrioTargets++
		}
	}

	stats.TotalTargets = len(rules)

	return stats
}

func (app *ServerCtx) RulesPage(c *gin.Context) {
	session := sessions.Default(c)
	rules, err := app.QoSManager.GetAllRules(app.DB)
	if err != nil {
		c.Error(err)
		return
	}

	c.HTML(http.StatusOK, "rules", gin.H{
		"Title":       "Rules - QoS Manager",
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
		"Title":       "Analytics - QoS Manager",
		"Heading":     "Analytics",
		"Description": "Network usage insights and QoS effectiveness",
		"User":        session.Get("username"),
		"Role":        session.Get("role"),
	})
}

func (app *ServerCtx) SettingsPage(c *gin.Context) {
	session := sessions.Default(c)
	c.HTML(http.StatusOK, "settings", gin.H{
		"Title":       "Settings - QoS Manager",
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
	username := session.Get("username").(string)

	session.Clear()
	session.Save()

	db.AddLog(app.DB, db.Log{
		EventType:   "INFO",
		Description: "logout for user " + username,
	})
	c.Redirect(http.StatusFound, "/login")
}

func (app *ServerCtx) LogsPage(c *gin.Context) {
	session := sessions.Default(c)
	logs, stats, err := db.GetLogsWithStats(app.DB)
	if err != nil {
		c.Error(err)
		return
	}
	c.HTML(http.StatusOK, "logs", gin.H{
		"Title":       "Logs - QoS Manager",
		"Heading":     "Logs",
		"Description": "Real-time QoS engine and network activity logs",
		"User":        session.Get("username"),
		"Role":        session.Get("role"),
		"Logs":        logs,
		"Stats":       stats,
	})
}

func (app *ServerCtx) LogsFilter(c *gin.Context) {
	filter := c.Query("event_filter")
	if filter == "" {
		filter = "all"
	}
	var logs []db.Log
	var err error
	if filter == "all" {
		logs, err = db.GetLogs(app.DB)
	} else {
		logs, err = db.GetLogsOfEvent(app.DB, strings.ToUpper(filter))
	}

	if err != nil {
		c.Error(err)
		return
	}

	c.HTML(http.StatusOK, "logs_view", gin.H{
		"Logs": logs,
	})
}

func (app *ServerCtx) LogsDelete(c *gin.Context) {
	err := db.DeleteAllLogs(app.DB)
	if err != nil {
		c.Error(err)
		return
	}
}
