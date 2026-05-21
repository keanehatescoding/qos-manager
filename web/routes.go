package web

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/core/pam"
)

func (app *ServerCtx) loginPost(ctx *gin.Context) {
	username := ctx.PostForm("username")
	password := ctx.PostForm("password")

	app.logger.Info("login attempt", "username", username)

	if err := pam.AuthenticateUser(username, password); err != nil {
		app.logger.Error("auth_failed", "username", username, "err", err)
		ctx.Error(ServerError{
			StatusCode: http.StatusOK,
			Err:        fmt.Errorf(" Invalid username or password"),
		})

		return
	}

	ctx.Header("HX-Redirect", "/dashboard")
	ctx.Status(http.StatusOK)
}

func (app *ServerCtx) login(c *gin.Context) {
	c.HTML(http.StatusOK, "login", gin.H{
		"Title": "Login - QoS Manager",
	})
}

func (app *ServerCtx) dashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard", gin.H{
		"Path":        c.Request.URL.Path,
		"Heading":     "Dashboard",
		"Description": "Overview of network traffic and QoS policies",
	})
}

func (app *ServerCtx) rules(c *gin.Context) {
	c.HTML(http.StatusOK, "rules", gin.H{
		"Path":        c.Request.URL.Path,
		"Heading":     "Rules",
		"Description": "Define how network traffic should be prioritized or limited",
	})
}

func (app *ServerCtx) analytics(c *gin.Context) {
	c.HTML(http.StatusOK, "analytics", gin.H{
		"Path":        c.Request.URL.Path,
		"Heading":     "Analytics",
		"Description": "Network usage insights and QoS effectiveness",
	})
}

func (app *ServerCtx) logs(c *gin.Context) {
	c.HTML(http.StatusOK, "logs", gin.H{
		"Path":        c.Request.URL.Path,
		"Heading":     "Logs",
		"Description": "Real-time QoS engine and network activity logs",
	})
}

func (app *ServerCtx) settings(c *gin.Context) {
	c.HTML(http.StatusOK, "settings", gin.H{
		"Path":        c.Request.URL.Path,
		"Heading":     "Settings",
		"Description": "Configure QoS engine behavior and system preferences",
	})
}

func (app *ServerCtx) logout(c *gin.Context) {
	c.Redirect(http.StatusFound, "/login")
}
