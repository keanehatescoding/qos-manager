package routes

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/core/tc"
	"github.com/kakeetopius/qosm/web/db"
)

func (app *ServerCtx) SaveSettings(c *gin.Context) {
	var s db.Settings

	s.QoSEnabled = c.PostForm("qos_enabled") == "on"
	s.LoggingLevel = c.PostForm("logging_level")
	s.Interface = c.PostForm("interface")
	s.PrimaryDNS = c.PostForm("primary_dns")

	fmt.Sscanf(c.PostForm("max_bandwidth"), "%d", &s.MaxBandwidth)
	fmt.Sscanf(c.PostForm("session_timeout"), "%d", &s.SessionTimeout)

	s.DNSOverride = c.PostForm("dns_override") == "on"

	err := app.ApplySettings(&s)
	if err != nil {
		c.Error(ServerError{
			StatusCode: http.StatusOK,
			Err:        err,
		})
		return
	}

	err = db.UpdateSettings(app.DB, &s)
	if err != nil {
		c.Error(ServerError{
			StatusCode: http.StatusOK,
			Err:        err,
		})
	}
}

func (app *ServerCtx) ApplySettings(s *db.Settings) error {
	var err error
	if s.QoSEnabled {
		err = enableQoS(app, s)
	} else {
		err = disableQoS(app)
	}
	if err != nil {
		return err
	}

	app.Settings = s
	return nil
}

func enableQoS(app *ServerCtx, s *db.Settings) error {
	if app.HtbCtx == nil {
		htbCtx, err := tc.NewHTBCtx(s.Interface)
		if err != nil {
			return err
		}
		app.HtbCtx = htbCtx
	}

	return nil
}

func disableQoS(app *ServerCtx) error {
	if app.HtbCtx != nil {
		err := app.HtbCtx.FlushQdisc()
		if err != nil {
			return err
		}
		app.HtbCtx = nil
	}
	return nil
}
