package server

import (
	"fmt"
	"net"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/db"
)

func (app *Server) PostSystemSettings(c *gin.Context) {
	loggingLevel := c.PostForm("logging_level")
	var maxBandwidth int
	fmt.Sscanf(c.PostForm("max_bandwidth"), "%d", &maxBandwidth)

	err := db.UpdateSettingsField(app.DB, "logging_level", loggingLevel)
	if err != nil {
		c.Error(err)
		return
	}
	app.Settings.LoggingLevel = loggingLevel

	err = db.UpdateSettingsField(app.DB, "max_bandwidth", maxBandwidth)
	if err != nil {
		c.Error(err)
		return
	}

	app.Settings.MaxBandwidth = maxBandwidth

	SendSuccessMessage(c)
}

func (app *Server) PostInterfaceSettings(c *gin.Context) {
	ifaceNames := c.PostFormArray("interfaces")

	var err error
	ifaces := app.QoSManager.Ifaces
	for _, iface := range ifaces {
		ifaceChecked := slices.Contains(ifaceNames, iface.Name) // checkbox marked by use
		if ifaceChecked && !iface.Enabled {
			err = app.QoSManager.EnableTcOnInterface(iface.Name, app.DB)
		} else if !ifaceChecked && iface.Enabled {
			err = app.QoSManager.DisableTcOnInterface(iface.Name, app.DB)
		}

		if err != nil {
			c.Error(err)
			return
		}
	}

	SendSuccessMessage(c)
}

func (app *Server) PostDNSSettings(c *gin.Context) {
	primaryDNS := c.PostForm("primary_dns")
	dnsOverride := c.PostForm("dns_override") == "on"

	err := db.UpdateSettingsField(app.DB, "dns_override", dnsOverride)
	if err != nil {
		c.Error(err)
		return
	}
	app.Settings.DNSOverride = dnsOverride

	ip := net.ParseIP(primaryDNS)
	if ip == nil {
		err = fmt.Errorf("invalid primary dns: %v", primaryDNS)
		c.Error(err)
		return
	}

	err = db.UpdateSettingsField(app.DB, "primary_dns", primaryDNS)
	if err != nil {
		c.Error(err)
		return
	}
	app.Settings.PrimaryDNS = primaryDNS

	SendSuccessMessage(c)
}

func (app *Server) PostSecuritySettings(c *gin.Context) {
	var sessionTimeout int

	fmt.Sscanf(c.PostForm("session_timeout"), "%d", &sessionTimeout)
	err := db.UpdateSettingsField(app.DB, "session_timeout", sessionTimeout)
	if err != nil {
		c.Error(err)
		return
	}
	app.Settings.SessionTimeout = sessionTimeout

	SendSuccessMessage(c)
}

func SendSuccessMessage(c *gin.Context, message ...string) {
	var msg string
	if len(message) == 0 {
		msg = "Settings applied successfully ✔"
	} else {
		msg = message[0]
	}

	c.HTML(http.StatusOK, "toast_success", gin.H{
		"Message": msg,
	})
}
