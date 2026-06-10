package routes

import (
	"fmt"
	"net"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/db"
)

func (app *ServerCtx) PostSystemSettings(c *gin.Context) {
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

func (app *ServerCtx) PostInterfaceSettings(c *gin.Context) {
	ifaceNames := c.PostFormArray("interfaces")

	var err error
	for _, iface := range app.Ifaces {
		if slices.Contains(ifaceNames, iface.Name) {
			err = enableQoS(app, iface.Name)
		} else {
			err = disableQoS(app, iface.Name)
		}
		if err != nil {
			c.Error(err)
			return
		}
	}

	SendSuccessMessage(c)
}

func (app *ServerCtx) PostDNSSettings(c *gin.Context) {
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

func (app *ServerCtx) PostSecuritySettings(c *gin.Context) {
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

func enableQoS(app *ServerCtx, ifaceName string) error {
	iface := app.Ifaces[ifaceName]

	if iface.Enabled {
		return nil
	}

	err := app.QoSManager.EnableTcOnInterface(net.Interface{Name: iface.Name, Index: iface.Index}, app.DB)
	if err != nil {
		return err
	}

	iface.Enabled = true
	app.Ifaces[ifaceName] = iface

	return nil
}

func disableQoS(app *ServerCtx, ifaceName string) error {
	iface := app.Ifaces[ifaceName]
	if !iface.Enabled {
		return nil
	}

	err := app.QoSManager.DisableTcOnInterface(net.Interface{Name: iface.Name, Index: iface.Index}, app.DB)
	if err != nil {
		return err
	}

	iface.Enabled = false
	app.Ifaces[ifaceName] = iface
	return nil
}
