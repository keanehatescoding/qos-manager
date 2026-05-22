package routes

import (
	"fmt"
	"net"

	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/core/tc"
	"github.com/kakeetopius/qosm/internal/core/util"
)

type PostForm struct {
	RuleType  string `form:"type"`
	Target    string `form:"target"`
	IfaceName string `form:"interface"`
	Priority  string `form:"priority"`
}

func (app *ServerCtx) PostRules(c *gin.Context) {
	var form PostForm

	if err := c.ShouldBind(&form); err != nil {
		c.Error(fmt.Errorf("invalid form fields"))
		return
	}

	var err error
	switch form.RuleType {
	case "ip":
		err = addIPRule(app, form.Target, form.IfaceName, form.Priority)
	case "domain":
		err = addDomainRule(app, form.Target, form.IfaceName, form.Priority)
	default:
		err = fmt.Errorf("unknown rule type: %s", form.RuleType)
	}

	if err != nil {
		c.Error(err)
		return
	}

	SendSuccessMessage(c, "Rule applied successfully")
}

func addDomainRule(app *ServerCtx, domain string, iface string, priority string) error {
	var prio tc.Priority
	switch priority {
	case "high":
		prio = tc.PRIORITYHIGH
	case "low":
		prio = tc.PRIORITYLOW
	default:
		return fmt.Errorf("unknown priority: %s", priority)
	}

	app.Logger.Info("resolving_domain", "domain", domain)
	ips, err := net.LookupIP(domain)
	if err != nil {
		app.Logger.Error("resolve_error", "domain", domain, "error", err.Error())
		return err
	}
	addrs := util.NetIPtoNetIPPRefix(ips)

	app.Logger.Info("add_rule", "target", domain, "network_interface", iface, "priority", priority)
	err = app.Ifaces[iface].HTBCtx.AddRule(addrs, prio)
	if err != nil {
		app.Logger.Error("tc_error", "error", err.Error())
		return err
	}

	return nil
}

func addIPRule(app *ServerCtx, ip string, iface string, priority string) error {
	var prio tc.Priority
	switch priority {
	case "high":
		prio = tc.PRIORITYHIGH
	case "low":
		prio = tc.PRIORITYLOW
	default:
		return fmt.Errorf("unknown priority: %s", priority)
	}

	addrs, err := util.TargetsFromString(ip)
	if err != nil {
		return err
	}

	app.Logger.Info("add_rule", "target", ip, "network_interface", iface, "priority", priority)
	err = app.Ifaces[iface].HTBCtx.AddRule(addrs, prio)
	if err != nil {
		app.Logger.Error("tc_error", "error", err.Error())
		return err
	}

	return nil
}
