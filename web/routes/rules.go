package routes

import (
	"fmt"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/core/tc"
	"github.com/kakeetopius/qosm/internal/core/util"
	"github.com/kakeetopius/qosm/web/db"
)

type PostForm struct {
	RuleType string `form:"type"`
	Target   string `form:"target"`
	Priority string `form:"priority"`
}

type Rule struct {
	ID       int
	Target   string
	Type     string
	Priority string
}

func (app *ServerCtx) PostRules(c *gin.Context) {
	var form PostForm

	if err := c.ShouldBind(&form); err != nil {
		c.Error(fmt.Errorf("invalid form fields"))
		return
	}

	var err error
	var rule Rule
	switch form.RuleType {
	case "ip":
		rule, err = addIPRule(app, form.Target, form.Priority)
	case "domain":
		rule, err = addDomainRule(app, form.Target, form.Priority)
	default:
		err = fmt.Errorf("unknown rule type: %s", form.RuleType)
	}

	if err != nil {
		c.Error(err)
		return
	}

	c.Header("HX-Trigger", `{"toast":"Rule added"}`)
	SendNewRuleRow(c, rule)
}

func SendNewRuleRow(c *gin.Context, rule Rule) {
	c.HTML(http.StatusOK, "rule_table_row", gin.H{
		"Rule": rule,
	})
}

func addDomainRule(app *ServerCtx, domain string, priority string) (Rule, error) {
	exists, err := db.CheckDomainRuleExists(app.DB, domain)
	if err != nil {
		return Rule{}, err
	}
	if exists {
		return Rule{}, fmt.Errorf("rule for %v already exists", domain)
	}

	var prio tc.Priority
	switch priority {
	case "high":
		prio = tc.PRIORITYHIGH
	case "low":
		prio = tc.PRIORITYLOW
	default:
		return Rule{}, fmt.Errorf("unknown priority: %s", priority)
	}

	app.Logger.Info("resolving_domain", "domain", domain)
	ips, err := net.LookupIP(domain)
	if err != nil {
		app.Logger.Error("resolve_error", "domain", domain, "error", err.Error())
		return Rule{}, err
	}
	addrs := util.NetIPtoNetIPPRefix(ips)

	app.Logger.Info("add_rule", "target", domain, "priority", priority)

	err = app.HTBCtx.AddRule(addrs, prio)
	if err != nil {
		app.Logger.Error("tc_error", "error", err.Error())
		return Rule{}, err
	}
	err = db.AddDomainToPriority(app.DB, domain, priority, addrs)
	if err != nil {
		return Rule{}, err
	}

	rule, err := db.GetDomainRuleNameByWithoutIPs(app.DB, domain)
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		Type:     "domain",
		Priority: rule.Priority,
		Target:   rule.DomainName,
		ID:       rule.ID,
	}, nil
}

func addIPRule(app *ServerCtx, ip string, priority string) (Rule, error) {
	exists, err := db.CheckIPRuleExists(app.DB, ip)
	if err != nil {
		return Rule{}, err
	}
	if exists {
		return Rule{}, fmt.Errorf("rule for %v already exists", ip)
	}

	var prio tc.Priority
	switch priority {
	case "high":
		prio = tc.PRIORITYHIGH
	case "low":
		prio = tc.PRIORITYLOW
	default:
		return Rule{}, fmt.Errorf("unknown priority: %s", priority)
	}

	addrs, err := util.TargetsFromString(ip)
	if err != nil {
		return Rule{}, err
	}

	app.Logger.Info("add_rule", "target", ip, "priority", priority)

	err = app.HTBCtx.AddRule(addrs, prio)
	if err != nil {
		app.Logger.Error("tc_error", "error", err.Error())
		return Rule{}, err
	}

	err = db.AddIPToPriority(app.DB, ip, priority)
	if err != nil {
		return Rule{}, err
	}

	rule, err := db.GetIPRuleByName(app.DB, ip)
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		Type:     "ip",
		Priority: rule.Priority,
		Target:   rule.IP,
		ID:       rule.ID,
	}, nil
}

func getAllRules(app *ServerCtx) ([]Rule, error) {
	ipRules, err := db.GetAllIPRules(app.DB)
	if err != nil {
		return nil, err
	}
	domainRules, err := db.GetAllDomainRulesWithoutIPs(app.DB)
	if err != nil {
		return nil, err
	}

	rules := make([]Rule, 0, len(ipRules)+len(domainRules))
	for _, rule := range ipRules {
		rules = append(rules, Rule{
			ID:       rule.ID,
			Priority: rule.Priority,
			Target:   rule.IP,
			Type:     "ip",
		})
	}

	for _, rule := range domainRules {
		rules = append(rules, Rule{
			ID:       rule.ID,
			Priority: rule.Priority,
			Target:   rule.DomainName,
			Type:     "domain",
		})
	}

	return rules, nil
}
