package routes

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/qos"
)

type PostForm struct {
	RuleType string `form:"type"`
	Target   string `form:"target"`
	Priority string `form:"priority"`
}

func (app *ServerCtx) PostRules(c *gin.Context) {
	var form PostForm

	if err := c.ShouldBind(&form); err != nil {
		c.Error(fmt.Errorf("invalid form fields"))
		return
	}

	var err error
	var rule qos.Rule
	switch form.RuleType {
	case "ip":
		rule, err = app.QoSManager.AddIPRule(app.DB, form.Target, form.Priority)
	case "domain":
		rule, err = app.QoSManager.AddDomainRule(app.DB, form.Target, form.Priority)
	default:
		err = fmt.Errorf("unknown rule type: %s", form.RuleType)
	}

	if err != nil {
		c.Error(err)
		return
	}

	SendNewRuleRow(c, rule)
	SendSuccessMessage(c, "Successfully added rule.")
}

func (app *ServerCtx) DeleteRule(c *gin.Context) {
	ruleType := c.Param("type")
	ruleID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.Error(fmt.Errorf("invalid id given"))
		return
	}

	switch ruleType {
	case "domain":
		err = app.QoSManager.DeleteDomainRuleByID(app.DB, ruleID)
	case "ip":
		err = app.QoSManager.DeleteIPRuleByID(app.DB, ruleID)
	default:
		err = fmt.Errorf("unknown rule type: %s", ruleType)
	}

	if err != nil {
		c.Error(err)
		return
	}

	SendSuccessMessage(c, "Successfully deleted rule.")
}

func SendNewRuleRow(c *gin.Context, rule qos.Rule) {
	c.HTML(http.StatusOK, "rule_table_row", gin.H{
		"Rule": rule,
	})
}
