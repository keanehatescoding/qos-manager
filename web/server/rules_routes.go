package routes

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/internal/rules"
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
	var rule rules.Rule
	switch form.RuleType {
	case "ip":
		rule, err = rules.AddIPRule(app.DB, app.HTBCtx, form.Target, form.Priority, app.Logger)
	case "domain":
		rule, err = rules.AddDomainRule(app.DB, app.HTBCtx, form.Target, form.Priority, app.Logger)
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
		err = rules.DeleteDomainRuleByID(app.DB, app.HTBCtx, ruleID)
	case "ip":
		err = rules.DeleteIPRuleByID(app.DB, app.HTBCtx, ruleID)
	default:
		err = fmt.Errorf("unknown rule type: %s", ruleType)
	}

	if err != nil {
		c.Error(err)
		return
	}

	SendSuccessMessage(c, "Successfully deleted rule.")
}

func SendNewRuleRow(c *gin.Context, rule rules.Rule) {
	c.HTML(http.StatusOK, "rule_table_row", gin.H{
		"Rule": rule,
	})
}
