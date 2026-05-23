package nft

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/google/nftables"
)

type IfaceIndex int

// NFTCtx holds the nftables connection and all QOSM table structures.
type NFTCtx struct {
	conn *nftables.Conn
	qosmTable

	Logger *slog.Logger
}

// qosmTable represents the nftables table with all QOSM chains and sets.
type qosmTable struct {
	*nftables.Table
	qosmChains
	qosmSets
}

// qosmChains holds the output and forward chains for QOSM.
type qosmChains struct {
	outputChain  qosmChain
	forwardChain qosmChain
}

// qosmChain represents an nftables chain with its associated rules.
type qosmChain struct {
	*nftables.Chain
	Rules map[IfaceIndex]qosmRules
}

// qosmSets holds the nftables ip sets for high and low priority traffic.
type qosmSets struct {
	highPrioSet *nftables.Set
	lowPrioSet  *nftables.Set
}

// qosmRules holds the nftables rules for high and low priority traffic.
type qosmRules struct {
	highPrioRule *nftables.Rule
	lowPrioRule  *nftables.Rule
}

type PrioritySetStats struct {
	PacketCount uint64
	ByteCount   uint64
}

const (
	TABLENAME        = "qosmtable"
	OUTPUTCHAINNAME  = "output"
	FORWARDCHAINNAME = "forward"
)

const (
	HIGHPRIORULENAME  = "high_prio_rule"
	HIGHPRIOIPSETNAME = "high_prio_ips"
	HIGHPRIOMARK      = 10
)

const (
	LOWPRIORULENAME  = "low_prio_rule"
	LOWPRIOIPSETNAME = "low_prio_ips"
	LOWPRIOMARK      = 20
)

type ruleParams struct {
	table       *nftables.Table
	chain       *nftables.Chain
	ipSet       *nftables.Set
	oifaceIndex int
	mark        int
	ruleName    string
}

var (
	ErrNotFound      = errors.New("nft object not found")
	ErrTableNotFound = errors.New("qosm table not found")
	ErrChainNotFound = errors.New("qosm chains not found")
)

type ErrSetNotFound struct {
	Name string
}

func (e ErrSetNotFound) Error() string {
	return "nft set " + e.Name + " not found"
}

type ErrRuleNotFound struct {
	Name string
}

func (e ErrRuleNotFound) Error() string {
	return "nft chain " + e.Name + " not found"
}

func Debug(logger *slog.Logger, msg string, args ...any) {
	if logger != nil {
		logger.Debug(msg, args...)
		return
	}

	slog.Debug(msg, args...)
}

func Info(logger *slog.Logger, msg string, args ...any) {
	if logger != nil {
		logger.Info(msg, args...)
		return
	}

	slog.Info(msg, args...)
}

func Warn(logger *slog.Logger, msg string, args ...any) {
	if logger != nil {
		logger.Warn(msg, args...)
		return
	}

	slog.Warn(msg, args...)
}

func Error(logger *slog.Logger, msg string, args ...any) {
	if logger != nil {
		logger.Error(msg, args...)
		return
	}

	slog.Error(msg, args...)
}

// AddTargetsToHighPriority ip addresses to the high-priority IP set.
func (c *NFTCtx) AddTargetsToHighPriority(targets []netip.Prefix) error {
	return addIPsToQoSMIPSet(c.conn, c.highPrioSet, targets)
}

// AddTargetsToLowPriority adds ip addresses to the low-priority IP set.
func (c *NFTCtx) AddTargetsToLowPriority(targets []netip.Prefix) error {
	return addIPsToQoSMIPSet(c.conn, c.lowPrioSet, targets)
}

// DeleteTargetFromHighPriority removes the given ip addresses from the high-priority IP set.
func (c *NFTCtx) DeleteTargetFromHighPriority(targets []netip.Prefix) error {
	return deleteIPsFromQoSIPSet(c.conn, c.highPrioSet, targets)
}

// DeleteTargetFromLowPriority removes the given ip addresses from the low-priority IP set.
func (c *NFTCtx) DeleteTargetFromLowPriority(targets []netip.Prefix) error {
	return deleteIPsFromQoSIPSet(c.conn, c.lowPrioSet, targets)
}

// GetHighPrioIPs returns all IP addresses in the high-priority set.
func (c *NFTCtx) GetHighPrioIPs() ([]netip.Prefix, error) {
	return getIPSetElements(c.conn, c.highPrioSet)
}

// GetLowPrioIPs returns all IP addresses in the low-priority set.
func (c *NFTCtx) GetLowPrioIPs() ([]netip.Prefix, error) {
	return getIPSetElements(c.conn, c.lowPrioSet)
}

func (c *NFTCtx) NetworkIsHighPriority(network netip.Prefix) (bool, error) {
	return networkExistsInIPSet(c.conn, c.highPrioSet, network)
}

func (c *NFTCtx) NetworkIsLowPriority(network netip.Prefix) (bool, error) {
	return networkExistsInIPSet(c.conn, c.lowPrioSet, network)
}

func (c *NFTCtx) AddIfaceRules(ifIndex int) error {
	if c.Table == nil {
		return fmt.Errorf(" qosm nft table not yet initialised")
	}

	nftOpts := NFTOpts{
		CreateIfNotExists: true,
		Logger:            c.Logger,
	}

	// get rules in output chain for given interface
	outputRules, err := lookupQoSMRules(c.conn, c.Table, c.outputChain.Chain, c.qosmSets, ifIndex, &nftOpts)
	if err != nil {
		return err
	}

	// get rules in forward chain for given interface
	forwardRules, err := lookupQoSMRules(c.conn, c.Table, c.forwardChain.Chain, c.qosmSets, ifIndex, &nftOpts)
	if err != nil {
		return err
	}

	if c.outputChain.Rules == nil {
		c.outputChain.Rules = make(map[IfaceIndex]qosmRules)
	}
	c.outputChain.Rules[IfaceIndex(ifIndex)] = outputRules

	if c.forwardChain.Rules == nil {
		c.forwardChain.Rules = make(map[IfaceIndex]qosmRules)
	}
	c.forwardChain.Rules[IfaceIndex(ifIndex)] = forwardRules

	return nil
}

func (c *NFTCtx) DeleteIfaceRules(ifIndex int) error {
	if c.Table == nil {
		return fmt.Errorf(" qosm nft table not yet initialised")
	}

	nftOpts := NFTOpts{
		CreateIfNotExists: false,
		Logger:            c.Logger,
	}

	// first delete from the context itself
	delete(c.forwardChain.Rules, IfaceIndex(ifIndex))
	delete(c.outputChain.Rules, IfaceIndex(ifIndex))

	// get rules in output chain for given interface
	var errRuleNotFound ErrRuleNotFound
	outputRules, err := lookupQoSMRules(c.conn, c.Table, c.outputChain.Chain, c.qosmSets, ifIndex, &nftOpts)
	if err != nil {
		if errors.As(err, &errRuleNotFound) {
			return nil
		}
		return err
	}
	c.conn.DelRule(outputRules.highPrioRule)
	c.conn.DelRule(outputRules.lowPrioRule)

	// get rules in forward chain for given interface
	forwardRules, err := lookupQoSMRules(c.conn, c.Table, c.forwardChain.Chain, c.qosmSets, ifIndex, &nftOpts)
	if err != nil {
		if errors.As(err, &errRuleNotFound) {
			return nil
		}
		return err
	}
	c.conn.DelRule(forwardRules.highPrioRule)
	c.conn.DelRule(forwardRules.lowPrioRule)

	err = c.conn.Flush()
	if err != nil {
		return err
	}

	return nil
}

// func (c *NFTCtx) GetHighPrioStats() (PrioritySetStats, error) {
// 	outputStats := getRuleStats(c.outputChain.highPrioRule)
// 	forwardStats := getRuleStats(c.forwardChain.highPrioRule)
//
// 	return PrioritySetStats{
// 		PacketCount: outputStats.PacketCount + forwardStats.PacketCount,
// 		ByteCount:   outputStats.ByteCount + forwardStats.ByteCount,
// 	}, nil
// }
//
// func (c *NFTCtx) GetLowPrioStats() (PrioritySetStats, error) {
// 	outputStats := getRuleStats(c.outputChain.lowPrioRule)
// 	forwardStats := getRuleStats(c.forwardChain.lowPrioRule)
//
// 	return PrioritySetStats{
// 		PacketCount: outputStats.PacketCount + forwardStats.PacketCount,
// 		ByteCount:   outputStats.ByteCount + forwardStats.ByteCount,
// 	}, nil
// }

func (c *NFTCtx) Refresh() error {
	nftOpts := NFTOpts{
		CreateIfNotExists: false,
		Logger:            c.Logger,
	}
	ipSets, err := lookupQoSMIPSets(c.conn, c.Table, &nftOpts)
	if err != nil {
		return err
	}
	c.highPrioSet = ipSets.highPrioSet
	c.lowPrioSet = ipSets.lowPrioSet

	nftOpts.CreateIfNotExists = true

	for ifIndex := range c.outputChain.Rules {
		outputRules, err := lookupQoSMRules(c.conn, c.Table, c.outputChain.Chain, ipSets, int(ifIndex), &nftOpts)
		if err != nil {
			return err
		}
		c.outputChain.Rules[ifIndex] = outputRules
	}

	for ifIndex := range c.forwardChain.Rules {
		forwardRules, err := lookupQoSMRules(c.conn, c.Table, c.forwardChain.Chain, ipSets, int(ifIndex), &nftOpts)
		if err != nil {
			return err
		}
		c.forwardChain.Rules[ifIndex] = forwardRules
	}

	return nil
}

// DeleteTable removes the qosm nftables table from the system. The context becomes invalid after this operation.
func (c *NFTCtx) DeleteTable() error {
	fmt.Println("Deleting table")
	c.conn.DelTable(c.Table)
	return c.conn.Flush()
}
