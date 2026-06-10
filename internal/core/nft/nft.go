package nft

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/kakeetopius/qosm/internal/prio"
)

func (c *NFT) AddTargetsToPriority(targets []netip.Prefix, priorityString string) error {
	priority, err := prio.PriorityFromString(priorityString)
	if err != nil {
		return err
	}

	switch priority {
	case prio.PRIORITYHIGH:
		return c.AddTargetsToHighPriority(targets)
	case prio.PRIORITYLOW:
		return c.AddTargetsToLowPriority(targets)
	default:
		return fmt.Errorf("unknown priority %v", priority)
	}
}

func (c *NFT) DeleteTargetsFromPriority(targets []netip.Prefix, priorityString string) error {
	priority, err := prio.PriorityFromString(priorityString)
	if err != nil {
		return err
	}

	switch priority {
	case prio.PRIORITYHIGH:
		return c.DeleteTargetFromHighPriority(targets)
	case prio.PRIORITYLOW:
		return c.DeleteTargetFromLowPriority(targets)
	default:
		return fmt.Errorf("unknown priority %v", priority)
	}
}

// AddTargetsToHighPriority ip addresses to the high-priority IP set.
func (c *NFT) AddTargetsToHighPriority(targets []netip.Prefix) error {
	return addIPsToIPSet(c.conn, c.highPrioSet, targets)
}

// AddTargetsToLowPriority adds ip addresses to the low-priority IP set.
func (c *NFT) AddTargetsToLowPriority(targets []netip.Prefix) error {
	return addIPsToIPSet(c.conn, c.lowPrioSet, targets)
}

// DeleteTargetFromHighPriority removes the given ip addresses from the high-priority IP set.
func (c *NFT) DeleteTargetFromHighPriority(targets []netip.Prefix) error {
	return deleteIPsFromIPSet(c.conn, c.highPrioSet, targets)
}

// DeleteTargetFromLowPriority removes the given ip addresses from the low-priority IP set.
func (c *NFT) DeleteTargetFromLowPriority(targets []netip.Prefix) error {
	return deleteIPsFromIPSet(c.conn, c.lowPrioSet, targets)
}

// GetHighPrioIPs returns all IP addresses in the high-priority set.
func (c *NFT) GetHighPrioIPs() ([]netip.Prefix, error) {
	return getIPSetElements(c.conn, c.highPrioSet)
}

// GetLowPrioIPs returns all IP addresses in the low-priority set.
func (c *NFT) GetLowPrioIPs() ([]netip.Prefix, error) {
	return getIPSetElements(c.conn, c.lowPrioSet)
}

func (c *NFT) NetworkIsHighPriority(network netip.Prefix) (bool, error) {
	return networkExistsInIPSet(c.conn, c.highPrioSet, network)
}

func (c *NFT) NetworkIsLowPriority(network netip.Prefix) (bool, error) {
	return networkExistsInIPSet(c.conn, c.lowPrioSet, network)
}

func (c *NFT) AddIfaceRules(ifIndex int) error {
	if c.Table == nil {
		return fmt.Errorf("qosm nft table not yet initialised")
	}

	nftOpts := NFTOpts{
		CreateIfNotExists: true,
		Logger:            c.Logger,
	}

	// get rules in output chain for given interface
	outputRules, err := lookupQosmIPRules(c.conn, c.Table, c.outputChain.Chain, c.qosmSets, ifIndex, &nftOpts)
	if err != nil {
		return err
	}

	// get rules in forward chain for given interface
	forwardRules, err := lookupQosmIPRules(c.conn, c.Table, c.forwardChain.Chain, c.qosmSets, ifIndex, &nftOpts)
	if err != nil {
		return err
	}

	// cache the rules.
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

func (c *NFT) DeleteIfaceRules(ifIndex int) error {
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
	outputRules, err := lookupQosmIPRules(c.conn, c.Table, c.outputChain.Chain, c.qosmSets, ifIndex, &nftOpts)
	if err != nil {
		if errors.As(err, &errRuleNotFound) {
			return nil
		}
		return err
	}
	c.conn.DelRule(outputRules.highPrioRule)
	c.conn.DelRule(outputRules.lowPrioRule)

	// get rules in forward chain for given interface
	forwardRules, err := lookupQosmIPRules(c.conn, c.Table, c.forwardChain.Chain, c.qosmSets, ifIndex, &nftOpts)
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

func (c *NFT) GetIfaceRuleStats(ifindex int) (InterfaceStats, error) {
	nftOpts := NFTOpts{
		CreateIfNotExists: false,
		Logger:            c.Logger,
	}

	// rules from output chain
	outputRules, err := lookupQosmIPRules(c.conn, c.Table, c.outputChain.Chain, c.qosmSets, ifindex, &nftOpts)
	if err != nil {
		return InterfaceStats{}, err
	}
	outputStatsHigh := getRuleStats(outputRules.highPrioRule)
	outputStatsLow := getRuleStats(outputRules.lowPrioRule)

	// rules from forward chain
	forwardRules, err := lookupQosmIPRules(c.conn, c.Table, c.forwardChain.Chain, c.qosmSets, ifindex, &nftOpts)
	if err != nil {
		return InterfaceStats{}, err
	}
	forwrdStatsHigh := getRuleStats(forwardRules.highPrioRule)
	forwrdStatsLow := getRuleStats(forwardRules.lowPrioRule)

	// aggregate stats from both output and foward chains into one.
	return InterfaceStats{
		IfIndex: ifindex,
		HighPrio: RuleStats{
			PacketCount: outputStatsHigh.PacketCount + forwrdStatsHigh.PacketCount,
			ByteCount:   outputStatsHigh.ByteCount + forwrdStatsHigh.ByteCount,
		},
		LowPrio: RuleStats{
			PacketCount: outputStatsLow.PacketCount + forwrdStatsLow.PacketCount,
			ByteCount:   outputStatsLow.ByteCount + forwrdStatsLow.ByteCount,
		},
	}, nil
}

// DeleteTable removes the qosm nftables table from the system. The context becomes invalid after this operation.
func (c *NFT) DeleteTable() error {
	fmt.Println("Deleting table")
	c.conn.DelTable(c.Table)
	err := c.conn.Flush()
	if err != nil {
		return err
	}
	c = nil
	return nil
}
