// Package nft contains packet filtering for packets entering tc classes.
package nft

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type NFTOpts struct {
	CreateIfNotExists bool
	Logger            *slog.Logger
}

func NewNFTCtx(opts NFTOpts) (NFTCtx, error) {
	conn, err := nftables.New()
	if err != nil {
		return NFTCtx{}, err
	}

	table, err := lookupQoSMTable(conn, &opts)
	if err != nil {
		return NFTCtx{}, err
	}

	outputChain, err := lookupQoSMChain(conn, table, OUTPUTCHAINNAME, nftables.ChainHookOutput, &opts)
	if err != nil {
		return NFTCtx{}, err
	}

	forwardChain, err := lookupQoSMChain(conn, table, FORWARDCHAINNAME, nftables.ChainHookForward, &opts)
	if err != nil {
		return NFTCtx{}, err
	}

	ipSets, err := lookupQoSMIPSets(conn, table, &opts)
	if err != nil {
		return NFTCtx{}, err
	}

	chains := qosmChains{
		outputChain:  outputChain,
		forwardChain: forwardChain,
	}

	return NFTCtx{
		Logger: opts.Logger,
		conn:   conn,
		qosmTable: qosmTable{
			Table:      table,
			qosmChains: chains,
			qosmSets:   ipSets,
		},
	}, nil
}

// DeleteTable removes the qosm nftables table from the system.
func DeleteTable() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}

	tables, err := conn.ListTables()
	if err != nil {
		return err
	}

	for _, table := range tables {
		if table.Name == TABLENAME {
			conn.DelTable(table)
			return conn.Flush()
		}
	}

	return ErrTableNotFound
}

func lookupQoSMTable(conn *nftables.Conn, opts *NFTOpts) (*nftables.Table, error) {
	Debug(opts.Logger, "nft: lookup of qosm table")
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}

	for _, table := range tables {
		if table.Name == TABLENAME {
			Debug(opts.Logger, "nft: lookup successfull", "name", "qosmtable")
			return table, nil
		}
	}

	if opts.CreateIfNotExists {
		return addNewQoSMTable(conn, opts.Logger)
	}

	return nil, ErrTableNotFound
}

// addNewQoSMTable creates and adds a new qosm nftables table to the system.
// Returns the created table or an error if failed
func addNewQoSMTable(conn *nftables.Conn, logger *slog.Logger) (*nftables.Table, error) {
	Debug(logger, "nft: creating table", "name", "qosmtable")
	table := conn.AddTable(&nftables.Table{
		Name:   TABLENAME,
		Family: nftables.TableFamilyINet,
	})

	err := conn.Flush()
	if err != nil {
		return nil, err
	}

	return table, nil
}

// lookupQoSMChains searches for the specified chain within the specified nftables table.
// If found, it return the chain. If not found, it creates the chain
func lookupQoSMChain(conn *nftables.Conn, table *nftables.Table, chainName string, hook *nftables.ChainHook, opts *NFTOpts) (qosmChain, error) {
	Debug(opts.Logger, "nft: lookup of qosm chain")
	chains, err := conn.ListChains()
	if err != nil {
		return qosmChain{}, err
	}

	for _, chain := range chains {
		if chain.Table.Name != table.Name {
			continue
		}
		if chain.Name == chainName {
			Debug(opts.Logger, "nft: chain lookup successfull", "name", chainName)
			return qosmChain{
				Chain: chain,
			}, nil
		}
	}

	if opts.CreateIfNotExists {
		return addNewQosMChain(conn, table, chainName, hook, opts.Logger)
	}

	return qosmChain{}, ErrChainNotFound
}

// addNewQosMChain creates and adds a new chain to the specified nftables table.
// The chain is configured as the specified hook  with standard filter priority.
func addNewQosMChain(conn *nftables.Conn, table *nftables.Table, chainName string, hook *nftables.ChainHook, logger *slog.Logger) (qosmChain, error) {
	Debug(logger, "nft: creating chain", "name", chainName)
	chain := conn.AddChain(&nftables.Chain{
		Name:     chainName,
		Hooknum:  hook,
		Type:     nftables.ChainTypeFilter,
		Table:    table,
		Priority: nftables.ChainPriorityFilter,
	})

	err := conn.Flush()
	if err != nil {
		return qosmChain{}, err
	}

	return qosmChain{
		Chain: chain,
	}, nil
}

func lookupQoSMRules(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, ipSets qosmSets, oifIndex int, opts *NFTOpts) (qosmRules, error) {
	Debug(opts.Logger, "nft: lookup of qosm rules", "chain", chain.Name)

	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return qosmRules{}, err
	}

	highPrioRuleName := fmt.Sprintf("%v_%v", oifIndex, HIGHPRIORULENAME)
	lowPrioRuleName := fmt.Sprintf("%v_%v", oifIndex, LOWPRIORULENAME)

	var highPrioRule *nftables.Rule
	var lowPrioRule *nftables.Rule

	for _, rule := range rules {
		if string(rule.UserData) == highPrioRuleName {
			Debug(opts.Logger, "nft: rule lookup successfull", "chain", chain.Name, "rule", highPrioRuleName)
			highPrioRule = rule
		}
		if string(rule.UserData) == lowPrioRuleName {
			Debug(opts.Logger, "nft: rule lookup successfull", "chain", chain.Name, "rule", lowPrioRuleName)
			lowPrioRule = rule
		}
	}

	if highPrioRule == nil {
		if opts.CreateIfNotExists {
			highPrioRule, err = addMarkingRule(conn, ruleParams{
				table:       table,
				chain:       chain,
				ipSet:       ipSets.highPrioSet,
				mark:        HIGHPRIOMARK,
				ruleName:    highPrioRuleName,
				oifaceIndex: oifIndex,
			}, opts.Logger)
			if err != nil {
				return qosmRules{}, err
			}
		} else {
			return qosmRules{}, ErrRuleNotFound{Name: highPrioRuleName}
		}
	}

	if lowPrioRule == nil {
		if opts.CreateIfNotExists {
			lowPrioRule, err = addMarkingRule(conn, ruleParams{
				table:       table,
				chain:       chain,
				ipSet:       ipSets.lowPrioSet,
				mark:        LOWPRIOMARK,
				ruleName:    lowPrioRuleName,
				oifaceIndex: oifIndex,
			}, opts.Logger)
			if err != nil {
				return qosmRules{}, err
			}
		} else {
			return qosmRules{}, ErrRuleNotFound{Name: lowPrioRuleName}
		}
	}

	return qosmRules{
		highPrioRule: highPrioRule,
		lowPrioRule:  lowPrioRule,
	}, nil
}

func addMarkingRule(conn *nftables.Conn, params ruleParams, logger *slog.Logger) (*nftables.Rule, error) {
	Debug(logger, "nft: creating rule", "chain", params.chain.Name, "rule", params.ruleName, "mark", params.mark, "oifaceIndex", params.oifaceIndex)
	byteMark := make([]byte, 4)
	binary.NativeEndian.PutUint32(byteMark, uint32(params.mark))

	ifIndex := make([]byte, 4)
	binary.NativeEndian.PutUint32(ifIndex, uint32(params.oifaceIndex))

	rule := conn.AddRule(&nftables.Rule{
		Table:    params.table,
		Chain:    params.chain,
		UserData: []byte(params.ruleName),
		Exprs: []expr.Any{
			// Load outgoing interface index into reg 1
			&expr.Meta{
				Register: 1,
				Key:      expr.MetaKeyOIF,
			},

			// compare with what is in reg 1 ie the given interface's index
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifIndex,
			},

			// Load the dst IP in packet into register 1.
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // bytes from start of IP Layer (leads to dest IP)
				Len:          4,  // 4 bytes of the IPv4 addr
			},

			// Check if IP put in register 1 above is contained in the IP Set
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        params.ipSet.Name,
				SetID:          params.ipSet.ID,
			},

			// Load the mark into register 1
			&expr.Immediate{
				Register: 1,
				Data:     byteMark,
			},

			// Set the mark field in the metadata with what is in register 1.
			&expr.Meta{
				Key:            expr.MetaKeyMARK,
				SourceRegister: true, // indicates that we are reading  from the register not writing to it.
				Register:       1,
			},

			// Add a counter to the rule for the matched packets.
			&expr.Counter{},
		},
	})

	err := conn.Flush()
	if err != nil {
		return nil, err
	}

	return rule, nil
}

func lookupQoSMIPSets(conn *nftables.Conn, table *nftables.Table, opts *NFTOpts) (qosmSets, error) {
	Debug(opts.Logger, "nft: lookup of qosm sets")

	sets, err := conn.GetSets(table)
	if err != nil {
		return qosmSets{}, err
	}

	var highPrio *nftables.Set
	var lowPrio *nftables.Set

	for _, set := range sets {
		if set.Name == HIGHPRIOIPSETNAME {
			Debug(opts.Logger, "nft: set lookup successfull", "name", HIGHPRIOIPSETNAME)
			highPrio = set
		}
		if set.Name == LOWPRIOIPSETNAME {
			Debug(opts.Logger, "nft: set lookup successfull", "name", LOWPRIOIPSETNAME)
			lowPrio = set
		}
	}

	if highPrio == nil {
		if opts.CreateIfNotExists {
			highPrio, err = addQoSMIPSet(conn, table, HIGHPRIOIPSETNAME, opts.Logger)
			if err != nil {
				return qosmSets{}, err
			}
		} else {
			return qosmSets{}, ErrSetNotFound{Name: HIGHPRIOIPSETNAME}
		}
	}
	if lowPrio == nil {
		if opts.CreateIfNotExists {
			lowPrio, err = addQoSMIPSet(conn, table, LOWPRIOIPSETNAME, opts.Logger)
			if err != nil {
				return qosmSets{}, err
			}
		} else {
			return qosmSets{}, ErrSetNotFound{Name: LOWPRIOIPSETNAME}
		}
	}

	return qosmSets{
		highPrioSet: highPrio,
		lowPrioSet:  lowPrio,
	}, nil
}

// addQoSMIPSet creates and adds a new IP address set to the specified nftables table.
// The set is configured to store IPv4 addresses and is initialized as empty.
// Returns the created set or an error if flushing fails.
func addQoSMIPSet(conn *nftables.Conn, table *nftables.Table, name string, logger *slog.Logger) (*nftables.Set, error) {
	Debug(logger, "nft: creating set", "name", name)
	set := &nftables.Set{
		Table:   table,
		Name:    name,
		KeyType: nftables.TypeIPAddr,
	}
	ipSetElements := []nftables.SetElement{}

	err := conn.AddSet(set, ipSetElements)
	if err != nil {
		return nil, err
	}

	err = conn.Flush()
	if err != nil {
		return nil, err
	}

	return set, nil
}

// addIPsToQoSMIPSet adds a collection of IP networks to the specified nftables IP set.
// It iterates through each network prefix, expanding it to individual IP addresses,
// and adds each IP as a set element.
// Returns an error if the set add operation fails
func addIPsToQoSMIPSet(conn *nftables.Conn, ipSet *nftables.Set, ipNetworks []netip.Prefix) error {
	setElements := make([]nftables.SetElement, 0, len(ipNetworks))

	for _, network := range ipNetworks {
		ip := network.Addr()
		for network.Contains(ip) {
			setElements = append(setElements, nftables.SetElement{Key: ip.AsSlice()})

			ip = ip.Next()
		}
	}

	err := conn.SetAddElements(ipSet, setElements)
	if err != nil {
		return err
	}
	return conn.Flush()
}

// getIPSetElements retrieves all IP addresses stored in the specified nftables IP set.
func getIPSetElements(conn *nftables.Conn, set *nftables.Set) ([]netip.Addr, error) {
	elements, err := conn.GetSetElements(set)
	if err != nil {
		return nil, err
	}

	ips := make([]netip.Addr, 0, len(elements))
	for _, element := range elements {
		ip, ok := netip.AddrFromSlice(element.Key)
		if !ok {
			continue
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

func getRuleStats(rule *nftables.Rule) PrioritySetStats {
	exprs := rule.Exprs

	for _, e := range exprs {
		switch counter := e.(type) {
		case *expr.Counter:
			return PrioritySetStats{counter.Packets, counter.Bytes}
		}
	}

	return PrioritySetStats{}
}

// deleteIPsFromQoSIPSet removes a collection of IP networks from the specified nftables IP set.
// It iterates through each network prefix, expanding it to individual IP addresses,
// verifies each IP exists in the set, and collects them for deletion.
// If any IP is not found in the set, an error is returned.
func deleteIPsFromQoSIPSet(conn *nftables.Conn, ipSet *nftables.Set, ipNetworks []netip.Prefix) error {
	setElements := make([]nftables.SetElement, 0, len(ipNetworks))

	for _, network := range ipNetworks {
		ip := network.Addr()
		for network.Contains(ip) {
			exists, err := ipExistsInQoSIPSet(conn, ipSet, ip)
			if err != nil {
				return err
			}
			if exists {
				setElements = append(setElements, nftables.SetElement{Key: ip.AsSlice()})
			} else {
				return fmt.Errorf("%v is not found of the given priority set", ip)
			}
			ip = ip.Next()
		}
	}

	if len(setElements) > 0 {
		err := conn.SetDeleteElements(ipSet, setElements)
		if err != nil {
			return err
		}
		return conn.Flush()
	}

	return nil
}

// ipExistsInQoSIPSet checks whether a given IP address exists in the specified nftables IP set.
// It retrieves all elements from the set and searches for the given IP.
// Returns true if the IP is found, false otherwise. Returns an error if retrieving set elements fails.
func ipExistsInQoSIPSet(conn *nftables.Conn, ipSet *nftables.Set, givenIP netip.Addr) (bool, error) {
	addrs, err := getIPSetElements(conn, ipSet)
	if err != nil {
		return false, err
	}

	if slices.Contains(addrs, givenIP) {
		return true, nil
	}

	return false, nil
}
