// Package nft contains packet filtering for packets entering tc classes.
package nft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/bits"
	"net/netip"
	"os"
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
	Debug(opts.Logger, "nft: lookup of qosm rules", "chain", chain.Name, "ofindex", oifIndex)

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
			Debug(opts.Logger, "nft: set lookup successful", "name", LOWPRIOIPSETNAME)
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
		Table:    table,
		Name:     name,
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
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

func addIPsToQoSMIPSet(conn *nftables.Conn, ipSet *nftables.Set, ipNetworks []netip.Prefix) error {
	rangeElements := make([]nftables.SetElement, 2)
	for _, network := range ipNetworks {
		networkAddr := network.Masked().Addr()
		if network.Addr() != networkAddr {
			return fmt.Errorf("invalid CIDR -> %s is not a correct network address", network)
		}
		broadcast := intervalEnd(network)

		rangeElements[0] = nftables.SetElement{Key: networkAddr.AsSlice()}
		rangeElements[1] = nftables.SetElement{Key: broadcast.AsSlice(), IntervalEnd: true}

		err := conn.SetAddElements(ipSet, rangeElements)
		if err != nil {
			return err
		}
		err = conn.Flush()
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("%s is already part of one of the IP ranges", network.String())
			}
			return err
		}

	}

	return nil
}

// getIPSetElements retrieves all IP addresses stored in the specified nftables IP set.
func getIPSetElements(conn *nftables.Conn, set *nftables.Set) ([]netip.Prefix, error) {
	elements, err := conn.GetSetElements(set)
	if err != nil {
		return nil, err
	}

	ips := make([]netip.Prefix, 0, len(elements))

	for i := 0; i < len(elements); i += 2 {
		if i+1 == len(elements) {
			return nil, fmt.Errorf("invald results from nftables")
		}
		prefix, err := reconstructNftIPRange(elements[i], elements[i+1])
		if err != nil {
			return nil, err
		}
		ips = append(ips, prefix)
	}

	return ips, nil
}

func getRuleStats(rule *nftables.Rule) RuleStats {
	exprs := rule.Exprs

	for _, e := range exprs {
		switch counter := e.(type) {
		case *expr.Counter:
			return RuleStats{counter.Packets, counter.Bytes}
		}
	}

	return RuleStats{}
}

func deleteIPsFromQoSIPSet(conn *nftables.Conn, ipSet *nftables.Set, ipNetworks []netip.Prefix) error {
	toDelete := make([]nftables.SetElement, 0, len(ipNetworks))

	currentElements, err := getIPSetElements(conn, ipSet)
	if err != nil {
		return err
	}

	for _, network := range ipNetworks {
		if !slices.Contains(currentElements, network) {
			return fmt.Errorf(" Network %v not found", network)
		}
		start := network.Addr()
		end := intervalEnd(network)

		toDelete = append(toDelete,
			nftables.SetElement{
				Key: start.AsSlice(),
			},
			nftables.SetElement{
				Key:         end.AsSlice(),
				IntervalEnd: true,
			})
	}

	if len(toDelete) > 0 {
		err := conn.SetDeleteElements(ipSet, toDelete)
		if err != nil {
			return err
		}
		return conn.Flush()
	}

	return nil
}

func networkExistsInIPSet(conn *nftables.Conn, set *nftables.Set, network netip.Prefix) (bool, error) {
	setElements, err := getIPSetElements(conn, set)
	if err != nil {
		return false, err
	}
	return slices.Contains(setElements, network), nil
}

func intervalEnd(networkPrefix netip.Prefix) netip.Addr {
	if networkPrefix.IsSingleIP() {
		return networkPrefix.Addr().Next()
	}
	networkAddr := networkPrefix.Masked().Addr()
	hostBitLen := 32 - networkPrefix.Bits()

	ip := networkAddr.As4()

	ipUint := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	mask := uint32((1 << hostBitLen) - 1)

	broadCast := ipUint | mask

	return netip.AddrFrom4([4]byte{byte(broadCast >> 24), byte(broadCast >> 16), byte(broadCast >> 8), byte(broadCast)})
}

func reconstructNftIPRange(limit1 nftables.SetElement, limit2 nftables.SetElement) (netip.Prefix, error) {
	var upper, lower []byte

	if limit1.IntervalEnd {
		upper = limit2.Key
		lower = limit1.Key
	} else {
		upper = limit1.Key
		lower = limit2.Key
	}

	start, ok := netip.AddrFromSlice(upper)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("nft: invalid address")
	}
	end, ok := netip.AddrFromSlice(lower)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("nft: invalid address")
	}

	if start.Next().Compare(end) == 0 { // single IP range
		return netip.PrefixFrom(start, 32), nil
	}

	netAddr := binary.BigEndian.Uint32(start.AsSlice())
	brodcastAddr := binary.BigEndian.Uint32(end.AsSlice())

	if brodcastAddr < netAddr {
		return netip.Prefix{}, fmt.Errorf("nft: invalid CIDR range")
	}

	size := brodcastAddr - netAddr // would be something like 255

	hostbits := bits.Len32(size) // min number of bits required to represent size -> effectively hostbits
	prefix := 32 - hostbits

	return netip.PrefixFrom(start, prefix), nil
}
