// Package nft contains packet filtering for packets entering tc classes.
package nft

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// AddTargetsToHighPriority ip addresses to the high-priority IP set.
func AddTargetsToHighPriority(targets []netip.Prefix) error {
	nftablesCtx, err := NewNFTCtx()
	if err != nil {
		return err
	}

	return addIPsToQoSMIPSet(nftablesCtx.conn, nftablesCtx.highPrioSet, targets)
}

// AddTargetsToLowPriority adds ip addresses to the low-priority IP set.
func AddTargetsToLowPriority(targets []netip.Prefix) error {
	nftablesCtx, err := NewNFTCtx()
	if err != nil {
		return err
	}

	return addIPsToQoSMIPSet(nftablesCtx.conn, nftablesCtx.lowPrioSet, targets)
}

// DeleteTargetFromHighPriority removes the given ip addresses from the high-priority IP set.
func DeleteTargetFromHighPriority(targets []netip.Prefix) error {
	nftablesCtx, err := NewNFTCtx()
	if err != nil {
		return err
	}

	return deleteIPsFromQoSIPSet(nftablesCtx.conn, nftablesCtx.highPrioSet, targets)
}

// DeleteTargetFromLowPriority removes the given ip addresses from the low-priority IP set.
func DeleteTargetFromLowPriority(targets []netip.Prefix) error {
	nftablesCtx, err := NewNFTCtx()
	if err != nil {
		return err
	}

	return deleteIPsFromQoSIPSet(nftablesCtx.conn, nftablesCtx.lowPrioSet, targets)
}

// GetHighPrioIPs returns all IP addresses in the high-priority set.
func GetHighPrioIPs() ([]netip.Addr, error) {
	nftCtx, err := NewNFTCtx()
	if err != nil {
		return nil, err
	}

	return getIPSetElements(nftCtx.conn, nftCtx.highPrioSet)
}

// GetLowPrioIPs returns all IP addresses in the low-priority set.
func GetLowPrioIPs() ([]netip.Addr, error) {
	nftCtx, err := NewNFTCtx()
	if err != nil {
		return nil, err
	}

	return getIPSetElements(nftCtx.conn, nftCtx.lowPrioSet)
}

// DeleteTable removes the qosm nftables table from the system.
func DeleteTable() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}

	fmt.Println("Looking up qosm table on system")

	tables, err := conn.ListTables()
	if err != nil {
		return err
	}

	for _, table := range tables {
		if table.Name == TABLENAME {

			fmt.Println("Deleting table")
			conn.DelTable(table)
		}
	}

	return conn.Flush()
}

// NewNFTCtx creates and initializes a new Ctx (context) for nftables operations.
// It establishes a connection to nftables and retrieves the qosm table, chains,
// IP sets, and rules. Returns a populated Ctx or an error if any step fails.
func NewNFTCtx() (NFTCtx, error) {
	conn, err := nftables.New()
	if err != nil {
		return NFTCtx{}, err
	}

	table, err := lookupQoSMTable(conn)
	if err != nil {
		return NFTCtx{}, err
	}

	outputChain, err := lookupQoSMChain(conn, table, OUTPUTCHAINNAME, nftables.ChainHookOutput)
	if err != nil {
		return NFTCtx{}, err
	}

	forwardChain, err := lookupQoSMChain(conn, table, FORWARDCHAINNAME, nftables.ChainHookForward)
	if err != nil {
		return NFTCtx{}, err
	}

	ipSets, err := lookupQoSMIPSets(conn, table)
	if err != nil {
		return NFTCtx{}, err
	}

	outputRules, err := lookupQoSMRules(conn, table, outputChain.Chain, ipSets)
	if err != nil {
		return NFTCtx{}, err
	}
	outputChain.qosmRules = outputRules

	filterRules, err := lookupQoSMRules(conn, table, forwardChain.Chain, ipSets)
	if err != nil {
		return NFTCtx{}, err
	}
	forwardChain.qosmRules = filterRules

	chains := qosmChains{
		outputChain:  outputChain,
		forwardChain: forwardChain,
	}

	return NFTCtx{
		conn: conn,
		qosmTable: qosmTable{
			Table:      table,
			qosmChains: chains,
			qosmSets:   ipSets,
		},
	}, nil
}

// lookupQoSMTable searches for the qosm nftables table on the system.
// If found, it returns the table. If not found, it creates a new qosm table
// by calling addNewQoSMTable. Returns an error if listing tables fails.
func lookupQoSMTable(conn *nftables.Conn) (*nftables.Table, error) {
	fmt.Println("Looking up qosm table on system")

	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}

	for _, table := range tables {
		if table.Name == TABLENAME {
			return table, nil
		}
	}

	return addNewQoSMTable(conn)
}

// addNewQoSMTable creates and adds a new qosm nftables table to the system.
// Returns the created table or an error if failed
func addNewQoSMTable(conn *nftables.Conn) (*nftables.Table, error) {
	fmt.Println("Adding qosm table")
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
func lookupQoSMChain(conn *nftables.Conn, table *nftables.Table, chainName string, hook *nftables.ChainHook) (qosmChain, error) {
	fmt.Println("Looking up qosm chain ", chainName)

	chains, err := conn.ListChains()
	if err != nil {
		return qosmChain{}, err
	}

	for _, chain := range chains {
		if chain.Table.Name != table.Name {
			continue
		}
		if chain.Name == chainName {
			return qosmChain{
				Chain: chain,
			}, nil
		}
	}

	return addNewQosMChain(conn, table, chainName, hook)
}

// addNewQosMChain creates and adds a new chain to the specified nftables table.
// The chain is configured as the specified hook  with standard filter priority.
func addNewQosMChain(conn *nftables.Conn, table *nftables.Table, chainName string, hook *nftables.ChainHook) (qosmChain, error) {
	fmt.Println("Adding QoSM chain ", chainName)
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

// lookupQoSMRules searches for qosm marking rules within the specified chain.
// If either rule is not found, it creates a new marking rule by calling addMarkingRule.
// Returns a QoSMRules struct containing both rules, or an error if any operation fails.
func lookupQoSMRules(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, ipSets qosmSets) (qosmRules, error) {
	fmt.Println("Looking up qosm rules for " + chain.Name)

	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return qosmRules{}, err
	}

	var highPrioRule *nftables.Rule
	var lowPrioRule *nftables.Rule

	for _, rule := range rules {
		if string(rule.UserData) == HIGHPRIORULENAME {
			highPrioRule = rule
		}
		if string(rule.UserData) == LOWPRIORULENAME {
			lowPrioRule = rule
		}
	}

	if highPrioRule == nil {
		highPrioRule, err = addMarkingRule(conn, table, chain, ipSets.highPrioSet, HIGHPRIOMARK, HIGHPRIORULENAME)
		if err != nil {
			return qosmRules{}, err
		}
	}

	if lowPrioRule == nil {
		lowPrioRule, err = addMarkingRule(conn, table, chain, ipSets.lowPrioSet, LOWPRIOMARK, LOWPRIORULENAME)
		if err != nil {
			return qosmRules{}, err
		}
	}

	return qosmRules{
		highPrioRule: highPrioRule,
		lowPrioRule:  lowPrioRule,
	}, nil
}

// addMarkingRule creates and adds a packet marking rule to the specified chain.
// The rule matches packets whose destination IP is in the provided IP set,
// A counter is added to track matched packets.
// Returns the created rule or an error if flushing fails.
func addMarkingRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, ipSet *nftables.Set, mark int, ruleName string) (*nftables.Rule, error) {
	fmt.Println("Adding ", ruleName, " QoSM rule")
	byteMark := make([]byte, 4)
	binary.LittleEndian.PutUint32(byteMark, uint32(mark))

	rule := conn.AddRule(&nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: []byte(ruleName),
		Exprs: []expr.Any{
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
				SetName:        ipSet.Name,
				SetID:          ipSet.ID,
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

// lookupQoSMIPSets searches for high and low priority IP sets within the specified table.
// If either IP set is not found, it creates a new IP set by calling addQoSMIPSet.
// Returns a QoSMSets struct containing both IP sets, or an error if any operation fails.
func lookupQoSMIPSets(conn *nftables.Conn, table *nftables.Table) (qosmSets, error) {
	fmt.Println("Looking up IP Sets")

	sets, err := conn.GetSets(table)
	if err != nil {
		return qosmSets{}, err
	}

	var highPrio *nftables.Set
	var lowPrio *nftables.Set

	for _, set := range sets {
		if set.Name == HIGHPRIOIPSETNAME {
			highPrio = set
		}
		if set.Name == LOWPRIOIPSETNAME {
			lowPrio = set
		}
	}

	if highPrio == nil {
		highPrio, err = addQoSMIPSet(conn, table, HIGHPRIOIPSETNAME)
		if err != nil {
			return qosmSets{}, err
		}
	}
	if lowPrio == nil {
		lowPrio, err = addQoSMIPSet(conn, table, LOWPRIOIPSETNAME)
		if err != nil {
			return qosmSets{}, err
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
func addQoSMIPSet(conn *nftables.Conn, table *nftables.Table, name string) (*nftables.Set, error) {
	fmt.Println("Adding QoSM IP Sets")
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
