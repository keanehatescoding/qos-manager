// Package filter contains packet filtering for packets entering tc classes.
package filter

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type Ctx struct {
	conn  *nftables.Conn
	table *nftables.Table
	chain *nftables.Chain

	QoSMRules
	QoSMSets
}

type QoSMSets struct {
	highPrioSet *nftables.Set
	lowPrioSet  *nftables.Set
}

type QoSMRules struct {
	highPrioRule *nftables.Rule
	lowPrioRule  *nftables.Rule
}

const (
	TABLENAME = "qosmtable"
	CHAINNAME = "output"
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

func AddTargetToHighPriority(target netip.Addr) error {
	nftablesCtx, err := newCtx()
	if err != nil {
		return err
	}

	return addIPToQoSMIPSet(nftablesCtx.conn, nftablesCtx.highPrioSet, target)
}

func AddTargetToLowPriority(target netip.Addr) error {
	nftablesCtx, err := newCtx()
	if err != nil {
		return err
	}

	return addIPToQoSMIPSet(nftablesCtx.conn, nftablesCtx.lowPrioSet, target)
}

func newCtx() (Ctx, error) {
	conn, err := nftables.New()
	if err != nil {
		return Ctx{}, err
	}

	table, err := lookupQoSMTable(conn)
	if err != nil {
		return Ctx{}, err
	}

	chain, err := lookupQoSMChain(conn, table)
	if err != nil {
		return Ctx{}, err
	}

	ipSets, err := lookupQoSMIPSets(conn, table)
	if err != nil {
		return Ctx{}, err
	}

	rules, err := lookupQoSMRules(conn, table, chain, ipSets)
	if err != nil {
		return Ctx{}, err
	}

	return Ctx{
		conn:      conn,
		table:     table,
		chain:     chain,
		QoSMRules: rules,
		QoSMSets:  ipSets,
	}, nil
}

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

func lookupQoSMChain(conn *nftables.Conn, table *nftables.Table) (*nftables.Chain, error) {
	fmt.Println("Looking up qosm chains")

	chains, err := conn.ListChains()
	if err != nil {
		return nil, err
	}

	for _, chain := range chains {
		if chain.Table.Name != table.Name {
			continue
		}
		if chain.Name == CHAINNAME {
			return chain, nil
		}
	}

	return addNewQosMChain(conn, table)
}

func addNewQosMChain(conn *nftables.Conn, table *nftables.Table) (*nftables.Chain, error) {
	fmt.Println("Adding QoSM chain ")
	chain := conn.AddChain(&nftables.Chain{
		Name:     CHAINNAME,
		Hooknum:  nftables.ChainHookOutput,
		Type:     nftables.ChainTypeFilter,
		Table:    table,
		Priority: nftables.ChainPriorityFilter,
	})

	err := conn.Flush()
	if err != nil {
		return nil, err
	}

	return chain, nil
}

func lookupQoSMRules(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, ipSets QoSMSets) (QoSMRules, error) {
	fmt.Println("Looking up qosm rules")

	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return QoSMRules{}, err
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
			return QoSMRules{}, err
		}
	}

	if lowPrioRule == nil {
		lowPrioRule, err = addMarkingRule(conn, table, chain, ipSets.lowPrioSet, LOWPRIOMARK, LOWPRIORULENAME)
		if err != nil {
			return QoSMRules{}, err
		}
	}

	return QoSMRules{
		highPrioRule: highPrioRule,
		lowPrioRule:  lowPrioRule,
	}, nil
}

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

func lookupQoSMIPSets(conn *nftables.Conn, table *nftables.Table) (QoSMSets, error) {
	fmt.Println("Looking up IP Set")

	sets, err := conn.GetSets(table)
	if err != nil {
		return QoSMSets{}, err
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
			return QoSMSets{}, err
		}
	}
	if lowPrio == nil {
		lowPrio, err = addQoSMIPSet(conn, table, LOWPRIOIPSETNAME)
		if err != nil {
			return QoSMSets{}, err
		}
	}

	return QoSMSets{
		highPrioSet: highPrio,
		lowPrioSet:  lowPrio,
	}, nil
}

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

func addIPToQoSMIPSet(conn *nftables.Conn, ipSet *nftables.Set, ipToAdd netip.Addr) error {
	ip := ipToAdd.AsSlice()

	err := conn.SetAddElements(ipSet, []nftables.SetElement{
		{Key: ip},
	})
	if err != nil {
		return err
	}

	return conn.Flush()
}
