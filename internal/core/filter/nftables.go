// Package filter contains packet filtering for packets entering classes.
package filter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type NftablesCtx struct {
	conn  *nftables.Conn
	table *nftables.Table
	chain *nftables.Chain
	rule  *nftables.Rule
	ipSet *nftables.Set
}

var errEntityNotFound = errors.New("entity not found")

func MarkPacketHighPriority(target netip.Addr) error {
	nftablesCtx, err := newCtx()
	if err != nil {
		return err
	}

	return addIPToQoSMIPSet(nftablesCtx.conn, nftablesCtx.ipSet, target)
}

func newCtx() (NftablesCtx, error) {
	conn, err := nftables.New()
	if err != nil {
		return NftablesCtx{}, err
	}

	table, err := lookupQoSMTable(conn)
	if err != nil {
		if !errors.Is(err, errEntityNotFound) {
			return NftablesCtx{}, err
		}
		table, err = addNewQoSMTable(conn)
		if err != nil {
			return NftablesCtx{}, err
		}
	}
	chain, err := lookupQoSMChain(conn, table)
	if err != nil {
		if !errors.Is(err, errEntityNotFound) {
			return NftablesCtx{}, err
		}
		chain, err = addNewQosMChain(conn, table)
		if err != nil {
			return NftablesCtx{}, err
		}
	}

	ipSet, err := lookupQoSMIPSet(conn, table)
	if err != nil {
		if !errors.Is(err, errEntityNotFound) {
			return NftablesCtx{}, err
		}
		ipSet, err = addQoSMIPSet(conn, table)
		if err != nil {
			return NftablesCtx{}, err
		}
	}

	rule, err := lookupQoSMRules(conn, table, chain)
	if err != nil {
		if !errors.Is(err, errEntityNotFound) {
			return NftablesCtx{}, err
		}
		rule, err = addNewQoSMRule(conn, table, chain, ipSet)
		if err != nil {
			return NftablesCtx{}, err
		}
	}

	return NftablesCtx{
		conn:  conn,
		table: table,
		chain: chain,
		ipSet: ipSet,
		rule:  rule,
	}, nil
}

func lookupQoSMTable(conn *nftables.Conn) (*nftables.Table, error) {
	fmt.Println("Looking up qosm table on system")

	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}

	for _, table := range tables {
		if table.Name == "qosmtable" {
			return table, nil
		}
	}

	return nil, errEntityNotFound
}

func addNewQoSMTable(conn *nftables.Conn) (*nftables.Table, error) {
	fmt.Println("Adding qosm table")
	table := conn.AddTable(&nftables.Table{
		Name:   "qosmtable",
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
		if chain.Name == "output" {
			return chain, nil
		}
	}

	return nil, errEntityNotFound
}

func addNewQosMChain(conn *nftables.Conn, table *nftables.Table) (*nftables.Chain, error) {
	fmt.Println("Adding QoSM chain ")
	chain := conn.AddChain(&nftables.Chain{
		Name:     "output",
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

func lookupQoSMRules(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain) (*nftables.Rule, error) {
	fmt.Println("Looking up qosm rules")

	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return nil, err
	}

	if len(rules) == 0 {
		return nil, errEntityNotFound
	}

	return rules[0], nil
}

func addNewQoSMRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, ipSet *nftables.Set) (*nftables.Rule, error) {
	fmt.Println("Adding QoSM rule")
	mark := make([]byte, 4)
	binary.LittleEndian.PutUint32(mark, 10)

	rule := conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
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
				Data:     mark,
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

func lookupQoSMIPSet(conn *nftables.Conn, table *nftables.Table) (*nftables.Set, error) {
	fmt.Println("Looking up IP Set")

	sets, err := conn.GetSets(table)
	if err != nil {
		return nil, err
	}

	for _, set := range sets {
		if set.Name == "matched_ips" {
			return set, nil
		}
	}

	return nil, errEntityNotFound
}

func addQoSMIPSet(conn *nftables.Conn, table *nftables.Table) (*nftables.Set, error) {
	fmt.Println("Adding QoSM IP Set")
	ipSet := &nftables.Set{
		Table:   table,
		Name:    "matched_ips",
		KeyType: nftables.TypeIPAddr,
	}
	ipSetElements := []nftables.SetElement{}

	fmt.Println("Adding IP Set")
	err := conn.AddSet(ipSet, ipSetElements)
	if err != nil {
		return nil, err
	}

	err = conn.Flush()
	if err != nil {
		return nil, err
	}

	return ipSet, nil
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
