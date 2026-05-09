// Package filter contains packet filtering for packets entering classes.
package filter

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func MarkPacket(target netip.Addr) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}

	fmt.Println("Adding nftables rule for: ", target.String())

	table := conn.AddTable(&nftables.Table{
		Name:   "qosmtable",
		Family: nftables.TableFamilyINet,
	})

	fmt.Println("Adding table.")
	err = conn.Flush()
	if err != nil {
		return err
	}

	chain := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Hooknum:  nftables.ChainHookOutput,
		Type:     nftables.ChainTypeFilter,
		Table:    table,
		Priority: nftables.ChainPriorityFilter,
	})

	fmt.Println("Adding Chain ")
	err = conn.Flush()
	if err != nil {
		return err
	}

	mark := make([]byte, 4)
	binary.LittleEndian.PutUint32(mark, 10)

	ip := target.AsSlice()

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},

			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     ip,
			},

			&expr.Counter{},

			&expr.Immediate{
				Register: 1,
				Data:     mark,
			},

			&expr.Meta{
				Key:            expr.MetaKeyMARK,
				SourceRegister: true,
				Register:       1,
			},
		},
	})

	fmt.Println("Adding Rule")
	err = conn.Flush()
	if err != nil {
		return err
	}

	return nil
}

func newConn() (*nftables.Conn, error) {
	return nftables.New()
}

func addTableAndChain(conn *nftables.Conn) error {
	table := conn.AddTable(&nftables.Table{
		Name:   "qosmtable",
		Family: nftables.TableFamilyINet,
	})

	conn.AddChain(&nftables.Chain{
		Name:     "output",
		Hooknum:  nftables.ChainHookOutput,
		Type:     nftables.ChainTypeFilter,
		Table:    table,
		Priority: nftables.ChainPriorityFirst,
	})

	return nil
}
