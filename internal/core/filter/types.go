package filter

import "github.com/google/nftables"

// Ctx holds the nftables connection and all QOSM table structures.
type Ctx struct {
	conn *nftables.Conn
	QosmTable
}

// QosmTable represents the nftables table with all QOSM chains and sets.
type QosmTable struct {
	*nftables.Table
	QosmChains
	QosmSets
}

// QosmChain represents an nftables chain with its associated rules.
type QosmChain struct {
	*nftables.Chain
	QosmRules
}

// QosmChains holds the output and forward chains for QOSM.
type QosmChains struct {
	outputChain  QosmChain
	forwardChain QosmChain
}

// QosmSets holds the nftables ip sets for high and low priority traffic.
type QosmSets struct {
	highPrioSet *nftables.Set
	lowPrioSet  *nftables.Set
}

// QosmRules holds the nftables rules for high and low priority traffic.
type QosmRules struct {
	highPrioRule *nftables.Rule
	lowPrioRule  *nftables.Rule
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
