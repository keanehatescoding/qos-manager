package tc

import (
	"errors"
	"net"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/kakeetopius/qosm/internal/core/filter"
)

type Priority int

const (
	PRIORITYHIGH Priority = iota + 1
	PRIORITYLOW
)

const (
	ROOTHANDLE = tc.HandleRoot
)

var (
	HTBQDISCHANDLE         = core.BuildHandle(0x1, 0x0)  // 1:0 handle of the qdisc itself to be attached at root
	HTBPARENTCLASSHANDLE   = core.BuildHandle(0x1, 0x1)  // 1:1 handle of parent class to be attached right under the root qdisc
	HTBHIGHPRIOCLASSHANDLE = core.BuildHandle(0x1, 0x10) //1:10 handle of high priority class
	HTBDEFAULTCLASSHANDLE  = core.BuildHandle(0x1, 0x15) //1:15 handle of the default class (packets that don't match any rule are sent here.)
	HTBLOWPRIOCLASSHANDLE  = core.BuildHandle(0x1, 0x19) // 1:19 handle of the low priority class

	HTBDEFAULTCLASS = 0x15 // default class minor (ie minor of 1:15 which is 15)

	HTBHIGHCLASSPRIO    = 0
	HTBDEFAULTCLASSPRIO = 2
	HTBLOWCLASSPRIO     = 4
)

type HTBCtx struct {
	Conn  *tc.Tc
	Iface *net.Interface

	Root         *tc.Object
	ParentClass  *tc.Object
	HighClass    *tc.Object
	LowClass     *tc.Object
	DefaultClass *tc.Object

	HighClassFilter *tc.Object
	LowClassFilter  *tc.Object

	Filter filter.NFTCtx
}

type HTBQdisc struct {
	Handle       uint32
	Parent       uint32
	DefaultClass uint32
}

type HTBClass struct {
	Handle       uint32
	ParentHandle uint32
	Rate         uint32 // in bytes per second
	Burst        uint32
	Cburst       uint32
	Priority
}

type FWFilter struct {
	Handle       uint32
	ParentHandle uint32
	ClassID      uint32
}

var ErrQdiscNotFound = errors.New("qdisc not found")

type ErrClassNotFound struct {
	ClassName   string
	ClassHandle uint32
}

type ErrFilterNotFound struct {
	FilterName   string
	FilterHandle uint32
}

func (f ErrClassNotFound) Error() string {
	return "class " + f.ClassName + " not found"
}

func (f ErrFilterNotFound) Error() string {
	return "filter " + f.FilterName + " not found"
}
