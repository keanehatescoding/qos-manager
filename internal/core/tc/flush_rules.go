package tc

import (
	"errors"
	"fmt"

	"github.com/florianl/go-tc"
	"github.com/kakeetopius/qosm/internal/core/filter"
)

func FlushRules(iface string) error {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return err
	}

	defer func() {
		closeErr := tcnl.Close()
		if closeErr != nil {
			err = fmt.Errorf("%w", closeErr)
		}
	}()

	qdisc, err := getQdisc(tcnl)
	if err != nil {
		if !errors.Is(err, errQdiscNotFound) {
			return err
		}
	}
	if qdisc != nil {
		err = deleteQdisc(tcnl, qdisc)
		if err != nil {
			return err
		}
	}

	return filter.DeleteTable()
}

func deleteQdisc(tcnl *tc.Tc, qdisc *tc.Object) error {
	fmt.Println("Deleting qdisc on root.")
	err := tcnl.Qdisc().Delete(qdisc)
	if err != nil {
		return err
	}

	return nil
}
