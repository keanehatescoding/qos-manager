package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/kakeetopius/qosm/internal/core/htb"
	"github.com/kakeetopius/qosm/internal/db"
	"github.com/kakeetopius/qosm/internal/rules"
	"github.com/kakeetopius/qosm/internal/tc"
	"github.com/spf13/cobra"
)

func RestoreCmd() *cobra.Command {
	restoreCmd := cobra.Command{
		Use:     "restore",
		Short:   "Restore all traffic control rules and interface settings according to the state stored in the database.",
		Long:    "Restore all traffic control rules and interface settings according to the state stored in the database.\nUseful when the system was rebooted or the QoS rules and interface qdisc settings were altered externally without using qosm.",
		Args:    cobra.NoArgs,
		Aliases: []string{"res"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRestore()
		},
	}

	return &restoreCmd
}

func runRestore() error {
	htbCtx, err := htb.NewHTBCtx()
	if err != nil {
		return err
	}
	defer htbCtx.Close()
	if debug {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
		htbCtx.WithLogger(logger)
	}

	err = htbCtx.InitHTBFilter(true)
	if err != nil {
		return err
	}

	dbConn, err := db.NewConn(appConfig.GetString("db.path"))
	if err != nil {
		return err
	}

	err = rules.InitSavedRules(dbConn, htbCtx, htbCtx.Logger)
	if err != nil {
		return err
	}

	err = tc.InitSavedInterfaceSettings(dbConn, htbCtx)
	if err != nil {
		return err
	}

	fmt.Println("Restore Done Successfully")

	return nil
}
