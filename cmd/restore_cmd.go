package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/kakeetopius/qosm/internal/db"
	"github.com/kakeetopius/qosm/internal/qos"
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
	qosManager, err := qos.NewManager()
	if err != nil {
		return err
	}
	defer qosManager.Close()

	if debug {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
		qosManager.WithLogger(logger)
	}

	err = qosManager.InitQoSClassifier(true)
	if err != nil {
		return err
	}

	dbConn, err := db.NewConn(appConfig.GetString("db.path"))
	if err != nil {
		return err
	}

	err = qosManager.InitSavedRules(dbConn)
	if err != nil {
		return err
	}

	err = qosManager.InitSavedInterfaceSettings(dbConn)
	if err != nil {
		return err
	}

	fmt.Println("Restore Done Successfully")

	return nil
}
