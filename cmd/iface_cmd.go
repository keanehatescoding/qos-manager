package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/kakeetopius/qosm/internal/core/nft"
	"github.com/kakeetopius/qosm/internal/db"
	"github.com/kakeetopius/qosm/internal/qos"
	"github.com/spf13/cobra"
)

func IfaceCmd() *cobra.Command {
	ifaceCmd := cobra.Command{
		Use:     "iface",
		Short:   "Manage traffic control settings for an interface.",
		Aliases: []string{"i"},
	}

	ifaceCmd.AddCommand(
		IfaceEnableCmd(),
		IfaceDisableCmd(),
		IfaceStats(),
		IfaceListCmd(),
	)
	return &ifaceCmd
}

func IfaceEnableCmd() *cobra.Command {
	ifaceEnableCmd := cobra.Command{
		Use:     "enable interfaces...",
		Short:   "Enable the htb qdisc on an interface(s)",
		Aliases: []string{"e"},
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dbConn, err := db.NewConn(appConfig.GetString("db.path"))
			if err != nil {
				return err
			}
			qosManager, err := qos.NewManager()
			if err != nil {
				return err
			}
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

			for _, iface := range args {
				dev, err := net.InterfaceByName(iface)
				if err != nil {
					return fmt.Errorf(" Interface %v -> %w", iface, err)
				}
				err = qosManager.EnableTcOnInterface(*dev, dbConn)
				if err != nil {
					return fmt.Errorf(" Interface %v -> %w", iface, err)
				}
				fmt.Printf("Successfully enabled HTB qdisc on interface: %v\n", iface)
			}

			return nil
		},
	}

	return &ifaceEnableCmd
}

func IfaceDisableCmd() *cobra.Command {
	ifaceDisableCmd := cobra.Command{
		Use:     "disable interfaces...",
		Short:   "Disable the htb qdisc from an interface(s)",
		Aliases: []string{"d"},
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dbCon, err := db.NewConn(appConfig.GetString("db.path"))
			if err != nil {
				return err
			}
			qosManager, err := qos.NewManager()
			if err != nil {
				return err
			}
			if debug {
				logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
					Level: slog.LevelDebug,
				}))
				qosManager.WithLogger(logger)
			}

			err = qosManager.InitQoSClassifier(false)
			if err != nil {
				if !errors.Is(err, nft.ErrTableNotFound) {
					return err
				}
			}

			for _, iface := range args {
				dev, err := net.InterfaceByName(iface)
				if err != nil {
					return fmt.Errorf(" Interface %v -> %w", iface, err)
				}
				err = qosManager.DisableTcOnInterface(*dev, dbCon)
				if err != nil {
					return fmt.Errorf(" Interface %v -> %w", iface, err)
				}
				fmt.Printf("Successfully disabled the HTB qdisc on interface: %v\n", iface)
			}

			return nil
		},
	}

	return &ifaceDisableCmd
}

func IfaceStats() *cobra.Command {
	ifaceAddCmd := cobra.Command{
		Use:     "stats <inteface>",
		Short:   "Get htb stats for an interface.",
		Aliases: []string{"s"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			qosManager, err := qos.NewManager()
			if err != nil {
				return err
			}
			if debug {
				logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
					Level: slog.LevelDebug,
				}))
				qosManager.WithLogger(logger)
			}

			err = qosManager.InitQoSClassifier(false)
			if err != nil {
				return err
			}
			iface := args[0]

			dev, err := net.InterfaceByName(iface)
			if err != nil {
				return err
			}
			stats, err := qosManager.Classifier.GetIfaceRuleStats(dev.Index)
			if err != nil {
				var errRuleNotFound nft.ErrRuleNotFound
				if errors.As(err, &errRuleNotFound) {
					return fmt.Errorf("interface %v is not initialised", iface)
				}
				return err
			}
			fmt.Println("High Priority")
			fmt.Println("Packet Count: ", stats.HighPrio.PacketCount)
			fmt.Println("Bytes Count: ", stats.HighPrio.ByteCount)
			fmt.Println("Low Priority")
			fmt.Println("Packet Count: ", stats.LowPrio.PacketCount)
			fmt.Println("Bytes Count: ", stats.LowPrio.ByteCount)

			return nil
		},
	}

	return &ifaceAddCmd
}

func IfaceListCmd() *cobra.Command {
	ifacelistCmd := cobra.Command{
		Use:     "list",
		Short:   "List htb enabled interfaces.",
		Aliases: []string{"l"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dbCon, err := db.NewConn(appConfig.GetString("db.path"))
			if err != nil {
				return err
			}
			enabledIfaces, err := db.GetEnabledInterfaces(dbCon)
			if err != nil {
				return err
			}
			if len(enabledIfaces) == 0 {
				fmt.Println("No htb enabled interfaces.")
				return nil
			}

			fmt.Println("Enabled Interfaces: ")
			for _, iface := range enabledIfaces {
				fmt.Println(iface.Name)
			}

			return nil
		},
	}

	return &ifacelistCmd
}
