package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/kakeetopius/qosm/internal/core/nft"
	"github.com/kakeetopius/qosm/internal/core/tc"
	"github.com/spf13/cobra"
)

func IfaceCmd() *cobra.Command {
	ifaceCmd := cobra.Command{
		Use:     "iface",
		Short:   "Add or remove the qdisc from an interface",
		Aliases: []string{"i"},
	}

	ifaceCmd.AddCommand(
		IfaceAddCmd(),
		IfaceDeleteCmd(),
	)
	return &ifaceCmd
}

func IfaceAddCmd() *cobra.Command {
	ifaceAddCmd := cobra.Command{
		Use:     "add iface...",
		Short:   "Add the htb qdisc on an interface(s)",
		Aliases: []string{"a"},
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			htbCtx, err := tc.NewHTBCtx()
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

			for _, iface := range args {
				dev, err := net.InterfaceByName(iface)
				if err != nil {
					return err
				}
				err = htbCtx.InitHTBIface(iface)
				if err != nil {
					return err
				}
				err = htbCtx.NFTFilter.AddIfaceRules(dev.Index)
				if err != nil {
					return err
				}
			}

			fmt.Printf("Successfully added HTB qdisc on interfaces: \n")
			for _, arg := range args {
				fmt.Printf("%v\n", arg)
			}

			return nil
		},
	}

	return &ifaceAddCmd
}

func IfaceDeleteCmd() *cobra.Command {
	ifaceDeleteCmd := cobra.Command{
		Use:     "delete iface...",
		Short:   "Remove the htb qdisc from an interface(s)",
		Aliases: []string{"d"},
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			htbCtx, err := tc.NewHTBCtx()
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

			err = htbCtx.InitHTBFilter(false)
			nftTableFound := true
			if err != nil {
				if !errors.Is(err, nft.ErrTableNotFound) {
					return err
				}
				nftTableFound = false
			}

			for _, iface := range args {
				err = tc.FlushQdisc(iface)
				if err != nil {
					if errors.Is(err, tc.ErrQdiscNotFound) {
						return fmt.Errorf("htb qdisc not found on interface -> %v", iface)
					}
					return err
				}

				if nftTableFound {
					dev, err := net.InterfaceByName(iface)
					if err != nil {
						return err
					}
					err = htbCtx.NFTFilter.DeleteIfaceRules(dev.Index)
					if err != nil {
						return err
					}
				}
				fmt.Printf("Successfully deleted HTB qdisc on interface: %v\n", iface)
			}

			return nil
		},
	}

	return &ifaceDeleteCmd
}
