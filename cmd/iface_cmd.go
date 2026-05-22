package cmd

import (
	"fmt"
	"net"

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
			fmt.Printf("Adding interfaces: %v\n", args)

			htbCtx, err := tc.NewHTBCtx()
			if err != nil {
				return err
			}
			defer htbCtx.Close()

			err = htbCtx.InitHTBFilter()
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
			fmt.Printf("Deleting interfaces: %v\n", args)
			htbCtx, err := tc.NewHTBCtx()
			if err != nil {
				return err
			}
			defer htbCtx.Close()

			err = htbCtx.InitHTBFilter()
			if err != nil {
				return err
			}

			for _, iface := range args {
				err = tc.FlushQdisc(iface)
				if err != nil {
					return err
				}

				dev, err := net.InterfaceByName(iface)
				if err != nil {
					return err
				}
				err = htbCtx.NFTFilter.DeleteIfaceRules(dev.Index)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	return &ifaceDeleteCmd
}
