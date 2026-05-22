package cmd

import (
	"fmt"

	"github.com/kakeetopius/qosm/internal/core/tc"
	"github.com/kakeetopius/qosm/internal/core/util"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

// TODO: ifaces can be given more than one.
// qosm add iface -> add interface to system.
// qosm add target to priority -> add target to given priority.
// all interfaces use the same marks and ipsets

var iface string

func RuleCmd() *cobra.Command {
	ruleCmd := cobra.Command{
		Use:     "rule",
		Short:   "Manage the traffic control rules.",
		Aliases: []string{"r"},
	}

	ruleCmd.PersistentFlags().StringVarP(&iface, "iface", "i", "", "The network interface to use.")

	ruleCmd.AddCommand(
		RuleAddCmd(),
		RuleDeleteCmd(),
		RuleFlushCmd(),
		RuleListCmd(),
	)
	return &ruleCmd
}

func RuleAddCmd() *cobra.Command {
	var priority string
	ruleAddCmd := cobra.Command{
		Use:     "add <targets>",
		Short:   "Add a QoS rule.",
		Aliases: []string{"a"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Adding rule for these targets: %v\n", args[0])
			targets, _, err := util.TargetsFromStringWithDNSLookup(args[0])
			if err != nil {
				return err
			}

			var tcPriority tc.Priority

			switch priority {
			case "high":
				tcPriority = tc.PRIORITYHIGH
			case "low":
				tcPriority = tc.PRIORITYLOW
			default:
				return fmt.Errorf("unknown priority %v", priority)
			}

			htbCtx, err := tc.InitHTBQdisc(iface)
			if err != nil {
				return err
			}
			defer htbCtx.Close()

			err = htbCtx.InitHTBFilter()
			if err != nil {
				return err
			}
			err = htbCtx.AddRule(targets, tcPriority)
			if err != nil {
				return err
			}
			return nil
		},
	}

	ruleAddCmd.Flags().StringVarP(&priority, "priority", "p", "", "Priority for the given targets.")
	ruleAddCmd.MarkFlagRequired("priority")

	return &ruleAddCmd
}

func RuleDeleteCmd() *cobra.Command {
	var priority string
	ruleAddCmd := cobra.Command{
		Use:     "delete <targets>",
		Short:   "Delete a QoS rule.",
		Aliases: []string{"d"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Deleting rule for these targets: %v\n", args[0])
			targets, _, err := util.TargetsFromStringWithDNSLookup(args[0])
			if err != nil {
				return err
			}
			htbCtx, err := tc.InitHTBQdisc(iface)
			if err != nil {
				return err
			}
			err = htbCtx.InitHTBFilter()
			if err != nil {
				return err
			}

			switch priority {
			case "high":
				return htbCtx.NFTFilter.DeleteTargetFromHighPriority(targets)
			case "low":
				return htbCtx.NFTFilter.DeleteTargetFromLowPriority(targets)
			default:
				return fmt.Errorf("unknown priority %v", priority)
			}
		},
	}

	ruleAddCmd.Flags().StringVarP(&priority, "priority", "p", "", "Priority for the given targets.")
	ruleAddCmd.MarkFlagRequired("priority")

	return &ruleAddCmd
}

func RuleFlushCmd() *cobra.Command {
	ruleFlushCmd := cobra.Command{
		Use:     "flush",
		Short:   "Flush all qosm rules.",
		Aliases: []string{"f"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if iface == "" {
				return fmt.Errorf("please provide an interface")
			}
			return tc.FlushQdiscandFilters(iface)
		},
	}

	return &ruleFlushCmd
}

func RuleListCmd() *cobra.Command {
	ruleListCmd := cobra.Command{
		Use:     "list",
		Short:   "List qosm priority rules.",
		Aliases: []string{"l"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if iface == "" {
				return fmt.Errorf("please provide an interface")
			}

			htbCtx, err := tc.InitHTBQdisc(iface)
			if err != nil {
				return err
			}
			err = htbCtx.InitHTBFilter()
			if err != nil {
				return err
			}

			highPrioIPs, err := htbCtx.NFTFilter.GetHighPrioIPs()
			if err != nil {
				return err
			}
			lowPrioIPs, err := htbCtx.NFTFilter.GetLowPrioIPs()
			if err != nil {
				return err
			}

			highPrioTable := pterm.DefaultTable
			highPrioTableData := pterm.TableData{
				{"High Priority IPs"},
			}
			for _, ip := range highPrioIPs {
				highPrioTableData = append(highPrioTableData, []string{ip.String()})
			}

			lowPrioTable := pterm.DefaultTable
			lowPrioTableData := pterm.TableData{
				{"Low Priority IPs"},
			}
			for _, ip := range lowPrioIPs {
				lowPrioTableData = append(lowPrioTableData, []string{ip.String()})
			}

			if len(highPrioIPs) > 0 {
				highPrioTable.WithHasHeader(true).WithHeaderRowSeparator("-").WithBoxed(true).WithData(highPrioTableData).Render()
			}
			if len(lowPrioIPs) > 0 {
				lowPrioTable.WithHasHeader(true).WithHeaderRowSeparator("-").WithBoxed(true).WithData(lowPrioTableData).Render()
			}

			return nil
		},
	}

	return &ruleListCmd
}
