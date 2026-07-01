package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/kakeetopius/qosm/internal/core/nft"
	"github.com/kakeetopius/qosm/internal/db"
	"github.com/kakeetopius/qosm/internal/qos"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

func RuleCmd() *cobra.Command {
	ruleCmd := cobra.Command{
		Use:     "rule",
		Short:   "Manage the traffic control rules.",
		Aliases: []string{"r"},
	}

	ruleCmd.AddCommand(
		RuleAddCmd(),
		RuleDeleteCmd(),
		RuleFlushCmd(),
		RuleListCmd(),
		RuleRefreshCmd(),
	)
	return &ruleCmd
}

func RuleAddCmd() *cobra.Command {
	var priority string
	var ruleType string
	ruleAddCmd := cobra.Command{
		Use:     "add <targets>",
		Short:   "Add a QoS rule.",
		Aliases: []string{"a"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			defer dbConn.Close()

			switch ruleType {
			case "ip":
				_, err = qosManager.AddIPRule(dbConn, args[0], priority)
			case "domain":
				_, err = qosManager.AddDomainRule(dbConn, args[0], priority)
			default:
				err = fmt.Errorf("unknown rule type: %s", ruleType)
			}
			if err != nil {
				return err
			}

			fmt.Printf("Rule for %v added successfully\n", args[0])
			return nil
		},
	}

	ruleAddCmd.Flags().StringVarP(&priority, "priority", "p", "", "Priority for the given targets.")
	ruleAddCmd.MarkFlagRequired("priority")
	ruleAddCmd.Flags().StringVarP(&ruleType, "type", "t", "ip", "The type of the target i.e. ip or domain")

	return &ruleAddCmd
}

func RuleDeleteCmd() *cobra.Command {
	var ruleType string
	ruleDeleteCmd := cobra.Command{
		Use:     "delete <targets>",
		Short:   "Delete a QoS rule.",
		Aliases: []string{"d"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			err = qosManager.InitQoSClassifier(false)
			if err != nil {
				if errors.Is(err, nft.ErrTableNotFound) {
					return fmt.Errorf(" No tc rules added yet by qosm ")
				}
				return err
			}

			dbConn, err := db.NewConn(appConfig.GetString("db.path"))
			if err != nil {
				return err
			}
			defer dbConn.Close()

			switch ruleType {
			case "domain":
				err = qosManager.DeleteDomainRuleByName(dbConn, args[0])
			case "ip":
				err = qosManager.DeleteIPRuleByName(dbConn, args[0])
			default:
				err = fmt.Errorf("unknown rule type: %s", ruleType)
			}

			if err != nil {
				return err
			}

			fmt.Printf("Rule for %v deleted successfully\n", args[0])
			return nil
		},
	}

	ruleDeleteCmd.Flags().StringVarP(&ruleType, "type", "t", "ip", "The type of the target i.e. ip or domain")

	return &ruleDeleteCmd
}

func RuleFlushCmd() *cobra.Command {
	ruleFlushCmd := cobra.Command{
		Use:     "flush",
		Short:   "Flush all QoS rules.",
		Aliases: []string{"f"},
		RunE: func(cmd *cobra.Command, args []string) error {
			qosManager, err := qos.NewManager()
			if err != nil {
				return err
			}
			defer qosManager.Close()

			dbConn, err := db.NewConn(appConfig.GetString("db.path"))
			if err != nil {
				return err
			}
			defer dbConn.Close()

			err = qosManager.DeleteAllRules(dbConn)
			if err != nil {
				return err
			}
			fmt.Println("Rules flushed successfully.")
			return nil
		},
	}

	return &ruleFlushCmd
}

func RuleListCmd() *cobra.Command {
	ruleListCmd := cobra.Command{
		Use:     "list",
		Short:   "List all QoS rules.",
		Aliases: []string{"l"},
		RunE: func(cmd *cobra.Command, args []string) error {
			dbConn, err := db.NewConn(appConfig.GetString("db.path"))
			if err != nil {
				return err
			}
			defer dbConn.Close()

			qosManger, err := qos.NewManager()
			if err != nil {
				return err
			}
			defer qosManger.Close()

			highPrio, err := qosManger.GetHighPriority(dbConn)
			if err != nil {
				return err
			}
			lowPrio, err := qosManger.GetLowPriority(dbConn)
			if err != nil {
				return err
			}

			highPrioTable := pterm.DefaultTable
			highPrioTableData := pterm.TableData{
				{"ID", "Type", "Target", "Created At"},
			}
			for _, rule := range highPrio {
				highPrioTableData = append(highPrioTableData, []string{fmt.Sprintf("%v", rule.ID), rule.Type, rule.Target, rule.CreatedAt.String()})
			}

			lowPrioTable := pterm.DefaultTable
			lowPrioTableData := pterm.TableData{
				{"ID", "Type", "Target", "Created At"},
			}
			for _, rule := range lowPrio {
				lowPrioTableData = append(lowPrioTableData, []string{fmt.Sprintf("%v", rule.ID), rule.Type, rule.Target, rule.CreatedAt.String()})
			}

			if len(highPrio) > 0 {
				fmt.Println("High Priority Rules")
				highPrioTable.WithHasHeader(true).WithHeaderRowSeparator("-").WithBoxed(true).WithData(highPrioTableData).Render()
			}
			if len(lowPrio) > 0 {
				fmt.Println("Low Priority Rules")
				lowPrioTable.WithHasHeader(true).WithHeaderRowSeparator("-").WithBoxed(true).WithData(lowPrioTableData).Render()
			}

			return nil
		},
	}

	return &ruleListCmd
}

func RuleRefreshCmd() *cobra.Command {
	ruleRefresh := cobra.Command{
		Use:     "refresh-dns",
		Short:   "Refresh dns mappings for stored domain rules.",
		Aliases: []string{"r"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Refreshing Domains..................")
			dbCon, err := db.NewConn(appConfig.GetString("db.path"))
			if err != nil {
				return err
			}
			defer dbCon.Close()

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

			err = qosManager.InitQoSClassifier(false)
			if err != nil {
				if errors.Is(err, nft.ErrTableNotFound) {
					return fmt.Errorf(" No tc rules added yet by qosm ")
				}
				return err
			}

			err = qosManager.RefreshAllDomains(dbCon)
			if err != nil {
				return err
			}
			fmt.Println("Refresh Successfully Completed")
			return nil
		},
	}

	return &ruleRefresh
}
