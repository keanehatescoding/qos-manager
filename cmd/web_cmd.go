package cmd

import (
	"fmt"

	"github.com/kakeetopius/qosm/cmd/web"
	"github.com/spf13/cobra"
)

func WebCmd() *cobra.Command {
	webCmd := cobra.Command{
		Use:   "web",
		Short: "Manage web server and its configurations.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Running web server.")
			return nil
		},
	}

	webCmd.AddCommand(web.RunCmd())

	return &webCmd
}
