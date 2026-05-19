package cmd

import (
	"github.com/kakeetopius/qosm/internal/web"
	"github.com/spf13/cobra"
)

func WebCmd() *cobra.Command {
	webCmd := cobra.Command{
		Use:   "web",
		Short: "Manage web server and its configurations.",
	}

	webCmd.AddCommand(runWeb())

	return &webCmd
}

func runWeb() *cobra.Command {
	runCmd := cobra.Command{
		Use:   "run",
		Short: "Run the web server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return web.Run()
		},
	}

	return &runCmd
}
