// Package web is used to manage the web server.
package web

import (
	"fmt"

	"github.com/spf13/cobra"
)

func RunCmd() *cobra.Command {
	runCmd := cobra.Command{
		Use:   "run",
		Short: "Run the web server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Running the web server.")
			return nil
		},
	}

	return &runCmd
}
