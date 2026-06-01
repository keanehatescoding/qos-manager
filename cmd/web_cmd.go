package cmd

import (
	"github.com/kakeetopius/qosm/web"
	"github.com/spf13/cobra"
)

func WebCmd() *cobra.Command {
	webCmd := cobra.Command{
		Use:   "web",
		Short: "Manage the web server and its configurations.",
	}

	webCmd.AddCommand(runWeb())

	webCmd.PersistentFlags().String("addr", "", "The IP address to listen on.(Default is all 0.0.0.0)")
	appConfig.BindPFlag("server.address", webCmd.PersistentFlags().Lookup("addr"))
	appConfig.SetDefault("server.address", "")

	webCmd.PersistentFlags().Int("port", 0, "The port to listen on.(Default is 9000)")
	appConfig.BindPFlag("server.port", webCmd.PersistentFlags().Lookup("port"))
	appConfig.SetDefault("server.port", 9000)

	return &webCmd
}

func runWeb() *cobra.Command {
	runCmd := cobra.Command{
		Use:   "run",
		Short: "Run the web server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return web.Run(web.ServerOptions{
				Addr:   appConfig.GetString("server.address"),
				Port:   appConfig.GetInt("server.port"),
				DBPath: appConfig.GetString("db.path"),
				Debug:  debug,
			})
		},
	}

	return &runCmd
}
