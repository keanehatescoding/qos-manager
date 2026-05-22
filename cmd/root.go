// Package cmd is used for command line parsing and configuration setup
package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	debug   bool
)

var qosVersion = "qosm v0.0.1"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:          "qosm",
	Short:        "A quality of service manager.",
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initConfig()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/config/qosm/qosm.toml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Run in debug mode")

	rootCmd.AddCommand(
		versionCmd(),
		WebCmd(),
		RuleCmd(),
		IfaceCmd(),
	)
}

func initConfig() error {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		configDir, err := os.UserConfigDir()
		if err != nil {
			return err
		}

		// Search config in home directory with name "qosm" (without extension).
		viper.AddConfigPath(path.Join(configDir, "qosm"))

		viper.SetConfigName("qosm")
		viper.SetConfigType("toml")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// ignore error file not found
			return nil
		}
		return fmt.Errorf("error reading config file %v: %w", viper.ConfigFileUsed(), err)
	}
	if debug {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	return nil
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Get the version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(qosVersion)
		},
	}
}
