// Package cmd is used for command line parsing and configuration setup
package cmd

import (
	"fmt"
	"os"
	"os/user"
	"path"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	debug   bool

	appConfig *viper.Viper
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
	appConfig = viper.New()

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/config/qosm/qosm.toml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Run in debug mode")

	rootCmd.PersistentFlags().String("db-path", "", "The path to the database file")
	appConfig.BindPFlag("db.path", rootCmd.PersistentFlags().Lookup("db-path"))
	appConfig.SetDefault("db.path", "./qos.db")

	rootCmd.AddCommand(
		versionCmd(),
		WebCmd(),
		RuleCmd(),
		IfaceCmd(),
		RestoreCmd(),
	)
}

func initConfig() error {
	if cfgFile != "" {
		// Use config file from the flag.
		appConfig.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		configDir, err := configDir()
		if err != nil {
			return err
		}

		// Search config in config directory with name "qosm"
		appConfig.AddConfigPath(path.Join(configDir, "qosm"))

		appConfig.SetConfigName("qosm")
	}

	appConfig.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := appConfig.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// ignore error file not found
			return nil
		}
		return fmt.Errorf("error reading config file %v: %w", appConfig.ConfigFileUsed(), err)
	}

	if debug {
		fmt.Fprintln(os.Stderr, "Using config file:", appConfig.ConfigFileUsed())
		fmt.Fprintln(os.Stderr, "Using db file:", appConfig.GetString("db.path"))
	}

	return nil
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Short:   "Show the version",
		Aliases: []string{"v"},
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(qosVersion)
		},
	}
}

// configDir returns the user's configuration directory.
// When running as root, it resolves the original sudo user's home directory
// and returns its .config path. Otherwise, it uses the current user's config
// directory.
func configDir() (string, error) {
	home := ""
	if os.Geteuid() == 0 {
		// running as root
		sudoUser := os.Getenv("SUDO_USER")
		if sudoUser == "" {
			return "", fmt.Errorf("could not get sudo user variable")
		}
		u, err := user.Lookup(sudoUser)
		if err != nil {
			return "", err
		}
		home = u.HomeDir
		return path.Join(home, ".config"), nil
	} else {
		return os.UserConfigDir()
	}
}
