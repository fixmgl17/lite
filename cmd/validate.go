package cmd

import (
	"lite/app"
	"lite/pkg"

	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate config file",
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		var (
			cfg *app.Config
			err error
		)
		if pkg.IsURL(configFile) {
			logger.Infoln("Read config from remote url")
			cfg, err = app.ReadConfigURL(configFile)
		} else {
			if configFile == "" {
				configFile = getDefaultConfigFile()
				if configFile != "" {
					logger.Infof("Automatically detected config file %s", configFile)
				} else {
					logger.Fatalln("No specified config file")
				}
			}
			cfg, err = app.ReadConfigFile(configFile)
		}
		if err != nil {
			logger.Fatalln(err)
		}
		_, err = app.NewApp(cfg)
		if err != nil {
			logger.Fatalln(err)
		}
		logger.Infoln("Validate success, but maybe occur some error when running")
	},
}

func init() {
	validateCmd.Flags().StringP("config", "c", "", "config file")
	rootCmd.AddCommand(validateCmd)
}
