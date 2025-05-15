package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"lite/app"
	"lite/lite"
	"lite/pkg"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "lite",
	Short:   "A simple and powerful proxy protocol and tool",
	Version: app.Version,
	Run: func(cmd *cobra.Command, args []string) {
		b64Str, _ := cmd.Flags().GetString("base64")
		configFile, _ := cmd.Flags().GetString("config")
		var (
			cfg *app.Config
			err error
		)
		if b64Str != "" {
			var data []byte
			data, err = base64.StdEncoding.DecodeString(b64Str)
			if err == nil {
				cfg, err = app.ReadConfig(bytes.NewReader(data))
			}
		} else {
			if pkg.IsURL(configFile) {
				cfg, err = app.ReadConfigURL(configFile)
			} else {
				if configFile == "" {
					configFile = getDefaultConfigFile()
				}
				if configFile == "" {
					logger.Fatalln("No specified config file")
				}
				cfg, err = app.ReadConfigFile(configFile)
			}
		}
		if err != nil {
			logger.Fatalln(err)
		}
		logger2, close, err := buildLogger(cfg.Log)
		if err != nil {
			logger.Fatalln(err)
		}
		defer logger2.Sync()
		if close != nil {
			defer close()
		}
		app.SetLogger(logger2)
		instance, err := app.NewApp(cfg)
		if err != nil {
			logger2.Fatalln(err)
		}
		if err := instance.Start(context.Background()); err != nil {
			logger2.Fatalln(err)
		}
		logger2.Warnf("Current version %s", app.Version)
		if cfg.API != nil {
			logger2.Warnf("API server listening on %s", cfg.API.Listen)
		}
		instance.RangeInbound(func(inb *app.Inbound) bool {
			protocol, transport := inb.Info()
			if transport != "" {
				logger2.Warnf("Inbound <%s> using protocol %s and transport %s, listening on %s", inb.Tag,
					protocol, transport, inb.ListenAddr)
			} else {
				logger2.Warnf("Inbound <%s> using protocol %s, listening on %s", inb.Tag,
					protocol, inb.ListenAddr)
			}
			return true
		})
		instance.RangeOutbound(func(ob *app.Outbound) bool {
			protocol, transport := ob.Info()
			if ob.ServerAddr == nil {
				logger2.Infof("Outbound <%s> using protocol %s", ob.Tag, protocol)
			} else if transport != "" {
				logger2.Infof("Outbound <%s> using protocol %s and transport %s, connecting to %s",
					ob.Tag, protocol, transport, ob.ServerAddr)
			} else {
				logger2.Infof("Outbound <%s> using protocol %s, connecting to %s",
					ob.Tag, protocol, ob.ServerAddr)
			}
			return true
		})
		for _, inb := range cfg.Inbounds {
			if inb.Protocol == lite.Protocol {
				link, err := app.LiteInboundConfigToLink(inb)
				if err == nil {
					logger2.Infof("Inbound <%s> to link: %s", inb.Tag, link)
				}
			}
		}
		for _, ob := range cfg.Outbounds {
			if ob.Protocol == lite.Protocol {
				link, err := app.LiteOutboundConfigToLink(ob)
				if err == nil {
					logger2.Infof("Outbound <%s> to link: %s", ob.Tag, link)
				}
			}
		}
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt)
		<-ch
		logger2.Warnln("Exit signal received, closing...")
		instance.Close()
		logger2.Warnln("Exit finished")
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("base64", "b", "", "use base64 encoded string as config")
	rootCmd.Flags().StringP("config", "c", "", "config file or remote url")
	rootCmd.MarkFlagsMutuallyExclusive("base64", "config")
	cobra.MousetrapHelpText = ""
}
