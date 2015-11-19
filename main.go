package main

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/leanovate/microzon-auth-go/commands"
	"github.com/leanovate/microzon-auth-go/config"
)

func main() {
	app := cli.NewApp()
	app.Name = "microzon-auth"
	app.Usage = "Distributed authentication for microservices"
	app.Version = config.Version()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config-dir",
			Value: "/etc/microzon-auth.d",
			Usage: "config directory",
		},
		cli.StringFlag{
			Name:  "log-file",
			Value: "",
			Usage: "Log to file instead stdout",
		},
		cli.StringFlag{
			Name:  "log-format",
			Value: "text",
			Usage: "Log format to use (test, json, logstash)",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Enable debug logging",
		},
	}
	app.Commands = []cli.Command{
		commands.ServerCommand,
	}

	if err := app.Run(os.Args); err != nil {
		log.Errorf("Failed to run command: %s", err.Error())
	}
}
