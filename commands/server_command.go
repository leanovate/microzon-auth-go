package commands

import (
	"github.com/codegangsta/cli"
	"github.com/leanovate/microzon-auth-go/server"
)

// Start in server mode
var ServerCommand = cli.Command{
	Name:   "server",
	Usage:  "Start server",
	Action: runWithContext(serverCommand),
}

func serverCommand(ctx *cli.Context, runCtx *runContext) {
	runCtx.server = server.NewServer(runCtx.config.Server, runCtx.logger)

	if err := runCtx.server.Start(); err != nil {
		runCtx.logger.ErrorErr(err)
		return
	}

	runCtx.handleSignals()
}