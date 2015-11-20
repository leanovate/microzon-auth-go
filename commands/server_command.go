package commands

import (
	"github.com/codegangsta/cli"
	"github.com/leanovate/microzon-auth-go/server"
	"github.com/leanovate/microzon-auth-go/store/memory_backend"
)

// Start in server mode
var ServerCommand = cli.Command{
	Name:   "server",
	Usage:  "Start server",
	Action: runWithContext(serverCommand),
}

func serverCommand(ctx *cli.Context, runCtx *runContext) {
	store, err := memory_backend.NewMemoryStore(runCtx.logger)
	if err != nil {
		runCtx.logger.ErrorErr(err)
		return
	}

	runCtx.server = server.NewServer(runCtx.config.Server, store, runCtx.logger)

	if err := runCtx.server.Start(); err != nil {
		runCtx.logger.ErrorErr(err)
		return
	}

	runCtx.handleSignals()
}
