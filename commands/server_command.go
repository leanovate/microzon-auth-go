package commands

import (
	"github.com/codegangsta/cli"
	"github.com/leanovate/microzon-auth-go/server"
	"github.com/leanovate/microzon-auth-go/store"
)

// Start in server mode
var ServerCommand = cli.Command{
	Name:   "server",
	Usage:  "Start server",
	Action: runWithContext(serverCommand),
}

func serverCommand(ctx *cli.Context, runCtx *runContext) {
	store, err := store.NewStore(runCtx.config.Store, runCtx.logger)
	if err != nil {
		runCtx.logger.ErrorErr(err)
		return
	}
	defer store.Close()

	server := server.NewServer(runCtx.config.Server, store, runCtx.logger)

	if err := server.Start(); err != nil {
		runCtx.logger.ErrorErr(err)
		return
	}
	defer server.Stop()

	runCtx.handleSignals()
}
