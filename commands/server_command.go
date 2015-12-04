package commands

import (
	"github.com/codegangsta/cli"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/revocations"
	"github.com/leanovate/microzon-auth-go/server"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/leanovate/microzon-auth-go/tokens"
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

	revocations, err := revocations.NewRevocationsManager(store, runCtx.logger)
	if err != nil {
		runCtx.logger.ErrorErr(err)
		return
	}

	certificateManager := certificates.NewSignerCertificateManager(store, runCtx.config.Store, runCtx.logger)

	tokenManager := tokens.NewTokenManager(runCtx.config.Token, certificateManager, revocations, runCtx.logger)

	server := server.NewServer(runCtx.config.Server, store, certificateManager.CertificateManager, revocations, tokenManager, runCtx.logger)

	if err := server.Start(); err != nil {
		runCtx.logger.ErrorErr(err)
		return
	}
	defer server.Stop()

	runCtx.handleSignals()
}
