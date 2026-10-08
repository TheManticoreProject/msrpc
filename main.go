package main

// msrpc - MS-RPC / DCE-RPC reconnaissance over the endpoint mapper, behind one
// protocol-noun binary with verb subcommands:
//
//	msrpc dump [options]   # enumerate ALL registered RPC endpoints
//
// main.go only declares the flag variables, lets each mode register its sub-parser,
// builds the shared config and dispatches to the matching mode's Run function.

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/msrpc/config"
	"github.com/TheManticoreProject/msrpc/core/mode_cli"
	"github.com/TheManticoreProject/msrpc/core/mode_dump"
	"github.com/TheManticoreProject/msrpc/core/mode_monitor"
)

var (
	// mode is the first positional argument (e.g. "dump"), filled by SetupSubParsing.
	mode string

	// Configuration
	debug  bool
	asJSON bool

	// Connection Settings
	host      string
	transport string
	port      int

	// Authentication (used when --transport smb)
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string

	// dump / monitor modes
	filter          string
	monitorInterval int
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "msrpc - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0",
	}
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)
	ap.SetupSubParsing("mode", &mode, true)

	// dump =====================================================================================
	mode_dump.SetupSubParser(&ap, &debug, &host, &transport, &port, &filter, &asJSON, &authDomain, &authUsername, &authPassword, &authHashes)
	// monitor ==================================================================================
	mode_monitor.SetupSubParser(&ap, &debug, &host, &transport, &port, &filter, &monitorInterval, &authDomain, &authUsername, &authPassword, &authHashes)
	// cli ======================================================================================
	mode_cli.SetupSubParser(&ap, &debug, &host, &transport, &port, &authDomain, &authUsername, &authPassword, &authHashes)

	ap.Parse()
}

func main() {
	parseArgs()

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating credentials: %s", err))
		return
	}

	cfg := config.Config{
		Debug:       debug,
		Credentials: creds,
		Connection: config.Connection{
			Host:      host,
			Port:      port,
			Transport: transport,
		},
	}

	switch mode {
	case "dump":
		if err := mode_dump.Run(filter, asJSON, cfg); err != nil {
			logger.Warn(fmt.Sprintf("Error in dump mode: %s", err))
		}

	case "monitor":
		if err := mode_monitor.Run(filter, monitorInterval, cfg); err != nil {
			logger.Warn(fmt.Sprintf("Error in monitor mode: %s", err))
		}

	case "cli":
		if err := mode_cli.Run(cfg); err != nil {
			logger.Warn(fmt.Sprintf("Error in cli mode: %s", err))
		}

	default:
		logger.Warn(fmt.Sprintf("Invalid mode '%s'.", mode))
	}

	logger.Print("Done.")
}
