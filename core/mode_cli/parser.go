package mode_cli

import (
	"fmt"

	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/msrpc/core/utils"
)

// SetupSubParser registers the "cli" subcommand and its argument groups on ap, binding
// every flag to the caller-owned variable it parses into.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, host *string, transport *string, port *int, authDomain *string, authUsername *string, authPassword *string, authHashes *string) {
	subparser_cli := ap.AddSubParser("cli", "Open an interactive console to bind and fuzz RPC interfaces on the target.")

	// Connection Settings
	subparser_cli_group_connection, err := subparser_cli.NewArgumentGroup("Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_cli_group_connection.NewStringArgument(host, "", "--host", "", true, "Hostname or IP address of the target machine.")
		subparser_cli_group_connection.NewStringArgument(transport, "-t", "--transport", utils.TransportTCP, false, "Transport to reach the endpoint mapper: 'tcp' (ncacn_ip_tcp) or 'smb' (ncacn_np).")
		subparser_cli_group_connection.NewTcpPortArgument(port, "", "--port", 0, false, "Endpoint mapper port (default: 135 for tcp, 445 for smb).")
	}

	// Authentication
	subparser_cli_group_auth, err := subparser_cli.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_cli_group_auth.NewStringArgument(authDomain, "-d", "--domain", "", false, "Active Directory domain to authenticate to (smb transport).")
		subparser_cli_group_auth.NewStringArgument(authUsername, "-u", "--username", "", false, "User to authenticate as (smb transport).")
		subparser_cli_group_auth.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with (smb transport).")
		subparser_cli_group_auth.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash (smb transport).")
	}

	// Output
	subparser_cli_group_output, err := subparser_cli.NewArgumentGroup("Output")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_cli_group_output.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")
	}
}
