package mode_monitor

import (
	"fmt"

	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/msrpc/core/utils"
)

// SetupSubParser registers the "monitor" subcommand and its argument groups on ap, binding
// every flag to the caller-owned variable it parses into.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, host *string, transport *string, port *int, filter *string, interval *int, authDomain *string, authUsername *string, authPassword *string, authHashes *string) {
	subparser_monitor := ap.AddSubParser("monitor", "Watch the endpoint mapper on a refresh loop and report created/deleted RPC endpoints.")

	// Connection Settings
	subparser_monitor_group_connection, err := subparser_monitor.NewArgumentGroup("Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_monitor_group_connection.NewStringArgument(host, "", "--host", "", true, "Hostname or IP address of the target machine.")
		subparser_monitor_group_connection.NewStringArgument(transport, "-t", "--transport", utils.TransportTCP, false, "Transport to reach the endpoint mapper: 'tcp' (ncacn_ip_tcp) or 'smb' (ncacn_np).")
		subparser_monitor_group_connection.NewTcpPortArgument(port, "", "--port", 0, false, "Endpoint mapper port (default: 135 for tcp, 445 for smb).")
	}

	// Authentication
	subparser_monitor_group_auth, err := subparser_monitor.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_monitor_group_auth.NewStringArgument(authDomain, "-d", "--domain", "", false, "Active Directory domain to authenticate to (smb transport).")
		subparser_monitor_group_auth.NewStringArgument(authUsername, "-u", "--username", "", false, "User to authenticate as (smb transport).")
		subparser_monitor_group_auth.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with (smb transport).")
		subparser_monitor_group_auth.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash (smb transport).")
	}

	// Monitor options
	subparser_monitor_group_options, err := subparser_monitor.NewArgumentGroup("Monitor options")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_monitor_group_options.NewIntArgument(interval, "-i", "--interval", 1, false, "Seconds between endpoint-map snapshots.")
		subparser_monitor_group_options.NewStringArgument(filter, "-f", "--filter", "", false, "Keep only interfaces whose UUID, name, protocol or binding matches this case-insensitive substring.")
	}

	// Output
	subparser_monitor_group_output, err := subparser_monitor.NewArgumentGroup("Output")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_monitor_group_output.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")
	}
}
