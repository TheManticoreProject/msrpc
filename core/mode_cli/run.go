// Package mode_cli implements the "cli" mode: an interactive console, in the style of
// smbclient-ng, for probing the RPC interfaces of a target. From the prompt the operator
// can bind to an interface and fuzz its opnums or its interface version range. Endpoints
// are resolved automatically through the target's endpoint mapper (ept_map), so only the
// interface UUID and version are needed.
package mode_cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"

	"github.com/TheManticoreProject/msrpc/config"
	"github.com/TheManticoreProject/msrpc/core/utils"
)

// shell is the interactive REPL state. It holds the target configuration; each command
// opens its own short-lived connections to the endpoint mapper and the resolved endpoint,
// so there is no long-lived session to keep alive between commands.
type shell struct {
	cfg     config.Config
	running bool
}

// Run opens the interactive console for the configured target and drives the REPL until
// the operator exits (via the "exit" command, Ctrl-D, or Ctrl-C on an empty line).
//
// Parameters:
// - config: The configuration of the application.
func Run(config config.Config) error {
	return (&shell{cfg: config}).run()
}

func (s *shell) run() error {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:            s.prompt(),
		HistoryFile:       filepath.Join(os.TempDir(), ".msrpc_history"),
		AutoComplete:      completer(),
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	})
	if err != nil {
		return fmt.Errorf("error initializing interactive shell: %s", err)
	}
	defer rl.Close()

	s.banner()

	s.running = true
	for s.running {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			// Ctrl-C clears a non-empty line; on an empty line it exits.
			if len(line) == 0 {
				break
			}
			continue
		} else if err == io.EOF {
			// Ctrl-D closes the shell.
			break
		}

		tokens := tokenize(line)
		if len(tokens) == 0 {
			continue
		}
		s.dispatch(tokens)
	}
	return nil
}

// dispatch routes a tokenized command line to its handler.
func (s *shell) dispatch(tokens []string) {
	switch strings.ToLower(tokens[0]) {
	case "help", "?":
		s.cmdHelp()
	case "info":
		s.cmdInfo()
	case "bind":
		s.cmdBind(tokens[1:])
	case "fuzz":
		s.cmdFuzz(tokens[1:])
	case "exit", "quit":
		s.running = false
	default:
		s.errorf("Unknown command %q. Type \"help\" for help.", tokens[0])
	}
}

// completer provides TAB completion for the command names and the fuzz subcommands.
func completer() *readline.PrefixCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("bind"),
		readline.PcItem("fuzz",
			readline.PcItem("opnums"),
			readline.PcItem("version"),
		),
		readline.PcItem("info"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
}

// prompt renders the interactive prompt: a green connection dot then the target in blue.
func (s *shell) prompt() string {
	return fmt.Sprintf("\x1b[1;92m■\x1b[0m[\x1b[1;94mmsrpc://%s\x1b[0m]> ", s.cfg.Connection.Host)
}

// banner prints the welcome line and a hint to type help.
func (s *shell) banner() {
	port := utils.DefaultPort(s.cfg.Connection.Transport, s.cfg.Connection.Port)
	s.printf("[>] Interactive RPC console on \x1b[1;94m%s:%d\x1b[0m (%s). Type \"help\" for commands, \"exit\" to quit.", s.cfg.Connection.Host, port, s.cfg.Connection.Transport)
}

// cmdHelp prints the available commands.
func (s *shell) cmdHelp() {
	s.print("Available commands:")
	s.print("  bind <uuid> <version>                       Bind to an interface and report whether it answers.")
	s.print("  fuzz opnums <uuid> <version>                Enumerate the valid opnums of an interface.")
	s.print("  fuzz version <uuid> [min] [max]             Find which interface versions exist (default 0 to 10, step 0.1).")
	s.print("  info                                        Show the current target.")
	s.print("  help                                        Show this help.")
	s.print("  exit                                        Leave the console.")
}

// cmdInfo prints the current target settings.
func (s *shell) cmdInfo() {
	port := utils.DefaultPort(s.cfg.Connection.Transport, s.cfg.Connection.Port)
	s.infof("Target    : %s:%d", s.cfg.Connection.Host, port)
	s.infof("Transport : %s", s.cfg.Connection.Transport)
	if s.cfg.Credentials != nil && s.cfg.Credentials.Username != "" {
		s.infof("Identity  : %s\\%s", s.cfg.Credentials.Domain, s.cfg.Credentials.Username)
	}
}

// --- output helpers (mirroring the smbclient-ng shell palette) -----------------------

func (s *shell) print(message string) { fmt.Println(message) }

func (s *shell) printf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

func (s *shell) info(message string) {
	fmt.Printf("[\x1b[1;92minfo\x1b[0m] %s\n", message)
}

func (s *shell) infof(format string, args ...interface{}) {
	s.info(fmt.Sprintf(format, args...))
}

func (s *shell) errorf(format string, args ...interface{}) {
	fmt.Printf("[\x1b[1;91merror\x1b[0m] %s\n", fmt.Sprintf(format, args...))
}

func (s *shell) debugf(format string, args ...interface{}) {
	if s.cfg.Debug {
		fmt.Printf("[debug] %s\n", fmt.Sprintf(format, args...))
	}
}

// tokenize splits a command line into tokens, honoring double quotes so an argument can
// contain spaces.
func tokenize(line string) []string {
	line = strings.TrimRight(line, "\r\n")

	tokens := []string{}
	var current strings.Builder
	inQuotes := false
	hasToken := false

	flush := func() {
		if hasToken {
			tokens = append(tokens, current.String())
			current.Reset()
			hasToken = false
		}
	}

	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			hasToken = true
		case (r == ' ' || r == '\t') && !inQuotes:
			flush()
		default:
			current.WriteRune(r)
			hasToken = true
		}
	}
	flush()
	return tokens
}
