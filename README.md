![](./.github/banner.png)

<p align="center">
      Enumerate, monitor, and fuzz MS-RPC interfaces through a target's endpoint mapper.
      <br>
      <a href="https://github.com/TheManticoreProject/msrpc/actions/workflows/release.yaml" title="Build"><img alt="Build and Release" src="https://github.com/TheManticoreProject/msrpc/actions/workflows/release.yaml/badge.svg"></a>
      <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/TheManticoreProject/msrpc">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/TheManticoreProject/msrpc">
      <br>
</p>

`msrpc` consolidates MS-RPC / DCE-RPC reconnaissance behind a single protocol-noun
binary with verb subcommands over a shared connection/auth core.

## Features

- [x] `dump` - enumerate **all** RPC endpoints registered with a target's endpoint
      mapper (EPM), grouped by interface.
- [x] `monitor` - watch the endpoint mapper on a refresh loop and report endpoints as
      they are created and deleted, with timestamps.
- [x] `cli` - interactive console to `bind` an interface and `fuzz` its opnums or its
      interface version range, resolving endpoints automatically via the endpoint mapper.
- [x] Two transports to reach the endpoint mapper: `ncacn_ip_tcp` (TCP/135, usually
      unauthenticated) and `ncacn_np` (`\pipe\epmapper` over SMB/445, authenticated).
- [x] Resolves well-known interface UUIDs to service names (e.g. MS-SAMR, MS-SCMR,
      MS-SRVS) using the framework's interface catalog.
- [x] Human-readable tree output and a machine-readable `--json` mode.

## Usage

The first positional argument is the mode. Running the tool with no mode prints the
list of available modes:

```
$ ./msrpc
msrpc - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: msrpc <cli|dump|monitor>

   cli      Open an interactive console to bind and fuzz RPC interfaces on the target.
   dump     Enumerate all RPC endpoints registered with the target's endpoint mapper.
   monitor  Watch the endpoint mapper on a refresh loop and report created/deleted RPC endpoints.
```

### `dump`

Enumerate every endpoint the target's endpoint mapper has registered. Over the default
TCP transport the endpoint mapper is typically reachable unauthenticated:

```
$ ./msrpc dump --host 10.0.0.5
```

Over the SMB named-pipe transport an authenticated session to `IPC$` is required:

```
$ ./msrpc dump --host 10.0.0.5 --transport smb -d MANTICORE -u jdoe -p 'Passw0rd!'
$ ./msrpc dump --host 10.0.0.5 --transport smb -d MANTICORE -u jdoe -H :a1b2c3...
```

Filter the results to a single interface or service, and/or emit JSON:

```
$ ./msrpc dump --host 10.0.0.5 --filter spoolss
$ ./msrpc dump --host 10.0.0.5 --json
```

Options:

```
Usage: msrpc dump --host <string> [--transport <string>] [--port <tcp port>] [--filter <string>] [--json] [--debug] [-d <string>] [-u <string>] [-p <string>] [-H <string>]

  Connection Settings:
    --host <string>          Hostname or IP address of the target machine.
    -t, --transport <string> Transport to reach the endpoint mapper: 'tcp' (ncacn_ip_tcp) or 'smb' (ncacn_np). (default: "tcp")
    --port <tcp port>        Endpoint mapper port (default: 135 for tcp, 445 for smb).

  Authentication:
    -d, --domain <string>   Active Directory domain to authenticate to (smb transport).
    -u, --username <string> User to authenticate as (smb transport).
    -p, --password <string> Password to authenticate with (smb transport).
    -H, --hashes <string>   NT/LM hashes, format is LMhash:NThash (smb transport).

  Dump options:
    -f, --filter <string>   Keep only interfaces whose UUID, name, protocol or binding matches this case-insensitive substring.

  Output:
    --json     Emit JSON instead of the tree view.
    --debug    Enable debug mode.
```

### `monitor`

Watch the endpoint mapper on a refresh loop and report endpoints as they appear and
disappear. The current registrations form the baseline (they are not printed); from then
on, only changes are shown - a yellow timestamp followed by `Endpoint was created` (green)
or `Endpoint was deleted` (red). Steady-state endpoints stay silent. Press `Ctrl-C` to
stop.

```
$ ./msrpc monitor --host 10.0.0.5
$ ./msrpc monitor --host 10.0.0.5 --interval 5 --filter spoolss
$ ./msrpc monitor --host 10.0.0.5 --transport smb -d MANTICORE -u jdoe -p 'Passw0rd!'
```

```
[>] Monitoring RPC endpoints on 10.0.0.5 every 1s (baseline: 514 endpoints). Press Ctrl-C to stop.
[2026-06-16 19h22m51s] Endpoint was created: spoolss 12345678-1234-abcd-ef00-0123456789ab v1.0: ncacn_ip_tcp:10.0.0.5[49680] (MS-RPRN - Print System Remote Protocol)
[2026-06-16 19h23m07s] Endpoint was deleted: spoolss 12345678-1234-abcd-ef00-0123456789ab v1.0: ncacn_ip_tcp:10.0.0.5[49680] (MS-RPRN - Print System Remote Protocol)
```

Extra options:

```
  Monitor options:
    -i, --interval <int>    Seconds between endpoint-map snapshots. (default: 1)
    -f, --filter <string>   Keep only interfaces whose UUID, name, protocol or binding matches this case-insensitive substring.
```

### `cli`

Open an interactive console against the target. Endpoints are resolved automatically
through the endpoint mapper, so commands take only an interface UUID and version:

```
$ ./msrpc cli --host 10.0.0.5
■[msrpc://10.0.0.5]> help
Available commands:
  bind <uuid> <version>                       Bind to an interface and report whether it answers.
  fuzz opnums <uuid> <version>                Enumerate the valid opnums of an interface.
  fuzz version <uuid> [min] [max]             Find which interface versions exist (default 0 to 10, step 0.1).
  info                                        Show the current target.
  help                                        Show this help.
  exit                                        Leave the console.
```

- `bind <uuid> <version>` resolves the interface via `ept_map`, connects to the resolved
  endpoint and performs a DCE/RPC bind, reporting success or failure.
- `fuzz opnums <uuid> <version>` probes each opnum with an empty stub on a fresh binding:
  `nca_s_op_rng_error` marks the end of the opnum range, any other fault (or a response)
  means the opnum exists.
- `fuzz version <uuid> [min] [max]` walks the version range (default `0` to `10` in steps
  of `0.1`) and reports which versions exist.

> Note: opnum probing is most precise against an authenticated session. Over an
> unauthenticated bind, interfaces that require authentication answer every call with
> `nca_s_fault_access_denied` (which masks the opnum-range signal)

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## Credits

- [Podalirius](https://github.com/p0dalirius) for the original idea and implementation.
