package mode_cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	epmfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/pdu"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/tcp"
	"github.com/TheManticoreProject/Manticore/windows/guid"

	"github.com/TheManticoreProject/msrpc/core/utils"
)

// bindTimeout bounds the TCP connect and bind to a resolved endpoint so a dead port fails
// promptly during a fuzz loop.
const bindTimeout = 5 * time.Second

// maxOpnumScan caps the opnum fuzzing loop. Opnums are dense (0..N-1), so the scan stops
// at the first nca_s_op_rng_error; this cap is only a backstop for interfaces that never
// return one (e.g. when authentication is required and every call is denied before the
// opnum range is checked).
const maxOpnumScan = 256

// cmdBind handles "bind <uuid> <version>": it resolves the interface to an endpoint via
// the endpoint mapper, binds to it, and reports success or failure.
func (s *shell) cmdBind(args []string) {
	if len(args) != 2 {
		s.errorf("Usage: bind <uuid> <version>")
		return
	}
	ifaceUUID, major, minor, ok := s.parseInterface(args[0], args[1])
	if !ok {
		return
	}

	s.infof("Binding to <uuid=%s, version=%d.%d> ...", ifaceUUID.ToFormatD(), major, minor)
	endpoint, rpc, err := s.resolveAndBind(ifaceUUID, major, minor)
	if err != nil {
		s.printf("  └── \x1b[1;91mfail\x1b[0m: %s", err)
		return
	}
	rpc.Close()
	s.printf("  └── \x1b[1;92msuccess\x1b[0m (endpoint %s)", endpoint)
}

// cmdFuzz handles "fuzz <opnums|version> ...".
func (s *shell) cmdFuzz(args []string) {
	if len(args) == 0 {
		s.errorf("Usage: fuzz <opnums|version> ...")
		return
	}
	switch strings.ToLower(args[0]) {
	case "opnums":
		s.fuzzOpnums(args[1:])
	case "version":
		s.fuzzVersion(args[1:])
	default:
		s.errorf("Unknown fuzz subcommand %q (expected 'opnums' or 'version').", args[0])
	}
}

// fuzzOpnums handles "fuzz opnums <uuid> <version>": it resolves the interface endpoint
// once, then probes each opnum with an empty stub on a fresh binding. An
// nca_s_op_rng_error means the opnum is out of range (so, since opnums are dense, the scan
// ends there); any other outcome (a fault such as bad-stub-data or access-denied, or a
// response) means the opnum exists. A fresh binding per opnum keeps the scan robust against
// servers that drop the connection after a fault.
func (s *shell) fuzzOpnums(args []string) {
	if len(args) != 2 {
		s.errorf("Usage: fuzz opnums <uuid> <version>")
		return
	}
	ifaceUUID, major, minor, ok := s.parseInterface(args[0], args[1])
	if !ok {
		return
	}

	// Resolve the endpoint once via the endpoint mapper, then reuse the port.
	port, err := s.resolveEndpoint(ifaceUUID, major, minor)
	if err != nil {
		s.errorf("Bind failed: %s", err)
		return
	}
	endpoint := fmt.Sprintf("%s:%d", s.cfg.Connection.Host, port)
	s.infof("Fuzzing opnums on <uuid=%s, version=%d.%d> at %s ...", ifaceUUID.ToFormatD(), major, minor, endpoint)

	found := 0
	stoppedOnRange := false
	sawNonDenied := false
	for opnum := 0; opnum < maxOpnumScan; opnum++ {
		rpc, err := s.bindEndpoint(ifaceUUID, major, minor, port)
		if err != nil {
			s.errorf("Stopped at opnum %d: bind failed: %s", opnum, err)
			break
		}
		_, callErr := rpc.Call(uint16(opnum), nil)
		rpc.Close()

		if callErr == nil {
			// The call returned a response (a no-argument opnum), so it exists.
			s.printf("  ├── [%3d] \x1b[1;92mexists\x1b[0m", opnum)
			found++
			sawNonDenied = true
			continue
		}

		var fault *pdu.Fault
		if errors.As(callErr, &fault) {
			if fault.Status == pdu.NCASOpRngError {
				// Opnum out of range: opnums are contiguous, so nothing higher exists.
				stoppedOnRange = true
				break
			}
			// Dispatched but faulted (bad stub data, access denied, ...) => the opnum exists.
			s.printf("  ├── [%3d] \x1b[1;92mexists\x1b[0m (%s)", opnum, pdu.FaultStatus(fault.Status))
			found++
			if fault.Status != pdu.NCASFaultAccessDenied {
				sawNonDenied = true
			}
			continue
		}

		// A transport/decoding error is not a per-opnum signal; stop rather than spin.
		s.errorf("Stopped at opnum %d: %s", opnum, callErr)
		break
	}

	if !stoppedOnRange && found > 0 {
		if !sawNonDenied {
			s.errorf("Every opnum up to the scan cap (%d) was access-denied; the interface likely requires authentication, so the opnum count is unreliable.", maxOpnumScan)
		} else {
			s.errorf("Reached the opnum scan cap (%d) before an out-of-range response; the count may be incomplete.", maxOpnumScan)
		}
	}
	s.infof("Found %d opnums.", found)
}

// fuzzVersion handles "fuzz version <uuid> [min] [max]": for each version in [min, max] in
// steps of 0.1 (default 0 to 10), it resolves and binds the interface and reports the
// versions that exist. The endpoint mapper connection is opened once and reused.
func (s *shell) fuzzVersion(args []string) {
	if len(args) < 1 || len(args) > 3 {
		s.errorf("Usage: fuzz version <uuid> [min-version] [max-version]")
		return
	}
	ifaceUUID, err := guid.FromString(args[0])
	if err != nil {
		s.errorf("Invalid UUID %q: %s", args[0], err)
		return
	}

	// Versions are walked as tenths to avoid floating-point drift: 0.0 -> tenths 0,
	// 10.0 -> tenths 100, step 0.1 -> +1.
	minTenths, maxTenths := 0, 100
	if len(args) >= 2 {
		if minTenths, err = parseTenths(args[1]); err != nil {
			s.errorf("Invalid min-version %q: %s", args[1], err)
			return
		}
	}
	if len(args) >= 3 {
		if maxTenths, err = parseTenths(args[2]); err != nil {
			s.errorf("Invalid max-version %q: %s", args[2], err)
			return
		}
	}
	if minTenths > maxTenths {
		s.errorf("min-version (%.1f) is greater than max-version (%.1f).", float64(minTenths)/10, float64(maxTenths)/10)
		return
	}

	ept, cleanup, err := utils.ConnectEPM(s.cfg.Connection.Host, s.cfg.Connection.Port, s.cfg.Connection.Transport, s.cfg.Credentials, s.cfg.Debug)
	if err != nil {
		s.errorf("Endpoint mapper: %s", err)
		return
	}
	defer cleanup()

	s.infof("Fuzzing versions %.1f to %.1f (step 0.1) of <uuid=%s> ...", float64(minTenths)/10, float64(maxTenths)/10, ifaceUUID.ToFormatD())
	found := 0
	for tenths := minTenths; tenths <= maxTenths; tenths++ {
		major, minor := uint16(tenths/10), uint16(tenths%10)
		_, rpc, err := s.mapAndBind(ept, *ifaceUUID, major, minor)
		if err != nil {
			s.debugf("version %d.%d: %s", major, minor, err)
			continue
		}
		rpc.Close()
		s.printf("  ├── \x1b[1;92m[+]\x1b[0m version %d.%d exists", major, minor)
		found++
	}
	s.infof("Found %d versions.", found)
}

// parseInterface parses and validates a UUID string and an "M.m" version string, reporting
// the error to the shell and returning ok=false on failure.
func (s *shell) parseInterface(uuidArg, versionArg string) (ifaceUUID guid.GUID, major uint16, minor uint16, ok bool) {
	g, err := guid.FromString(uuidArg)
	if err != nil {
		s.errorf("Invalid UUID %q: %s", uuidArg, err)
		return guid.GUID{}, 0, 0, false
	}
	major, minor, err = parseVersion(versionArg)
	if err != nil {
		s.errorf("Invalid version %q: %s", versionArg, err)
		return guid.GUID{}, 0, 0, false
	}
	return *g, major, minor, true
}

// resolveAndBind opens an endpoint mapper connection, resolves the interface to an endpoint
// and binds to it, returning the bound client (the caller closes it) and the endpoint used.
func (s *shell) resolveAndBind(ifaceUUID guid.GUID, major, minor uint16) (string, *client.Client, error) {
	ept, cleanup, err := utils.ConnectEPM(s.cfg.Connection.Host, s.cfg.Connection.Port, s.cfg.Connection.Transport, s.cfg.Credentials, s.cfg.Debug)
	if err != nil {
		return "", nil, fmt.Errorf("endpoint mapper: %w", err)
	}
	defer cleanup()
	return s.mapAndBind(ept, ifaceUUID, major, minor)
}

// mapAndBind resolves the interface to a TCP endpoint via ept_map on the supplied endpoint
// mapper invoker, then connects to that port on the target host and binds the interface.
func (s *shell) mapAndBind(ept ndr.Invoker, ifaceUUID guid.GUID, major, minor uint16) (string, *client.Client, error) {
	port, err := mapEndpointFor(ept, ifaceUUID, major, minor)
	if err != nil {
		return "", nil, err
	}
	endpoint := fmt.Sprintf("%s:%d", s.cfg.Connection.Host, port)
	rpc, err := s.bindEndpoint(ifaceUUID, major, minor, port)
	if err != nil {
		return endpoint, nil, err
	}
	return endpoint, rpc, nil
}

// resolveEndpoint opens an endpoint mapper connection and returns the TCP port the
// interface is registered on, without binding. It is used by the opnum fuzzer, which then
// rebinds per opnum.
func (s *shell) resolveEndpoint(ifaceUUID guid.GUID, major, minor uint16) (int, error) {
	ept, cleanup, err := utils.ConnectEPM(s.cfg.Connection.Host, s.cfg.Connection.Port, s.cfg.Connection.Transport, s.cfg.Credentials, s.cfg.Debug)
	if err != nil {
		return 0, fmt.Errorf("endpoint mapper: %w", err)
	}
	defer cleanup()
	port, err := mapEndpointFor(ept, ifaceUUID, major, minor)
	if err != nil {
		return 0, err
	}
	return port, nil
}

// bindEndpoint connects to the resolved TCP port on the target host and binds the
// interface, returning the bound client (the caller closes it). It connects to the
// configured target host (not the tower's address, which a server may return as 0.0.0.0).
func (s *shell) bindEndpoint(ifaceUUID guid.GUID, major, minor uint16, port int) (*client.Client, error) {
	t := tcp.New(s.cfg.Connection.Host, port)
	t.SetTimeout(bindTimeout)
	rpc := client.NewClient(t)
	if err := rpc.Bind(syntax.SyntaxID{UUID: ifaceUUID, MajorVersion: major, MinorVersion: minor}); err != nil {
		rpc.Close()
		return nil, err
	}
	return rpc, nil
}

// mapEndpointFor resolves an interface to its first TCP endpoint port via ept_map.
func mapEndpointFor(ept ndr.Invoker, ifaceUUID guid.GUID, major, minor uint16) (int, error) {
	endpoints, err := epmfunctions.Map(ept, ifaceUUID, major, minor)
	if err != nil {
		return 0, fmt.Errorf("ept_map: %w", err)
	}
	if len(endpoints) == 0 {
		return 0, fmt.Errorf("interface is not registered with the endpoint mapper")
	}
	return int(endpoints[0].Port), nil
}

// parseVersion parses an interface version "M.m" (or bare "M") into major and minor.
func parseVersion(s string) (major uint16, minor uint16, err error) {
	s = strings.TrimSpace(s)
	majorStr, minorStr := s, "0"
	if i := strings.IndexByte(s, '.'); i >= 0 {
		majorStr, minorStr = s[:i], s[i+1:]
	}
	maj, err := strconv.ParseUint(majorStr, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("expected a version like 1.0")
	}
	min, err := strconv.ParseUint(minorStr, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("expected a version like 1.0")
	}
	return uint16(maj), uint16(min), nil
}

// parseTenths parses a version bound (e.g. "0", "10", "2.5") into tenths (0 -> 0, 10 -> 100,
// 2.5 -> 25), the unit the version fuzzing loop walks in.
func parseTenths(s string) (int, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("expected a number like 0, 10 or 2.5")
	}
	if f < 0 {
		return 0, fmt.Errorf("must not be negative")
	}
	// Round to the nearest tenth.
	return int(f*10 + 0.5), nil
}
