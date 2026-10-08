// Package mode_dump implements the "dump" mode: it enumerates every RPC endpoint
// registered with the target's endpoint mapper (ept_lookup) and renders them grouped by
// interface, resolving well-known interface UUIDs to service names. It is the analogue of
// the classic rpcdump utility.
package mode_dump

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/catalog"
	epmfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0/structures"
	"github.com/TheManticoreProject/Manticore/windows/guid"

	"github.com/TheManticoreProject/msrpc/config"
	"github.com/TheManticoreProject/msrpc/core/utils"
)

// Binding is a single registration of an interface: where it can be reached and any
// annotation the endpoint mapper stored with it.
type Binding struct {
	StringBinding string `json:"binding"`              // e.g. "ncacn_ip_tcp:10.0.0.1[49664]" or "ncacn_np:HOST[\\PIPE\\srvsvc]"
	Annotation    string `json:"annotation,omitempty"` // human label, e.g. "Messenger Service"
	ObjectUUID    string `json:"object_uuid,omitempty"`
}

// Interface groups every endpoint registered for one interface UUID + version, with the
// catalog metadata resolved for it.
type Interface struct {
	UUID     string    `json:"interface_uuid"`
	Version  string    `json:"version"` // "major.minor"
	Name     string    `json:"name,omitempty"`
	Title    string    `json:"title,omitempty"`
	Protocol string    `json:"protocol,omitempty"`
	Bindings []Binding `json:"bindings"`
}

// Run enumerates the target's registered RPC endpoints and prints them, either as a tree
// grouped by interface or, when asJSON is set, as a stable JSON document.
//
// Parameters:
// - filter: A case-insensitive substring to filter interfaces by, or "" for all.
// - asJSON: Whether to emit JSON instead of the tree view.
// - config: The configuration of the application.
func Run(filter string, asJSON bool, config config.Config) error {
	interfaces, err := Collect(filter, config)
	if err != nil {
		return err
	}

	if asJSON {
		return printJSON(interfaces)
	}
	printTree(config.Connection.Host, interfaces)
	return nil
}

// Collect connects to the endpoint mapper, enumerates the whole endpoint map and returns
// the registered endpoints grouped by interface. It is factored out of Run so other modes
// (e.g. a monitor loop) can reuse the same enumeration.
//
// Parameters:
// - filter: A case-insensitive substring to filter interfaces by, or "" for all.
// - config: The configuration of the application.
func Collect(filter string, config config.Config) ([]Interface, error) {
	rpc, cleanup, err := utils.ConnectEPM(config.Connection.Host, config.Connection.Port, config.Connection.Transport, config.Credentials, config.Debug)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	entries, err := epmfunctions.Lookup(rpc)
	if err != nil {
		return nil, fmt.Errorf("error enumerating endpoints: %s", err)
	}

	return group(entries, filter, config.Debug), nil
}

// group decodes each endpoint-map entry into a (interface, binding) pair, resolves the
// interface metadata from the catalog and folds the bindings together by interface. A
// non-empty filter keeps only interfaces whose UUID, name, title, protocol or any binding
// matches the case-insensitive substring.
func group(entries []structures.EptEntry, filter string, debug bool) []Interface {
	filter = strings.ToLower(strings.TrimSpace(filter))

	// byKey accumulates bindings per interface; order preserves first-seen interfaces.
	type ifaceKey struct {
		uuid         string
		major, minor uint16
	}
	byKey := map[ifaceKey]*Interface{}
	var order []ifaceKey

	for _, entry := range entries {
		tower, err := entry.DecodeTower()
		if err != nil {
			if debug {
				logger.Debug(fmt.Sprintf("Skipping entry with undecodable tower: %s", err))
			}
			continue
		}

		ifaceUUID, major, minor, ok := interfaceID(tower)
		if !ok {
			if debug {
				logger.Debug("Skipping tower with no interface-identifier floor")
			}
			continue
		}

		binding := Binding{Annotation: string(entry.Annotation)}
		if decoded, err := tower.Binding(); err == nil {
			binding.StringBinding = decoded.String()
		} else if debug {
			logger.Debug(fmt.Sprintf("Tower for %s has no decodable binding: %s", ifaceUUID.ToFormatD(), err))
		}
		if object := entry.Object.GUID(); !isZeroGUID(object) {
			binding.ObjectUUID = object.ToFormatD()
		}

		key := ifaceKey{uuid: ifaceUUID.ToFormatD(), major: major, minor: minor}
		iface, seen := byKey[key]
		if !seen {
			iface = newInterface(ifaceUUID, major, minor)
			byKey[key] = iface
			order = append(order, key)
		}
		iface.Bindings = append(iface.Bindings, binding)
	}

	interfaces := make([]Interface, 0, len(order))
	for _, key := range order {
		iface := byKey[key]
		if filter != "" && !matchesInterface(*iface, filter) {
			continue
		}
		interfaces = append(interfaces, *iface)
	}

	// Named interfaces first (alphabetically), then the unnamed ones by UUID.
	sort.SliceStable(interfaces, func(i, j int) bool {
		nameI, nameJ := interfaces[i].Name, interfaces[j].Name
		if (nameI == "") != (nameJ == "") {
			return nameI != ""
		}
		if nameI != nameJ {
			return nameI < nameJ
		}
		return interfaces[i].UUID < interfaces[j].UUID
	})
	return interfaces
}

// newInterface builds an Interface with catalog metadata resolved for the given UUID and
// version. Unknown interfaces get an empty Name/Title/Protocol.
func newInterface(ifaceUUID guid.GUID, major, minor uint16) *Interface {
	iface := &Interface{
		UUID:    ifaceUUID.ToFormatD(),
		Version: fmt.Sprintf("%d.%d", major, minor),
	}
	if entry, ok := catalog.Resolve(ifaceUUID, major, minor); ok {
		iface.Name = entry.Name
		iface.Title = entry.Title
		iface.Protocol = entry.Protocol
	}
	return iface
}

// interfaceID extracts the interface UUID and version from a tower's interface-identifier
// floor (the first UUID-typed floor, [C706] Appendix L: LHS = 0x0D, 16-octet UUID, 16-bit
// major; RHS = 16-bit minor). The transfer-syntax floor is also UUID-typed, so the first
// match is taken.
func interfaceID(tower structures.Tower) (id guid.GUID, major uint16, minor uint16, ok bool) {
	for _, floor := range tower.Floors {
		if floor.Protocol() != structures.FloorProtoUUID || len(floor.LHS) < 19 {
			continue
		}
		var u structures.EptUUID
		copy(u.Octets[:], floor.LHS[1:17])
		major = binary.LittleEndian.Uint16(floor.LHS[17:19])
		if len(floor.RHS) >= 2 {
			minor = binary.LittleEndian.Uint16(floor.RHS[:2])
		}
		return u.GUID(), major, minor, true
	}
	return guid.GUID{}, 0, 0, false
}

// matchesInterface reports whether the interface matches the lowercase filter substring on
// any of its identifying fields or bindings.
func matchesInterface(iface Interface, filter string) bool {
	for _, field := range []string{iface.UUID, iface.Name, iface.Title, iface.Protocol} {
		if strings.Contains(strings.ToLower(field), filter) {
			return true
		}
	}
	for _, binding := range iface.Bindings {
		if strings.Contains(strings.ToLower(binding.StringBinding), filter) ||
			strings.Contains(strings.ToLower(binding.Annotation), filter) {
			return true
		}
	}
	return false
}

// isZeroGUID reports whether g is the nil UUID (00000000-0000-0000-0000-000000000000),
// which the endpoint mapper uses for "no object".
func isZeroGUID(g guid.GUID) bool {
	return g.A == 0 && g.B == 0 && g.C == 0 && g.D == 0 && g.E == 0
}

// printJSON writes the grouped interfaces as an indented JSON array.
func printJSON(interfaces []Interface) error {
	if interfaces == nil {
		interfaces = []Interface{}
	}
	out, err := json.MarshalIndent(interfaces, "", "  ")
	if err != nil {
		return fmt.Errorf("error encoding JSON: %s", err)
	}
	logger.Print(string(out))
	return nil
}

// printTree renders the interfaces as a tree: each interface header (resolved name in
// green, UUID/version in blue) with its bindings listed beneath it.
func printTree(host string, interfaces []Interface) {
	endpointCount := 0
	for _, iface := range interfaces {
		endpointCount += len(iface.Bindings)
	}

	logger.Print(fmt.Sprintf("[>] Enumerating RPC endpoints on \x1b[94m%s\x1b[0m", host))
	if len(interfaces) == 0 {
		logger.Print("[>] Registered interfaces (0)")
		return
	}
	logger.Print(fmt.Sprintf("[>] Registered interfaces (\x1b[93m%d\x1b[0m):", len(interfaces)))

	for ifaceIndex, iface := range interfaces {
		lastIface := ifaceIndex == len(interfaces)-1
		if lastIface {
			logger.Print(fmt.Sprintf("  └── %s", interfaceLabel(iface)))
		} else {
			logger.Print(fmt.Sprintf("  ├── %s", interfaceLabel(iface)))
		}

		// Continuation prefix so bindings line up under their interface.
		prefix := "  │   "
		if lastIface {
			prefix = "      "
		}
		for bindingIndex, binding := range iface.Bindings {
			if bindingIndex < len(iface.Bindings)-1 {
				logger.Print(fmt.Sprintf("%s├── %s", prefix, bindingLabel(binding)))
			} else {
				logger.Print(fmt.Sprintf("%s└── %s", prefix, bindingLabel(binding)))
			}
		}
	}
	logger.Print("")
	logger.Print(fmt.Sprintf("[>] Found \x1b[93m%d\x1b[0m endpoints across \x1b[93m%d\x1b[0m interfaces.", endpointCount, len(interfaces)))
}

// interfaceLabel renders the header line for one interface: the resolved name (green) when
// known, the UUID and version (blue), and the protocol document / title when known.
func interfaceLabel(iface Interface) string {
	label := ""
	if iface.Name != "" {
		label += fmt.Sprintf("\x1b[92m%s\x1b[0m ", iface.Name)
	}
	label += fmt.Sprintf("\x1b[94m%s v%s\x1b[0m", iface.UUID, iface.Version)

	extra := []string{}
	if iface.Protocol != "" {
		extra = append(extra, iface.Protocol)
	}
	if iface.Title != "" {
		extra = append(extra, iface.Title)
	}
	if len(extra) > 0 {
		label += fmt.Sprintf(" (%s)", strings.Join(extra, " - "))
	}
	return label
}

// bindingLabel renders one binding line: the string binding (blue) plus any annotation
// (green) and non-nil object UUID.
func bindingLabel(binding Binding) string {
	stringBinding := binding.StringBinding
	if stringBinding == "" {
		stringBinding = "(no binding)"
	}
	label := fmt.Sprintf("\x1b[94m%s\x1b[0m", stringBinding)
	if binding.Annotation != "" {
		label += fmt.Sprintf(" \x1b[92m'%s'\x1b[0m", binding.Annotation)
	}
	if binding.ObjectUUID != "" {
		label += fmt.Sprintf(" object=%s", binding.ObjectUUID)
	}
	return label
}
