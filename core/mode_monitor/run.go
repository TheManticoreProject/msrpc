// Package mode_monitor implements the "monitor" mode: it watches the target's endpoint
// mapper on a refresh loop and reports RPC endpoints as they appear and disappear, the
// way a live endpoint-watcher does. Steady-state endpoints are silent; only changes are
// printed, each with a timestamp. Ctrl-C stops the loop cleanly.
package mode_monitor

import (
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"

	"github.com/TheManticoreProject/msrpc/config"
	"github.com/TheManticoreProject/msrpc/core/mode_dump"
)

// endpoint is one registered (interface, binding) pair, flattened from mode_dump's grouped
// view so that two snapshots can be diffed binding-by-binding.
type endpoint struct {
	uuid       string
	version    string
	name       string
	title      string
	protocol   string
	binding    string
	annotation string
}

// key uniquely identifies an endpoint across snapshots: an endpoint is "the same" when its
// interface UUID, version and binding all match.
func (e endpoint) key() string {
	return e.uuid + "|" + e.version + "|" + e.binding
}

// Run watches the endpoint mapper and reports created/deleted endpoints every interval
// seconds until interrupted with Ctrl-C.
//
// Parameters:
// - filter: A case-insensitive substring to filter interfaces by, or "" for all.
// - interval: Seconds between endpoint-map snapshots (minimum 1).
// - config: The configuration of the application.
func Run(filter string, interval int, config config.Config) error {
	if interval < 1 {
		interval = 1
	}
	period := time.Duration(interval) * time.Second

	// Baseline snapshot: everything already registered is the starting state, so only
	// subsequent changes are reported (the endpoints present now are not printed).
	before, err := snapshot(filter, config)
	if err != nil {
		return err
	}

	logger.Print(fmt.Sprintf("[>] Monitoring RPC endpoints on %s every %ds (baseline: %d endpoints). Press Ctrl-C to stop.", config.Connection.Host, interval, len(before)))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			logger.Print("[>] Stopping monitor.")
			return nil

		case <-ticker.C:
			now, err := snapshot(filter, config)
			if err != nil {
				// A transient failure (e.g. the host briefly went away) should not end the
				// monitor; warn and keep the previous baseline so the next tick can recover.
				logger.Warn(fmt.Sprintf("Snapshot failed, keeping previous state: %s", err))
				continue
			}
			reportChanges(before, now)
			before = now
		}
	}
}

// snapshot collects the current endpoint map and flattens it into a set of endpoints keyed
// by (uuid, version, binding). It reuses mode_dump.Collect so the enumeration and catalog
// resolution stay identical to the dump mode.
func snapshot(filter string, config config.Config) (map[string]endpoint, error) {
	interfaces, err := mode_dump.Collect(filter, config)
	if err != nil {
		return nil, err
	}

	endpoints := make(map[string]endpoint)
	for _, iface := range interfaces {
		for _, binding := range iface.Bindings {
			e := endpoint{
				uuid:       iface.UUID,
				version:    iface.Version,
				name:       iface.Name,
				title:      iface.Title,
				protocol:   iface.Protocol,
				binding:    binding.StringBinding,
				annotation: binding.Annotation,
			}
			endpoints[e.key()] = e
		}
	}
	return endpoints, nil
}

// diffSnapshots returns the endpoints that appeared (created) and disappeared (deleted)
// between two snapshots, each sorted by key for deterministic output. Endpoints present in
// both snapshots are unchanged and returned in neither slice.
func diffSnapshots(before, now map[string]endpoint) (created, deleted []endpoint) {
	for key, e := range now {
		if _, ok := before[key]; !ok {
			created = append(created, e)
		}
	}
	for key, e := range before {
		if _, ok := now[key]; !ok {
			deleted = append(deleted, e)
		}
	}

	sort.Slice(deleted, func(i, j int) bool { return deleted[i].key() < deleted[j].key() })
	sort.Slice(created, func(i, j int) bool { return created[i].key() < created[j].key() })
	return created, deleted
}

// reportChanges diffs two snapshots and prints the endpoints that appeared (created, green)
// and disappeared (deleted, red) between them. The logger prepends the timestamp, so the
// line is not stamped here. Unchanged endpoints are not printed.
func reportChanges(before, now map[string]endpoint) {
	created, deleted := diffSnapshots(before, now)

	for _, e := range deleted {
		logger.Print(fmt.Sprintf("Endpoint was \x1b[1;91mdeleted\x1b[0m: %s", endpointLabel(e)))
	}
	for _, e := range created {
		logger.Print(fmt.Sprintf("Endpoint was \x1b[1;92mcreated\x1b[0m: %s", endpointLabel(e)))
	}
}

// endpointLabel renders one endpoint for a change line as plain text (the surrounding
// timestamp and created/deleted marker carry the only colour, matching the reference
// tool): "name uuid vX.Y: binding (protocol - title), annotation".
func endpointLabel(e endpoint) string {
	label := ""
	if e.name != "" {
		label += e.name + " "
	}

	binding := e.binding
	if binding == "" {
		binding = "(no binding)"
	}
	label += fmt.Sprintf("%s v%s: %s", e.uuid, e.version, binding)

	extra := []string{}
	if e.protocol != "" {
		extra = append(extra, e.protocol)
	}
	if e.title != "" {
		extra = append(extra, e.title)
	}
	if len(extra) > 0 {
		label += fmt.Sprintf(" (%s)", strings.Join(extra, " - "))
	}
	if e.annotation != "" {
		label += fmt.Sprintf(", %s", e.annotation)
	}
	return label
}
