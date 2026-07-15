//go:build windows

package tun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

const windowsRouteJournalVersion = 1

const (
	windowsRoutePending = "pending"
	windowsRouteActive  = "active"
)

var windowsRouteJournalMu sync.Mutex

type windowsRouteJournal struct {
	path string
}

type windowsRouteJournalData struct {
	Version int                        `json:"version"`
	Entries []windowsRouteJournalEntry `json:"entries"`
}

type windowsRouteJournalEntry struct {
	InterfaceLUID  uint64    `json:"interface_luid"`
	InterfaceIndex uint32    `json:"interface_index"`
	Destination    string    `json:"destination"`
	Metric         uint32    `json:"metric"`
	Protocol       uint32    `json:"protocol"`
	State          string    `json:"state"`
	CreatedAt      time.Time `json:"created_at"`
}

func newWindowsRouteJournal(path string) *windowsRouteJournal {
	return &windowsRouteJournal{path: path}
}

func defaultWindowsRouteJournalPath() string {
	if value := os.Getenv("TACHYON_ROUTE_JOURNAL"); value != "" {
		return value
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "Tachyon", "route-journal-v1.json")
}

func (j *windowsRouteJournal) prepare(op *windowsRouteOperator, prefix netip.Prefix) error {
	windowsRouteJournalMu.Lock()
	defer windowsRouteJournalMu.Unlock()
	data, err := j.load()
	if err != nil {
		return err
	}
	key := prefix.Masked().String()
	for idx, entry := range data.Entries {
		if entry.InterfaceLUID == op.interfaceLUID && entry.Destination == key {
			data.Entries[idx] = newWindowsRouteJournalEntry(op, key, windowsRoutePending)
			return j.save(data)
		}
	}
	data.Entries = append(data.Entries, newWindowsRouteJournalEntry(op, key, windowsRoutePending))
	return j.save(data)
}

func (j *windowsRouteJournal) record(op *windowsRouteOperator, prefix netip.Prefix) error {
	windowsRouteJournalMu.Lock()
	defer windowsRouteJournalMu.Unlock()
	data, err := j.load()
	if err != nil {
		return err
	}
	key := prefix.Masked().String()
	for idx, entry := range data.Entries {
		if entry.InterfaceLUID == op.interfaceLUID && entry.Destination == key {
			data.Entries[idx].State = windowsRouteActive
			return j.save(data)
		}
	}
	return fmt.Errorf("route journal intent is missing for %s", key)
}

func newWindowsRouteJournalEntry(op *windowsRouteOperator, key, state string) windowsRouteJournalEntry {
	return windowsRouteJournalEntry{
		InterfaceLUID:  op.interfaceLUID,
		InterfaceIndex: op.interfaceIdx,
		Destination:    key,
		Metric:         windowsRouteMetric,
		Protocol:       windowsRouteProtocol,
		State:          state,
		CreatedAt:      time.Now().UTC(),
	}
}

func (j *windowsRouteJournal) release(op *windowsRouteOperator, prefix netip.Prefix) error {
	windowsRouteJournalMu.Lock()
	defer windowsRouteJournalMu.Unlock()
	data, err := j.load()
	if err != nil {
		return err
	}
	key := prefix.Masked().String()
	kept := data.Entries[:0]
	for _, entry := range data.Entries {
		if entry.InterfaceLUID == op.interfaceLUID && entry.Destination == key {
			continue
		}
		kept = append(kept, entry)
	}
	data.Entries = kept
	return j.save(data)
}

func (j *windowsRouteJournal) reconcile(ctx context.Context, op *windowsRouteOperator) error {
	windowsRouteJournalMu.Lock()
	defer windowsRouteJournalMu.Unlock()
	data, err := j.load()
	if err != nil {
		return err
	}
	kept := make([]windowsRouteJournalEntry, 0, len(data.Entries))
	var reconcileErr error
	for _, entry := range data.Entries {
		if entry.InterfaceLUID != op.interfaceLUID {
			kept = append(kept, entry)
			continue
		}
		prefix, parseErr := netip.ParsePrefix(entry.Destination)
		if parseErr != nil || entry.InterfaceIndex != op.interfaceIdx || entry.Metric != windowsRouteMetric || entry.Protocol != windowsRouteProtocol {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("unsafe route journal entry for Wintun LUID %d destination %q", entry.InterfaceLUID, entry.Destination))
			continue
		}
		state, readErr := op.Read(ctx, prefix)
		if readErr != nil {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, readErr)
			continue
		}
		if !state.Exists {
			continue
		}
		if !state.Matches {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("journaled route %s changed; refusing startup deletion", prefix))
			continue
		}
		if entry.State == windowsRoutePending {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("route journal intent for %s is pending; refusing ambiguous startup deletion", prefix))
			continue
		}
		if entry.State != windowsRouteActive {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("route journal entry for %s has invalid state %q", prefix, entry.State))
			continue
		}
		if err := op.Delete(ctx, prefix); err != nil {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("delete journaled route %s: %w", prefix, err))
			continue
		}
		state, readErr = op.Read(ctx, prefix)
		if readErr != nil || state.Exists {
			kept = append(kept, entry)
			if readErr == nil {
				readErr = fmt.Errorf("journaled route %s remained after deletion", prefix)
			}
			reconcileErr = errors.Join(reconcileErr, readErr)
		}
	}
	data.Entries = kept
	return errors.Join(reconcileErr, j.save(data))
}

func (j *windowsRouteJournal) load() (windowsRouteJournalData, error) {
	data := windowsRouteJournalData{Version: windowsRouteJournalVersion}
	wire, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return data, nil
	}
	if err != nil {
		return data, fmt.Errorf("read route journal %q: %w", j.path, err)
	}
	if err := json.Unmarshal(wire, &data); err != nil {
		return data, fmt.Errorf("parse route journal %q: %w", j.path, err)
	}
	if data.Version != windowsRouteJournalVersion {
		return data, fmt.Errorf("unsupported route journal version %d", data.Version)
	}
	return data, nil
}

func (j *windowsRouteJournal) save(data windowsRouteJournalData) error {
	if len(data.Entries) == 0 {
		if err := os.Remove(j.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove empty route journal %q: %w", j.path, err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return fmt.Errorf("create route journal directory: %w", err)
	}
	wire, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, wire, 0o600); err != nil {
		return fmt.Errorf("write route journal: %w", err)
	}
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	to, err := windows.UTF16PtrFromString(j.path)
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit route journal: %w", err)
	}
	return nil
}
