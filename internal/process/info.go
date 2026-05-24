package process

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

type ProcessEntry struct {
	PID        int32
	Name       string
	Executable string
}

type Info struct {
	processes  []ProcessEntry
	mu         sync.RWMutex
	lastUpdate time.Time
}

func NewInfo() *Info {
	info := &Info{}
	info.Refresh()
	return info
}

func (i *Info) Refresh() error {
	processes, err := process.Processes()
	if err != nil {
		return fmt.Errorf("Failed to get process list: %v", err)
	}

	var entries []ProcessEntry

	for _, p := range processes {
		name, err := p.Name()
		if err != nil {

			continue
		}

		exe, err := p.Exe()
		if err != nil {

			exe = ""
		}

		entries = append(entries, ProcessEntry{
			PID:        p.Pid,
			Name:       name,
			Executable: exe,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	i.mu.Lock()
	i.processes = entries
	i.lastUpdate = time.Now()
	i.mu.Unlock()

	return nil
}

func (i *Info) GetProcesses() []ProcessEntry {
	i.mu.RLock()
	defer i.mu.RUnlock()

	result := make([]ProcessEntry, len(i.processes))
	copy(result, i.processes)

	return result
}

func (i *Info) GetProcessByName(name string) ([]ProcessEntry, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	var result []ProcessEntry

	for _, p := range i.processes {
		if p.Name == name {
			result = append(result, p)
		}
	}

	return result, len(result) > 0
}

func (i *Info) LastUpdateTime() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.lastUpdate
}
