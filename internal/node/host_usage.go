package node

import (
	"bufio"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
)

type hostCPUTicks struct{ total, idle uint64 }

type hostUsageSampler struct {
	mu       sync.Mutex
	previous hostCPUTicks
}

// Sample Linux's system-wide /proc view at the existing heartbeat cadence.
// Optional data must never fail a heartbeat.
func (s *hostUsageSampler) sample() map[string]any {
	usage := map[string]any{}
	s.mu.Lock()
	if stat, err := os.Open("/proc/stat"); err == nil {
		current, ok := readHostCPUTicks(stat)
		stat.Close()
		if ok {
			if percent, valid := hostCPUPercent(s.previous, current); valid {
				usage["cpu_percent"] = percent
			}
			s.previous = current
		}
	}
	s.mu.Unlock()
	if meminfo, err := os.Open("/proc/meminfo"); err == nil {
		used, total, ok := readHostMemory(meminfo)
		meminfo.Close()
		if ok {
			usage["memory_used_bytes"] = used
			usage["memory_total_bytes"] = total
		}
	}
	return usage
}

func readHostCPUTicks(r io.Reader) (hostCPUTicks, bool) {
	line := bufio.NewScanner(r)
	if !line.Scan() {
		return hostCPUTicks{}, false
	}
	fields := strings.Fields(line.Text())
	if len(fields) < 9 || fields[0] != "cpu" {
		return hostCPUTicks{}, false
	}
	var ticks hostCPUTicks
	// Guest and guest_nice are already included in user and nice.
	for i, field := range fields[1:9] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil || value > math.MaxUint64-ticks.total {
			return hostCPUTicks{}, false
		}
		ticks.total += value
		if i == 3 || i == 4 { // idle and iowait
			ticks.idle += value
		}
	}
	return ticks, ticks.total != 0
}

func hostCPUPercent(previous, current hostCPUTicks) (int64, bool) {
	if previous.total == 0 || current.total <= previous.total || current.idle < previous.idle {
		return 0, false
	}
	total := current.total - previous.total
	idle := current.idle - previous.idle
	if idle > total {
		return 0, false
	}
	return int64(math.Round(100 * float64(total-idle) / float64(total))), true
}

func readHostMemory(r io.Reader) (used, total int64, ok bool) {
	var available int64 = -1
	lines := bufio.NewScanner(r)
	for lines.Scan() {
		key, value, _ := strings.Cut(lines.Text(), ":")
		if key != "MemTotal" && key != "MemAvailable" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) != 2 || fields[1] != "kB" {
			return 0, 0, false
		}
		kib, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || kib < 0 || kib > math.MaxInt64/1024 {
			return 0, 0, false
		}
		if key == "MemTotal" {
			total = kib * 1024
		} else {
			available = kib * 1024
		}
		if total > 0 && available >= 0 {
			if available > total {
				return 0, 0, false
			}
			return total - available, total, true
		}
	}
	return 0, 0, false
}
