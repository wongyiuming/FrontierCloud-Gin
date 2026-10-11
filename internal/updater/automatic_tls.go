package updater

import (
	"encoding/json"
	"errors"
	"strings"
)

// Replacing image bytes cannot introduce missing volumes/services. Refuse a
// legacy-to-automatic boundary before stopping Web; the first migration uses
// Compose under maintenance with an independent recovery copy. Once migrated,
// the updater snapshots/replaces/restores both certificate services as well.
func automaticTLSTopology(snapshots map[string]Container) error {
	if len(snapshots) != 7 {
		return errors.New("automatic TLS requires first Compose topology migration; see docs/automatic-tls-migration.md")
	}
	sources := map[string]string{}
	mounts := func(c Container, target string, readOnly bool) bool {
		var host struct {
			Binds  []string
			Mounts []struct {
				Source, Target string
				ReadOnly       bool
			}
		}
		raw, err := json.Marshal(c.HostConfig)
		if err != nil || json.Unmarshal(raw, &host) != nil {
			return false
		}
		found := 0
		source := ""
		for _, bind := range host.Binds {
			parts := strings.Split(bind, ":")
			if len(parts) >= 2 && parts[1] == target {
				ro := false
				if len(parts) >= 3 {
					for _, option := range strings.Split(parts[2], ",") {
						if option == "ro" {
							ro = true
						}
					}
				}
				if ro != readOnly {
					return false
				}
				source = parts[0]
				found++
			}
		}
		for _, mount := range host.Mounts {
			if mount.Target == target {
				if mount.ReadOnly != readOnly {
					return false
				}
				source = mount.Source
				found++
			}
		}
		if found != 1 || source == "" {
			return false
		}
		if previous := sources[target]; previous != "" && previous != source {
			return false
		}
		sources[target] = source
		return true
	}
	for _, entry := range []struct {
		service, path string
		ro            bool
	}{
		{"web", "/run/frontiercloud-certificate", true},
		{"nginx", "/run/frontiercloud-tls", true},
		{"certificate-agent", "/var/lib/frontiercloud-certificate", false},
		{"certificate-agent", "/run/frontiercloud-certificate", false},
		{"certificate-agent", "/run/frontiercloud-tls", false},
		{"certificate-init", "/var/lib/frontiercloud-certificate", false},
		{"certificate-init", "/run/frontiercloud-certificate", false},
		{"certificate-init", "/run/frontiercloud-tls", false},
	} {
		if !mounts(snapshots[entry.service], entry.path, entry.ro) {
			return errors.New("automatic TLS persistent volume topology is incomplete; perform Compose migration before image replacement")
		}
	}
	return nil
}
