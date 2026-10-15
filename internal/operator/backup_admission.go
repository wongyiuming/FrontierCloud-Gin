package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func expectedNativeBinding(cfg Config, database string) string {
	env := cfg.Services["web"].Environment
	parts := []string{"sqlite", env["SQLITE_PATH"]}
	if database == "mysql" {
		port := env["MYSQL_PORT"]
		if port == "" {
			port = "3306"
		}
		if number, err := strconv.Atoi(port); err == nil {
			port = strconv.Itoa(number)
		}
		parts = []string{"mysql", strings.ToLower(env["MYSQL_HOST"]), port, env["MYSQL_DATABASE"]}
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "native-store-v1:" + hex.EncodeToString(h[:]) + "\n"
}

func (d *Deployment) validateBackupAdmission(ctx context.Context, cfg Config, r Receipt, fact RuntimeFact) error {
	data, e := upgradeDataRoot(cfg)
	if e != nil {
		return e
	}
	binding, e := readRegular(filepath.Join(data, ".native-store"), 256)
	if e != nil || string(binding) != expectedNativeBinding(cfg, r.Database) {
		return errors.New("state backup requires a valid native store admission receipt")
	}
	receipt, e := readRegular(filepath.Join(data, ".native-runtime"), 4096)
	if e != nil {
		return errors.New("state backup requires a valid native runtime admission receipt")
	}
	secretRoot := ""
	for _, mount := range cfg.Services["web"].Volumes {
		if mount.Target != cfg.Services["web"].Environment["SECRETS_DIR"] {
			continue
		}
		if mount.Type == "bind" {
			secretRoot = mount.Source
		} else if mount.Type == "volume" {
			volume, ok := cfg.Volumes[mount.Source]
			if !ok {
				return errors.New("native vault volume unavailable")
			}
			secretRoot, e = d.volumeRoot(ctx, volume.Name)
			if e != nil {
				return e
			}
		}
	}
	if secretRoot == "" {
		return errors.New("native vault mount required for state backup")
	}
	v, e := vault.OpenExisting(secretRoot)
	if e != nil {
		return errors.New("native admission vault cannot be verified")
	}
	proof, e := v.Unseal(string(receipt))
	if e != nil || proof != "frontiercloud-native-runtime-v1\n"+string(binding)+fact.NodeID {
		return errors.New("native runtime admission does not match the selected store and node")
	}
	return nil
}
