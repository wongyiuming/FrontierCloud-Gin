package operator

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// Capture source physical table/index/free space with an expansion allowance.
// Unknown historical estimates cannot authorize destructive MySQL restoration.
func (d *Deployment) mysqlRestoreStorageBudget(ctx context.Context, cfg Config) (uint64, error) {
	if !validSQLName(cfg.Services["mysql"].Environment["MYSQL_DATABASE"]) {
		return 0, errors.New("invalid scoped MySQL database")
	}
	raw, e := d.Compose(ctx, true, "exec", "-T", "mysql", "sh", "-c", `MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysql -N -u root -e "SELECT COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH+DATA_FREE),0) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '$MYSQL_DATABASE'"`)
	if e != nil {
		return 0, errors.New("MySQL source storage estimate unavailable")
	}
	bytes, e := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if e != nil || bytes > 10*1024*1024*1024*1024 {
		return 0, errors.New("MySQL source storage estimate invalid")
	}
	return bytes*4 + (512 << 20), nil
}

func (d *Deployment) checkMySQLRestoreCapacity(ctx context.Context, cfg Config, budget uint64) error {
	if budget < (512<<20) || budget > 41*1024*1024*1024*1024 {
		return errors.New("MySQL recovery requires a captured source storage budget; destructive import refused")
	}
	volume, ok := cfg.Volumes["mysql_data"]
	if !ok || volume.External {
		return errors.New("scoped MySQL data filesystem unavailable")
	}
	root, e := d.volumeRoot(ctx, volume.Name)
	if e != nil {
		return e
	}
	return checkMySQLDataCapacity(root, budget, diskFree)
}

func checkMySQLDataCapacity(root string, budget uint64, available func(string) (uint64, error)) error {
	free, e := available(root)
	if e != nil {
		return e
	}
	if free < budget+(512<<20) {
		return errors.New("MySQL server data filesystem lacks captured import budget and remaining reserve; no database dropped")
	}
	return nil
}
