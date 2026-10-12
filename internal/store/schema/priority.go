package schema

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// Widen only the physical preference field. Every existing fact, timestamp,
// object identity, index and trigger is retained. SQLite DDL is transactional;
// MySQL's single ALTER is atomic and may be safely retried before the marker.
func widenPriority(ctx context.Context, conn *sql.Conn, backend string, statements []string) error {
	if backend == "mysql" {
		_, err := conn.ExecContext(ctx, migrations.PriorityMySQLAlter)
		return err
	}
	var create string
	for _, statement := range statements {
		if match := tablePattern.FindStringSubmatch(statement); len(match) == 2 && match[1] == "media_playback_stats" {
			create = statement
			break
		}
	}
	if create == "" {
		return fmt.Errorf("priority schema is missing")
	}
	rows, err := conn.QueryContext(ctx, "SELECT sql FROM sqlite_schema WHERE tbl_name='media_playback_stats' AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type,name")
	if err != nil {
		return err
	}
	definitions := []string{}
	for rows.Next() {
		var definition string
		if err = rows.Scan(&definition); err != nil {
			break
		}
		definitions = append(definitions, definition)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	create = strings.Replace(create, "CREATE TABLE IF NOT EXISTS media_playback_stats", "CREATE TABLE media_playback_stats_priority4", 1)
	for _, statement := range []string{
		create,
		"INSERT INTO media_playback_stats_priority4(media_id,media_path,play_score,preference,created_at,updated_at) SELECT media_id,media_path,play_score,preference,created_at,updated_at FROM media_playback_stats",
		"DROP TABLE media_playback_stats",
		"ALTER TABLE media_playback_stats_priority4 RENAME TO media_playback_stats",
	} {
		if _, err = conn.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	for _, definition := range definitions {
		if _, err = conn.ExecContext(ctx, definition); err != nil {
			return err
		}
	}
	return nil
}
