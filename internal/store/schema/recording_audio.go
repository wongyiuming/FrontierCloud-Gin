package schema

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func prepareRecordingAudioSchema(ctx context.Context, conn *sql.Conn, backend string, create, requireEmpty bool) error {
	const table = "sealed_recording_audio"
	statements, err := migrations.RecordingAudioStatements(backend)
	if err != nil || len(statements) == 0 || !strings.HasPrefix(statements[0], "CREATE TABLE IF NOT EXISTS "+table+" ") {
		return errors.New("missing canonical sealed recording schema")
	}
	if create {
		for _, statement := range statements {
			if _, err = conn.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
	}
	if err = checkS3Columns(ctx, conn, backend, table, statements[0]); err != nil {
		return err
	}
	if err = checkS3Constraints(ctx, conn, backend, table, statements[0]); err != nil {
		return err
	}
	if err = checkSealedTreeCollations(ctx, conn, backend, table); err != nil {
		return err
	}
	primary := "PRIMARY"
	if backend == "sqlite" {
		primary = "sqlite_autoindex_" + table + "_1"
	}
	for _, index := range []s3Index{
		{name: primary, table: table, columns: []string{"recording_index"}, unique: true},
		{name: "uq_sealed_recording_audio_enc", table: table, columns: []string{"encryption_id"}, unique: true},
		{name: "uq_sealed_recording_audio_title_enc", table: table, columns: []string{"title_encryption_id"}, unique: true},
	} {
		columns, unique, err := s3IndexColumns(ctx, conn, backend, table, index.name)
		if err != nil || !unique || len(columns) != 1 || columns[0] != index.columns[0] {
			return errors.New("invalid sealed recording index")
		}
		if err = checkSealedIndexOrdering(ctx, conn, backend, index); err != nil {
			return err
		}
	}
	if requireEmpty {
		var exists bool
		if err = conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+")").Scan(&exists); err != nil || exists {
			return errors.New("sealed recording state requires prepared Master recovery")
		}
	}
	return nil
}
