package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/httpapi"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func logQueryCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("log-query", flag.ContinueOnError)
	kind := flags.String("type", "", "explicit log type")
	from := flags.String("from", "", "RFC3339 start")
	to := flags.String("to", "", "RFC3339 end")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected log query arguments")
	}
	start, e := time.Parse(time.RFC3339, *from)
	if e != nil {
		return errors.New("explicit --from RFC3339 is required")
	}
	end, e := time.Parse(time.RFC3339, *to)
	if e != nil {
		return errors.New("explicit --to RFC3339 is required")
	}
	if e = logarchive.ValidateQuery(start, end, time.Now(), logarchive.Kind(*kind), false); e != nil {
		return e
	}
	settings, e := config.Load()
	if e != nil {
		return e
	}
	if settings.DatabaseType != config.DatabaseSQLite {
		return logarchive.ErrPolicy
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, e := sqlitestore.OpenReadOnly(ctx, settings.SQLitePath)
	if e != nil {
		return e
	}
	defer db.Close()
	identity, e := node.OpenExisting(ctx, db.Nodes(), settings.SecretsDirectory)
	if e != nil {
		return e
	}
	if identity.Role != "Master" {
		return errors.New("encrypted logs may be read only on Master")
	}
	key, e := vault.OpenExisting(settings.SecretsDirectory)
	if e != nil {
		return e
	}
	catalog, e := logarchive.ExistingCatalog(db.Database(), key, identity.ID)
	if e != nil {
		return e
	}
	cfg, e := catalog.Configuration(ctx)
	if e != nil || !cfg.Enabled {
		return errors.New("select an active Direct log node in Admin first")
	}
	service := node.NewService(db.Nodes(), identity, node.NewTransport())
	values := []json.RawMessage{}
	cursor := ""
	total := 0
	partial := false
	pending,e:=catalog.PendingForMaster(ctx,logarchive.Kind(*kind));if e!=nil{return e}
	for _,event:=range pending{var v struct{Time int64 `json:"received_at_ms"`};if json.Unmarshal(event,&v)!=nil{return logarchive.ErrBlock};if v.Time>=start.UnixMilli()&&v.Time<end.UnixMilli(){values=append(values,event)};if len(values)>=500{partial=true;break}}
	for {
		if partial{break}
		entries, more, e := catalog.Query(ctx, start, end, time.Now(), logarchive.Kind(*kind), false, cursor)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if total+entry.Record.CiphertextBytes > 4<<20 || len(values) >= 500 {
				partial = true
				break
			}
			var cipher []byte
			if entry.Remote.MemberID != "" {
				cipher, e = httpapi.PullLogForMaster(ctx, service, entry.Remote, entry.Record.Reference(), settings.AdminOrigin)
			} else {
				var local logarchive.Entry
				local, e = catalog.Entry(ctx, entry.Record.Header.ID)
				cipher = local.Ciphertext
			}
			if e != nil {
				return e
			}
			plain, e := logarchive.OpenForMaster(key, entry.Record, cipher)
			if e != nil {
				return e
			}
			total += len(cipher)
			var events []json.RawMessage
			if json.Unmarshal(plain, &events) != nil {
				events = []json.RawMessage{append(json.RawMessage{}, plain...)}
			}
			clear(plain)
			for _, event := range events {
				var v struct {
					Time int64 `json:"received_at_ms"`
				}
				if json.Unmarshal(event, &v) != nil {
					return logarchive.ErrBlock
				}
				if v.Time >= start.UnixMilli() && v.Time < end.UnixMilli() {
					values = append(values, event)
				}
				if len(values) >= 500 {
					partial = true
					break
				}
			}
			cursor = entry.Record.Header.ID
			if partial {
				break
			}
		}
		if partial || !more {
			break
		}
	}
	// JSON escaping keeps terminal control sequences inert. No key or plaintext
	// scratch file is created; callers explicitly decide how to use terminal output.
	return json.NewEncoder(output).Encode(map[string]any{"events": values, "partial": partial, "ciphertext_bytes": total, "read_only": true})
}
