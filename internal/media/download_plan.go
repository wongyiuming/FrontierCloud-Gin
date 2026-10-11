package media

import (
	"os"
	"strconv"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// PlanDelivery validates the issued source identity while this Download retains
// its shared mutation lease. Local bytes remain under that lease until the HTTP
// stream closes; remote capabilities bind the immutable storage object ID.
func (d *Download) PlanDelivery(id, snapshot, requestID, traceID string, nginx bool) (Delivery, error) {
	if id == "" || !ownedObjectID.MatchString(snapshot) || len(d.Items) != 1 || d.Items[0].Directory {
		return Delivery{}, ErrPath
	}
	entries, err := d.Plan(1)
	if err != nil {
		return Delivery{}, err
	}
	if len(entries) != 1 || entries[0].Encryption != nil || entries[0].MediaID != id || entries[0].Snapshot != snapshot {
		return Delivery{}, store.ErrNodeState
	}
	entry := entries[0]
	result := Delivery{ResourceID: entry.MediaID, ObjectID: entry.MediaID}
	if len(d.globals) == 1 {
		row := d.globals[0]
		_, relation, err := d.service.resolveGlobal(d.ctx, row.ID, row.Path)
		if err != nil {
			return Delivery{}, err
		}
		if relation != nil {
			return d.service.remoteDelivery(d.ctx, row, relation, requestID, traceID, nginx)
		}
		object, err := d.service.repository.ObjectByID(d.ctx, row.ObjectID)
		if err != nil {
			return Delivery{}, err
		}
		if object == nil || object.Path != row.Path || object.Kind != row.Kind {
			return Delivery{}, store.ErrNodeState
		}
		result.OwnerID, result.ObjectID = row.MemberID, row.ObjectID
	}
	f, info, err := d.Open(entry.Path)
	if err != nil {
		return Delivery{}, err
	}
	if !info.Mode().IsRegular() || info.Size() != entry.Bytes || len(d.globals) == 0 && downloadSnapshot(id, entry.Path, info.Size(), strconv.FormatInt(info.ModTime().UnixNano(), 10)) != snapshot {
		f.Close()
		return Delivery{}, store.ErrNodeState
	}
	// Use the descriptor's stat as well: out-of-band filesystem substitution is
	// unsupported, but must not make a stale stat appear to authorize new bytes.
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || info.Size() != opened.Size() || !info.ModTime().Equal(opened.ModTime()) {
		f.Close()
		return Delivery{}, store.ErrNodeState
	}
	result.Stream = &Stream{File: f, Info: opened, Path: entry.Path, ResourceID: result.ResourceID, OwnerID: result.OwnerID, ObjectID: result.ObjectID}
	return result, nil
}
