// Package noderetirement combines read-only Master and authenticated native
// observations. It never turns cached inventory into revocation permission.
package noderetirement

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"math"
	"strings"
	"time"
)

var ErrObservation = errors.New("retirement observation is incomplete or conflicts with identity, sequence or bounds")

const route = "/internal/v1/resource-inventory"
const MaxPages = 100000
const MaxSamples = 8
const MaxCategories = 64

type Caller interface {
	Call(context.Context, store.Relationship, string, any) (map[string]any, error)
}
type Service struct {
	Repository store.RetirementRepository
	Nodes      store.NodeRepository
	Client     Caller
}
type Concern struct {
	Code    string   `json:"code"`
	Count   int64    `json:"count"`
	Samples []string `json:"samples"`
}
type Report struct {
	MemberID            string                 `json:"member_id"`
	CheckedAt           int64                  `json:"checked_at"`
	PreflightOnly       bool                   `json:"preflight_only"`
	ObservationComplete bool                   `json:"observation_complete"`
	Master              store.RetirementLedger `json:"master"`
	Peer                store.RetirementLedger `json:"peer"`
	PhysicalEntries     uint64                 `json:"physical_entries"`
	LogicalBytes        int64                  `json:"logical_bytes"`
	ExpectedItems       uint64                 `json:"expected_items"`
	Concerns            []Concern              `json:"concerns"`
}

func validToken(value string) bool {
	decoded, e := hex.DecodeString(value)
	return e == nil && len(decoded) == 16 && value == strings.ToLower(value)
}
func decode(value any, target any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return json.Unmarshal(raw, target)
}
func (r *Report) concern(code, sample string) error {
	if len(code) == 0 || len(code) > 80 || len(sample) > resourceinventory.MaxPathBytes {
		return ErrObservation
	}
	for i := range r.Concerns {
		if r.Concerns[i].Code == code {
			if r.Concerns[i].Count == math.MaxInt64 {
				return ErrObservation
			}
			r.Concerns[i].Count++
			if len(r.Concerns[i].Samples) < MaxSamples {
				r.Concerns[i].Samples = append(r.Concerns[i].Samples, sample)
			}
			return nil
		}
	}
	if len(r.Concerns) >= MaxCategories {
		return ErrObservation
	}
	r.Concerns = append(r.Concerns, Concern{Code: code, Count: 1, Samples: []string{sample}})
	return nil
}
func ledgerMatches(l store.RetirementLedger, member, relationship, role string) bool {
	now := time.Now().Unix()
	return l.MemberID == member && l.RelationshipID == relationship && l.Role == role && l.CheckedAt >= now-30 && l.CheckedAt <= now+30 && len(l.Blockers) <= 32 && l.DatabaseClear == (len(l.Blockers) == 0) && l.RequiresPhysicalVerification
}
func (s *Service) Check(ctx context.Context, member, relationship string) (report Report, result error) {
	report = Report{MemberID: member, CheckedAt: time.Now().Unix(), PreflightOnly: true, Concerns: []Concern{}}
	if s.Repository == nil || s.Nodes == nil || s.Client == nil {
		return report, ErrObservation
	}
	identity, e := s.Nodes.ReadIdentity(ctx)
	if e != nil {
		return report, e
	}
	rel, e := s.Nodes.Relationship(ctx, relationship)
	if e != nil {
		return report, e
	}
	if identity.Role != "Master" || identity.ID == member || rel.PeerID != member || rel.Direction != "downstream" || rel.State != "active" {
		return report, ErrObservation
	}
	report.Master, e = s.Repository.RetirementLedger(ctx, relationship, member)
	if e != nil {
		return report, e
	}
	if !ledgerMatches(report.Master, member, relationship, "Master") {
		return report, ErrObservation
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return report, e
	}
	sessionID := hex.EncodeToString(nonce)
	request := map[string]any{"action": "open", "member_id": member, "scope": "data", "session_id": sessionID}
	value, e := s.Client.Call(ctx, rel, route, request)
	if e != nil {
		return report, e
	}
	var session resourceinventory.Session
	if e = decode(value, &session); e != nil {
		return report, e
	}
	request["incarnation"] = session.Incarnation
	defer func() {
		finish, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		closeRequest := map[string]any{"action": "close", "member_id": member, "scope": "data", "session_id": sessionID, "incarnation": session.Incarnation}
		_, e := s.Client.Call(finish, rel, route, closeRequest)
		if e != nil {
			report.ObservationComplete = false
			result = errors.Join(result, e)
		}
	}()
	if session.ID != sessionID || !validToken(session.Incarnation) || session.Binding != (resourceinventory.Binding{MemberID: member, MasterID: identity.ID, RelationshipID: relationship, Scope: "data"}) || session.CreatedAt < time.Now().Unix()-30 || session.CreatedAt > time.Now().Unix()+30 || session.ExpiresAt <= time.Now().Unix() || session.ExpiresAt > time.Now().Add(resourceinventory.SessionTTL).Unix() {
		return report, ErrObservation
	}
	call := func(action string) (map[string]any, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if time.Now().Unix() >= session.ExpiresAt {
			return nil, ErrObservation
		}
		request["action"] = action
		return s.Client.Call(ctx, rel, route, request)
	}
	request["sequence"] = uint64(0)
	value, e = call("ledger")
	if e != nil {
		return report, e
	}
	if e = decode(value, &report.Peer); e != nil {
		return report, e
	}
	if !ledgerMatches(report.Peer, member, relationship, "Follower") {
		return report, ErrObservation
	}
	digest := sha256.New()
	complete := false
	for sequence := uint64(0); sequence < MaxPages; sequence++ {
		request["sequence"] = sequence
		value, e = call("page")
		if e != nil {
			return report, e
		}
		var page struct {
			resourceinventory.SessionPage
			Facts []store.PhysicalInventoryFact `json:"facts"`
		}
		if e = decode(value, &page); e != nil {
			return report, e
		}
		if page.Session != session || page.Page.Sequence != sequence || len(page.Page.Entries) > resourceinventory.PageEntries || len(page.Facts) != len(page.Page.Entries) {
			return report, ErrObservation
		}
		for i, entry := range page.Page.Entries {
			if entry.LogicalBytes < 0 || entry.LogicalBytes > math.MaxInt64-report.LogicalBytes || report.PhysicalEntries == math.MaxUint64 {
				return report, ErrObservation
			}
			report.PhysicalEntries++
			report.LogicalBytes += entry.LogicalBytes
			encoded, e := json.Marshal(entry)
			if e != nil {
				return report, e
			}
			digest.Write(encoded)
			digest.Write([]byte{'\n'})
			fact := page.Facts[i]
			if fact.Blocking {
				if e = report.concern("physical_"+fact.Category, entry.Path); e != nil {
					return report, e
				}
			}
		}
		if page.Page.EntryCount != report.PhysicalEntries || page.Page.LogicalBytes != report.LogicalBytes || page.Page.ObservationSHA256 != hex.EncodeToString(digest.Sum(nil)) {
			return report, ErrObservation
		}
		if page.Page.Complete {
			complete = true
			break
		}
		if len(page.Page.Entries) == 0 {
			return report, ErrObservation
		}
	}
	if !complete {
		return report, ErrObservation
	}
	request["sequence"] = uint64(0)
	for _, resource := range []string{"media", "recording", "backup", "backup_chunk"} {
		request["resource"] = resource
		after := ""
		complete = false
		for pageNumber := 0; pageNumber < MaxPages; pageNumber++ {
			request["after"] = after
			value, e = call("expected")
			if e != nil {
				return report, e
			}
			var page struct {
				Session  resourceinventory.Session    `json:"session"`
				Manifest store.ExpectedPhysicalPage   `json:"manifest"`
				Presence []resourceinventory.Presence `json:"presence"`
			}
			if e = decode(value, &page); e != nil {
				return report, e
			}
			if page.Session != session || page.Manifest.Resource != resource || page.Manifest.After != after || len(page.Manifest.Items) > 16 || len(page.Presence) != len(page.Manifest.Items) {
				return report, ErrObservation
			}
			last := after
			for i, item := range page.Manifest.Items {
				cursor := item.ObjectID
				if item.Cursor != "" {
					cursor = item.Cursor
				}
				if cursor <= last || report.ExpectedItems == math.MaxUint64 {
					return report, ErrObservation
				}
				last = cursor
				report.ExpectedItems++
				observed := page.Presence[i]
				switch observed.State {
				case "present", "database_backed_unverified", "pending_backup", "missing", "unsupported", "invalid_path", "changed", "unverified", "length_mismatch":
				default:
					return report, ErrObservation
				}
				sample := item.Path
				if sample == "" {
					sample = item.ObjectID
				}
				if observed.State != "present" {
					if e = report.concern("expected_"+observed.State, sample); e != nil {
						return report, e
					}
				}
				if resource == "backup" || resource == "backup_chunk" {
					if e = report.concern("backup_retention_required", sample); e != nil {
						return report, e
					}
				}
			}
			if page.Manifest.Next != last {
				return report, ErrObservation
			}
			if page.Manifest.Complete {
				complete = true
				break
			}
			if last == after {
				return report, ErrObservation
			}
			after = last
		}
		if !complete {
			return report, ErrObservation
		}
	}
	delete(request, "resource")
	delete(request, "after")
	value, e = call("ledger")
	if e != nil {
		return report, e
	}
	var finalPeer store.RetirementLedger
	if e = decode(value, &finalPeer); e != nil {
		return report, e
	}
	if !ledgerMatches(finalPeer, member, relationship, "Follower") {
		return report, ErrObservation
	}
	finalMaster, e := s.Repository.RetirementLedger(ctx, relationship, member)
	if e != nil {
		return report, e
	}
	if !ledgerMatches(finalMaster, member, relationship, "Master") {
		return report, ErrObservation
	}
	// Latest ledgers replace the initial diagnostic facts; neither equal counts
	// nor a completed observation substitutes for a frozen final transaction.
	report.Master = finalMaster
	report.Peer = finalPeer
	for _, ledger := range []store.RetirementLedger{report.Master, report.Peer} {
		for _, block := range ledger.Blockers {
			if block.Count <= 0 || len(block.SampleIDs) > 8 || strings.TrimSpace(block.Code) == "" {
				return report, ErrObservation
			}
		}
	}
	report.ObservationComplete = true
	return report, nil
}
