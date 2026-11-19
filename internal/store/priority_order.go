package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"golang.org/x/text/cases"
)

// Directory ties follow the public category comparator; media ties follow the
// public playback comparator. The planner must use those exact comparators.
func priorityTie(a, b PriorityEntry, kind string) bool {
	if kind == "directory" {
		fold := cases.Fold()
		x, y := fold.String(a.Path), fold.String(b.Path)
		if x != y {
			return x < y
		}
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	return a.ID < b.ID
}

func priorityRevision(scope, kind string, items []PriorityEntry) string {
	data, _ := json.Marshal(struct {
		Path, Kind string
		Items      []PriorityEntry
	}{scope, kind, items})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NewPriorityOrder sorts siblings with the public comparators and computes a
// deterministic revision digest of the scope and ordered items.
func NewPriorityOrder(scope, kind string, items []PriorityEntry) PriorityOrder {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Preference != items[j].Preference {
			return items[i].Preference > items[j].Preference
		}
		return priorityTie(items[i], items[j], kind)
	})
	return PriorityOrder{Scope: scope, Kind: kind, Items: items, Revision: priorityRevision(scope, kind, items)}
}

// PlanPriorityMove checks a displayed revision and its requested neighbours.
// It returns a new order without modifying the caller's snapshot.
func PlanPriorityMove(current PriorityOrder, move PriorityMove) ([]PriorityEntry, error) {
	if move.Revision != current.Revision {
		return nil, ErrPriorityStale
	}
	if move.Path == "" || move.Before == move.Path || move.After == move.Path || (move.Before == "" && move.After == "") {
		return nil, ErrPriorityMove
	}
	items := make([]PriorityEntry, 0, len(current.Items))
	var moved PriorityEntry
	for _, v := range current.Items {
		if v.Path == move.Path {
			moved = v
		} else {
			items = append(items, v)
		}
	}
	if moved.Path == "" {
		return nil, ErrPriorityMove
	}
	at := -1
	for i := 0; i <= len(items); i++ {
		before, after := "", ""
		if i < len(items) {
			before = items[i].Path
		}
		if i > 0 {
			after = items[i-1].Path
		}
		if before == move.Before && after == move.After {
			at = i
			break
		}
	}
	if at < 0 {
		return nil, ErrPriorityMove
	}
	items = append(items, PriorityEntry{})
	copy(items[at+1:], items[at:])
	items[at] = moved
	if e := planPriority(items, at, current.Kind); e != nil {
		return nil, e
	}
	return items, nil
}

// Each canonical inversion needs one integer step. Expand a contiguous window
// until those steps fit between its unchanged neighbours. Work is linear; no
// catalog-wide unique renumbering, fractional ranks or new tie-break
func planPriority(items []PriorityEntry, at int, kind string) error {
	return planPriorityRange(items, at, kind, PriorityMinimum, PriorityMaximum)
}

func planPriorityRange(items []PriorityEntry, at int, kind string, minimum, maximum int) error {
	n := len(items)
	gap := make([]int, n)
	for i := 1; i < n; i++ {
		gap[i] = gap[i-1]
		if !priorityTie(items[i-1], items[i], kind) {
			gap[i]++
		}
	}
	l, r := at, at
	limits := func(l, r int) (int, int) {
		hi, lo := maximum, minimum
		if l > 0 {
			hi = items[l-1].Preference - (gap[l] - gap[l-1])
		}
		if r+1 < n {
			lo = items[r+1].Preference + (gap[r+1] - gap[r])
		}
		return hi, lo
	}
	for {
		hi, lo := limits(l, r)
		if hi-lo >= gap[r]-gap[l] {
			for i := l; i <= r; i++ {
				minimum := lo + gap[r] - gap[i]
				items[i].Preference = max(minimum, min(hi, items[i].Preference))
				if i < r {
					hi = items[i].Preference - (gap[i+1] - gap[i])
				}
			}
			return nil
		}
		if l == 0 && r == n-1 {
			return ErrPriorityRange
		}
		leftGain, rightGain := -1, -1
		if l > 0 {
			upper, _ := limits(l-1, r)
			leftGain = upper - hi - (gap[l] - gap[l-1])
		}
		if r+1 < n {
			_, lower := limits(l, r+1)
			rightGain = lo - lower - (gap[r+1] - gap[r])
		}
		if l > 0 && (r == n-1 || leftGain > rightGain || leftGain == rightGain && at-l <= r-at) {
			l--
		} else {
			r++
		}
	}
}
