package store

import (
	"context"
	"errors"
)

var ErrPriorityStale = errors.New("priority order changed")
var ErrPriorityRange = errors.New("priority range cannot represent requested order")
var ErrPriorityMove = errors.New("invalid priority move")

const PriorityMinimum = -7
const PriorityMaximum = 500000

// Objects are trusted filesystem siblings supplied by the media service. A
// Master derives its siblings from its own placement ledger instead.
type PriorityScope struct {
	Path, Kind string
	Objects    []MediaObject
}

type PriorityEntry struct {
	ID         string `json:"media_id,omitempty"`
	Path       string `json:"path"`
	Preference int    `json:"preference"`
	ObjectKind string `json:"-"`
}

type PriorityOrder struct {
	Scope    string          `json:"scope"`
	Kind     string          `json:"kind"`
	Revision string          `json:"revision"`
	Items    []PriorityEntry `json:"items"`
	Changed  int             `json:"changed"`
}

type PriorityMove struct {
	Revision string `json:"revision"`
	Path     string `json:"path"`
	Before   string `json:"before"`
	After    string `json:"after"`
}

type PriorityRepository interface {
	PriorityOrder(context.Context, PriorityScope) (PriorityOrder, error)
	MovePriority(context.Context, PriorityScope, PriorityMove, AdminAudit) (PriorityOrder, error)
}
