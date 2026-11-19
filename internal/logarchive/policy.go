// Package logarchive contains bounded log archive primitives. It is not enabled
// until an administrator selects a verified Direct archive destination.
package logarchive

import (
	"errors"
	"time"
)

const (
	LocalWindow   = 12 * time.Hour
	Retention     = 35 * 24 * time.Hour
	GrantLifetime = 5 * time.Minute
	MaxPlainBytes = 256 * 1024
)

var ErrPolicy = errors.New("log archive policy refused")

type Kind string

const (
	Application Kind = "application"
	Access      Kind = "access"
	Error       Kind = "error"
	Audit       Kind = "audit"
	Security    Kind = "security"
	WebRTC      Kind = "webrtc"
	Node        Kind = "node"
	Certificate Kind = "certificate"
	Job         Kind = "job"
	Browser     Kind = "browser"
)

func Kinds() []Kind {
	return []Kind{Application, Access, Error, Audit, Security, WebRTC, Node, Certificate, Job, Browser}
}

func validKind(k Kind) bool {
	for _, v := range Kinds() {
		if k == v {
			return true
		}
	}
	return false
}

// Destination facts must come from the authenticated node/control repositories,
// never from a browser URL or the historical relationship mode alone.
type Destination struct {
	Native, Active, Online, ResourceReady bool
	ConfiguredTransport, AppliedTransport string
}

func (d Destination) Eligible() bool {
	return d.Native && d.Active && d.Online && d.ResourceReady && d.ConfiguredTransport == "Direct" && d.AppliedTransport == "Direct"
}

// ValidateQuery admits a bounded selection, not server-side keyword work. The
// browser sends only the intent to use keyword filtering, never the keyword.
func ValidateQuery(start, end, now time.Time, kind Kind, keyword bool) error {
	if start.IsZero() || !start.Before(end) || end.After(now) || start.Before(now.Add(-Retention)) || !validKind(kind) {
		return ErrPolicy
	}
	if keyword && end.Sub(start) >= LocalWindow {
		return ErrPolicy
	}
	return nil
}

// ReleaseLocal requires a verified remote commit even after the local window.
// Expiry is separate and does not turn an uncertain upload into a success.
func ReleaseLocal(end, now time.Time, committedAndVerified bool) bool {
	return committedAndVerified && !end.IsZero() && !end.After(now.Add(-LocalWindow))
}

func Expired(end, now time.Time) bool {
	return !end.IsZero() && !end.After(now.Add(-Retention))
}
