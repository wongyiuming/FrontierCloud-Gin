package release

import (
	"context"
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type Evidence interface {
	Status(context.Context, bool) (map[string]any, error)
}
type HistoryEvidence interface {
	History(context.Context) ([]Version, error)
	Artifact(context.Context, string) (map[string]any, error)
}

// Coordinator manages this business authority only. Storage reachability or
// binary versions are deliberately absent from release permission and progress.
type Coordinator struct {
	Agent     Agent
	Verifier  Evidence
	Nodes     store.NodeRepository
	Policy    Policy
	CDManaged bool
}

func (s *Coordinator) Status(ctx context.Context, refresh bool) (map[string]any, error) {
	n, err := s.Nodes.ReadIdentity(ctx)
	if err != nil {
		return nil, err
	}
	local := AgentStatus(ctx, s.Agent)
	ci, err := s.Verifier.Status(ctx, refresh)
	if err != nil {
		return nil, err
	}
	current, err := s.Nodes.ReadIdentity(ctx)
	if err != nil {
		return nil, err
	}
	ready := !s.CDManaged && s.Policy.Valid() && local["release_branch"] == s.Policy.Branch && current.ID == n.ID && current.Role == n.Role
	detail := ""
	if !ready {
		detail = "local updater policy or identity mismatch"
	}
	if s.CDManaged {
		detail = "preproduction is managed by verified dev CD, not production release actions"
	}
	target, _ := ci["sha"].(string)
	previous, _ := local["previous_sha"].(string)
	return map[string]any{"role": current.Role, "release_branch": s.Policy.Branch, "ci": ci, "local": local, "release_policy_ready": ready, "release_policy_detail": detail,
		"can_upgrade":  current.Role == "Master" && ready && ci["publishable"] == true && ValidSHA(target) && target != local["current_sha"] && !Busy(local["state"]),
		"can_rollback": current.Role == "Master" && ready && ValidSHA(previous) && !Busy(local["state"])}, nil
}
func (s *Coordinator) History(ctx context.Context) ([]Version, error) {
	evidence, ok := s.Verifier.(HistoryEvidence)
	if !ok {
		return nil, errors.New("release history unavailable")
	}
	return evidence.History(ctx)
}
func (s *Coordinator) Start(ctx context.Context, mode string) (map[string]any, error) {
	return s.StartVersion(ctx, mode, "")
}
func (s *Coordinator) StartVersion(ctx context.Context, mode, target string) (map[string]any, error) {
	if s.CDManaged {
		return nil, errors.New("preproduction release actions belong to verified dev CD")
	}
	if mode != "upgrade" && mode != "rollback" {
		return nil, errors.New("invalid release mode")
	}
	n, err := s.Nodes.ReadIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if n.Role != "Master" {
		return nil, store.ErrNodeState
	}
	local := AgentStatus(ctx, s.Agent)
	if !s.Policy.Valid() || local["release_branch"] != s.Policy.Branch || Busy(local["state"]) {
		return nil, errors.New("local release unavailable or busy")
	}
	if mode == "upgrade" {
		if target != "" {
			return nil, errors.New("upgrade target comes from verified release HEAD")
		}
		ci, err := s.Verifier.Status(ctx, false)
		if err != nil {
			return nil, err
		}
		target, _ = ci["sha"].(string)
		if ci["publishable"] != true || !ValidSHA(target) {
			return nil, errors.New("release HEAD lacks reviewed source CI proof")
		}
		if target == local["current_sha"] {
			return nil, errors.New("latest release already installed")
		}
	} else if target == "" {
		target, _ = local["previous_sha"].(string)
	} else {
		evidence, ok := s.Verifier.(HistoryEvidence)
		if !ok || !ValidSHA(target) {
			return nil, errors.New("invalid historical release")
		}
		versions, err := evidence.History(ctx)
		if err != nil {
			return nil, err
		}
		found := false
		for _, version := range versions {
			if version.SHA == target {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("rollback target is not a listed reviewed release")
		}
		proof, err := evidence.Artifact(ctx, target)
		if err != nil {
			return nil, err
		}
		if proof["publishable"] != true || proof["sha"] != target || proof["branch"] != s.Policy.Branch || proof["source_branch"] != s.Policy.Source {
			return nil, errors.New("historical release lacks exact reviewed CI proof")
		}
	}
	if !ValidSHA(target) || target == local["current_sha"] {
		return nil, errors.New("no distinct verified rollback target")
	}
	current, err := s.Nodes.ReadIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if current.ID != n.ID || current.Role != "Master" {
		return nil, store.ErrNodeState
	}
	if s.Agent == nil {
		return nil, errors.New("updater unavailable")
	}
	out, err := s.Agent.Request(ctx, map[string]any{"action": "start", "target_sha": target, "mode": mode, "hold_maintenance": false})
	if err != nil {
		return nil, err
	}
	if out["ok"] != true {
		return nil, errors.New("updater rejected release")
	}
	return out, nil
}
