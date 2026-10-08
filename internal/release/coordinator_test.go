package release

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Embedding makes every unintended repository call panic. Release permission
// must use fresh local identity, not enumerate/probe storage appliances.
type localReleaseNodes struct {
	store.NodeRepository
	identity store.NodeIdentity
	reads    int
	change   bool
}

func (n *localReleaseNodes) ReadIdentity(context.Context) (store.NodeIdentity, error) {
	n.reads++
	out := n.identity
	if n.change && n.reads > 1 {
		out.ID = "replacement"
	}
	return out, nil
}

type localReleaseAgent struct {
	value   map[string]any
	starts  int
	request map[string]any
}

func (a *localReleaseAgent) Request(_ context.Context, request map[string]any) (map[string]any, error) {
	if request["action"] == "status" {
		return map[string]any{"ok": true, "status": a.value}, nil
	}
	a.starts++
	a.request = request
	return map[string]any{"ok": true}, nil
}

type localReleaseEvidence struct {
	head, proof                 map[string]any
	versions                    []Version
	historyCalls, artifactCalls int
	err                         error
}

func (e *localReleaseEvidence) Status(context.Context, bool) (map[string]any, error) {
	return e.head, e.err
}
func (e *localReleaseEvidence) History(context.Context) ([]Version, error) {
	e.historyCalls++
	return e.versions, e.err
}
func (e *localReleaseEvidence) Artifact(context.Context, string) (map[string]any, error) {
	e.artifactCalls++
	return e.proof, e.err
}
func localReleaseFixture() (*Coordinator, *localReleaseNodes, *localReleaseAgent, *localReleaseEvidence) {
	nodes := &localReleaseNodes{identity: store.NodeIdentity{ID: "master", Role: "Master"}}
	agent := &localReleaseAgent{value: map[string]any{"state": "success", "release_branch": "main", "current_sha": strings.Repeat("a", 40), "previous_sha": strings.Repeat("b", 40)}}
	target := strings.Repeat("c", 40)
	evidence := &localReleaseEvidence{head: map[string]any{"publishable": true, "sha": target}, versions: []Version{{SHA: target}}, proof: map[string]any{"publishable": true, "sha": target, "branch": "main", "source_branch": "dev"}}
	return &Coordinator{Nodes: nodes, Agent: agent, Verifier: evidence, Policy: DefaultPolicy()}, nodes, agent, evidence
}
func TestMasterSelfReleaseNeverEnumeratesOrCommandsStorage(t *testing.T) {
	service, _, agent, _ := localReleaseFixture()
	ctx := context.Background()
	status, err := service.Status(ctx, false)
	if err != nil || status["can_upgrade"] != true || status["followers"] != nil {
		t.Fatal(status, err)
	}
	if _, err = service.Start(ctx, "upgrade"); err != nil {
		t.Fatal(err)
	}
	if agent.starts != 1 || agent.request["hold_maintenance"] != false || agent.request["target_sha"] != strings.Repeat("c", 40) {
		t.Fatal(agent.request)
	}
}
func TestMasterSelfReleaseGuardsIdentityPolicyBusyAndEvidence(t *testing.T) {
	for _, kind := range []string{"storage", "changed-identity", "busy", "bad-policy", "bad-ci", "same-sha", "invalid-sha", "network", "override", "invalid-mode"} {
		t.Run(kind, func(t *testing.T) {
			service, nodes, agent, evidence := localReleaseFixture()
			mode, target := "upgrade", ""
			switch kind {
			case "storage":
				nodes.identity.Role = "Follower"
			case "changed-identity":
				nodes.change = true
			case "busy":
				agent.value["state"] = "running"
			case "bad-policy":
				agent.value["release_branch"] = "other"
			case "bad-ci":
				evidence.head["publishable"] = false
			case "same-sha":
				evidence.head["sha"] = agent.value["current_sha"]
			case "invalid-sha":
				evidence.head["sha"] = "short"
			case "network":
				evidence.err = errors.New("offline")
			case "override":
				target = strings.Repeat("d", 40)
			case "invalid-mode":
				mode = "remote"
			}
			if _, err := service.StartVersion(context.Background(), mode, target); err == nil || agent.starts != 0 {
				t.Fatal("unsafe local start", err, agent.starts)
			}
		})
	}
}
func TestHistoricalRollbackRequiresListedExactReviewedArtifact(t *testing.T) {
	for _, kind := range []string{"valid", "unknown", "failed-ci", "foreign-branch", "foreign-source", "wrong-sha", "invalid-sha", "changed-identity", "network"} {
		t.Run(kind, func(t *testing.T) {
			service, nodes, agent, evidence := localReleaseFixture()
			target := strings.Repeat("c", 40)
			switch kind {
			case "unknown":
				evidence.versions = nil
			case "failed-ci":
				evidence.proof["publishable"] = false
			case "foreign-branch":
				evidence.proof["branch"] = "other"
			case "foreign-source":
				evidence.proof["source_branch"] = "other"
			case "wrong-sha":
				evidence.proof["sha"] = strings.Repeat("d", 40)
			case "invalid-sha":
				target = "short"
			case "changed-identity":
				nodes.change = true
			case "network":
				evidence.err = errors.New("offline")
			}
			_, err := service.StartVersion(context.Background(), "rollback", target)
			if (err == nil) != (kind == "valid") || (agent.starts == 1) != (kind == "valid") {
				t.Fatal(kind, err, agent.starts)
			}
		})
	}
}
func TestLocalPreviousRollbackDoesNotRequireGithubAvailability(t *testing.T) {
	service, _, agent, evidence := localReleaseFixture()
	evidence.err = errors.New("github unavailable")
	if _, err := service.Start(context.Background(), "rollback"); err != nil {
		t.Fatal(err)
	}
	if evidence.historyCalls != 0 || evidence.artifactCalls != 0 || agent.request["target_sha"] != strings.Repeat("b", 40) {
		t.Fatal(agent.request)
	}
}
