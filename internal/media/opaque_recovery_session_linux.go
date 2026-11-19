//go:build linux

package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// OpenOpaqueRecoveryVolume opens an existing volume for the recovery session
// without starting normal media startup, creating locks, or repairing files.
func OpenOpaqueRecoveryVolume(directory string, repository store.MediaRepository, nodes store.NodeRepository, identity *node.Identity) (*Service, error) {
	if !recoveryValuePresent(repository) || !recoveryValuePresent(nodes) || identity == nil {
		return nil, store.ErrNodeState
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	return &Service{root: root, repository: repository, nodes: nodes, identity: identity}, nil
}

// RecoveryOpaqueSessionItem is a trusted projection, never a browser input.
// Selected recordings use Kind "recording" and their authenticated 32-hex
// recording ID; the other fields come from the verified recording inventory.
type RecoveryOpaqueSessionItem struct {
	Placement sealedtree.RecoveryMediaPlacement
	Binding   *OpaqueOwnerBinding
}

// The caller constructs the complete selected media and recording union while
// holding the Owner-exclusive context, then acquires its tree lease before
// returning. Check must validate that tree/recording authority and settled
// operation state remains valid; Release closes those leases. No caller should
// infer that an empty staging/ proves all operation journals are settled.
type RecoveryOpaqueSessionPlan struct {
	Items   []RecoveryOpaqueSessionItem
	Check   func(context.Context) error
	Release func()
}

type RecoveryOpaqueSessionResult struct {
	Version          int    `json:"version"`
	Objects          int    `json:"objects"`
	CensusCommitment string `json:"census_commitment"`
	ProofCommitment  string `json:"proof_commitment"`
}

// VisitRecoveryOpaqueSession obtains Owner exclusive -> caller tree -> shared
// volume in that order. prepare must take the actual tree/recording authority,
// produce the full authenticated Owner union, and prove other operation states
// settled; it must not acquire the volume lock. visit must not reenter Service.
// All results remain provisional until the function returns nil. The session
// checks this volume's staging/ is empty but does not claim other staging or
// operation journals are empty. This is not a cross-Owner or hostile-host proof.
func (s *Service) VisitRecoveryOpaqueSession(ctx context.Context, ownerID string, prepare func(context.Context) (RecoveryOpaqueSessionPlan, error), visit func(RecoveryOpaqueSessionResult) error) error {
	if s == nil || s.root == nil || ctx == nil || prepare == nil || visit == nil || ownerID == "" || !recoveryValuePresent(s.nodes) {
		return store.ErrNodeState
	}
	coordinator, ok := s.nodes.(store.OwnerControlCoordinator)
	if !ok {
		return store.ErrNodeState
	}
	borrower, ok := s.nodes.(interface {
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if !ok {
		return store.ErrNodeState
	}
	return coordinator.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		owner, err := borrower.AcquireOwnerControlShared(held)
		if err != nil {
			return err
		}
		if !recoveryValuePresent(owner) {
			return store.ErrNodeState
		}
		defer owner.Release()
		plan, err := prepare(held)
		if err != nil {
			if plan.Release != nil {
				plan.Release()
			}
			return err
		}
		if plan.Release == nil || plan.Check == nil {
			if plan.Release != nil {
				plan.Release()
			}
			return store.ErrNodeState
		}
		defer plan.Release()
		if len(plan.Items) > 100000 || plan.Check(held) != nil || owner.Check(held) != nil {
			return store.ErrNodeState
		}
		items := append([]RecoveryOpaqueSessionItem(nil), plan.Items...)
		for i := range items {
			if items[i].Binding != nil {
				copied := *items[i].Binding
				items[i].Binding = &copied
			}
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Placement.BlobID < items[j].Placement.BlobID })
		ids := make([]string, len(items))
		for i, item := range items {
			ids[i] = item.Placement.BlobID
			if item.Placement.OwnerID != ownerID || (i > 0 && ids[i-1] == ids[i]) {
				return store.ErrNodeState
			}
		}
		release, volumeCheck, err := s.recoveryOpaqueVolume(held)
		if err != nil {
			return err
		}
		defer release()
		stageCheck, stageRelease, err := s.recoveryEmptyStage()
		if err != nil {
			return err
		}
		defer stageRelease()
		check := func() error {
			if held.Err() != nil || owner.Check(held) != nil || plan.Check(held) != nil || volumeCheck() != nil || stageCheck() != nil {
				return store.ErrNodeState
			}
			return nil
		}
		if check() != nil {
			return store.ErrNodeState
		}
		var census RecoveryOpaqueCensus
		if err = s.visitRecoveryOpaqueCensus(held, owner, ownerID, ids, func(p RecoveryOpaqueCensus) error { census = p; return check() }, check); err != nil {
			return err
		}
		h := sha256.New()
		h.Write([]byte("frontiercloud:recovery-owner-proofs:v1\x00"))
		for _, item := range items {
			if err = s.visitRecoveryOpaqueProof(held, owner, item.Placement, item.Binding, func(p RecoveryOpaqueProof) error {
				h.Write([]byte(p.PlacementCommitment))
				h.Write([]byte(p.ContentSHA256))
				return check()
			}, check); err != nil {
				return err
			}
		}
		if check() != nil {
			return store.ErrNodeState
		}
		result := RecoveryOpaqueSessionResult{Version: 1, Objects: len(items), CensusCommitment: census.SetCommitment, ProofCommitment: hex.EncodeToString(h.Sum(nil))}
		if err = visit(result); err != nil {
			return err
		}
		return check()
	})
}

// recoveryEmptyStage checks only the BlobPublisher's private staging directory;
// other in-progress authorities must be checked by the authenticated plan.
func (s *Service) recoveryEmptyStage() (func() error, func(), error) {
	before, err := s.root.Lstat("staging")
	if errors.Is(err, os.ErrNotExist) {
		return func() error {
			_, e := s.root.Lstat("staging")
			if !errors.Is(e, os.ErrNotExist) {
				return store.ErrNodeState
			}
			return nil
		}, func() {}, nil
	}
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, store.ErrNodeState
	}
	root, err := s.root.OpenRoot("staging")
	if err != nil {
		return nil, nil, store.ErrNodeState
	}
	check := func() error {
		current, e := s.root.Lstat("staging")
		opened, x := root.Stat(".")
		if e != nil || x != nil || !sameCensusDirectory(before, current) || !sameCensusDirectory(before, opened) {
			return store.ErrNodeState
		}
		return nil
	}
	if check() != nil {
		root.Close()
		return nil, nil, store.ErrNodeState
	}
	f, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, nil, store.ErrNodeState
	}
	entries, readErr := f.ReadDir(1)
	closeErr := f.Close()
	if len(entries) != 0 || !errors.Is(readErr, io.EOF) || closeErr != nil || check() != nil {
		root.Close()
		return nil, nil, store.ErrNodeState
	}
	return check, func() { root.Close() }, nil
}
