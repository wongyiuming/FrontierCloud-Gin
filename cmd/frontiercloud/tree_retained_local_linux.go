//go:build linux

package main

import (
	"context"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func verifyRetainedTreeLocal(ctx context.Context, gate *maintenance.Gate, request runtimefacts.TreeRetainedRecoveryRequest, paths [2]string, checkMounts func() error) (runtimefacts.TreeRetainedLocalProof, error) {
	var result runtimefacts.TreeRetainedLocalProof
	data, secrets := paths[0], paths[1]
	dbPath := filepath.Join(data, request.DatabaseRelative)
	err := gate.InspectExistingSQLite(ctx, data, dbPath, func(held context.Context, checkSQLite func() error) error {
		check := func(c context.Context) error {
			if checkMounts() != nil || checkSQLite() != nil || gate.InspectTreeRecoveryHoldBinding(c, request.BindingSHA256) != nil {
				return maintenance.ErrState
			}
			return c.Err()
		}
		if err := check(held); err != nil {
			return err
		}
		database, err := sqlitestore.OpenReadOnly(held, dbPath)
		if err != nil {
			return err
		}
		defer database.Close()
		identity, err := node.OpenExisting(held, database.Nodes(), secrets)
		if err != nil || identity.Role != "Master" || identity.ID != request.NodeID {
			return store.ErrNodeState
		}
		settings := config.Config{DataRoot: data, SQLitePath: dbPath, SecretsDirectory: secrets, DatabaseType: config.DatabaseSQLite, DeploymentMode: config.DeploymentBusiness, TLSEnabled: true}
		ownerRuntime, err := openRuntimeOwner(held, settings, database, identity)
		if err != nil || ownerRuntime == nil {
			return store.ErrNodeState
		}
		defer ownerRuntime.Close()
		tree, closeTree, err := openOpaqueMasterTree(held, database, settings)
		if err != nil || tree == nil {
			return store.ErrNodeState
		}
		defer closeTree()
		key, err := tree.CapacityKey()
		if err != nil {
			return err
		}
		defer clear(key)
		nodeVault, err := vault.OpenExisting(secrets)
		if err != nil {
			return err
		}
		repo, ok := database.Nodes().(*business.Repository)
		if !ok {
			return store.ErrNodeState
		}
		volume, err := media.OpenOpaqueRecoveryVolume(filepath.Join(data, "media"), database.Media(), repo, identity)
		if err != nil {
			return err
		}
		defer volume.Close()
		report := recovery.Report{Manifest: *request.Manifest, SHA256: request.ArchiveSHA256}
		var proof runtimefacts.TreeRetainedLocalProof
		var verifyRebind func() error
		err = volume.VisitRecoveryOpaqueSession(held, identity.ID, func(ownerContext context.Context) (plan media.RecoveryOpaqueSessionPlan, err error) {
			owner, err := repo.AcquireOwnerControlShared(ownerContext)
			if err != nil {
				return plan, err
			}
			lease, err := tree.AcquireReadFence(ownerContext)
			if err != nil {
				owner.Release()
				return plan, err
			}
			plan.Release = func() { lease.Release(); owner.Release() }
			plan.Check = func(c context.Context) error {
				if check(c) != nil || owner.Check(c) != nil {
					return store.ErrNodeState
				}
				return lease.Check(c)
			}
			verifyRebind = func() error {
				return tree.VerifyRetainedMasterRebind(ownerContext, lease, report, data, secrets, request.DatabaseRelative, identity.ID)
			}
			if err := verifyRebind(); err != nil {
				return plan, err
			}
			if err := verifyRetainedOwnerRoster(ownerContext, repo, request.Manifest.Relations); err != nil {
				return plan, err
			}
			expected, err := repo.BuildRecoveryExpectations(ownerContext, owner, tree, lease, key, nodeVault)
			if err != nil {
				return plan, err
			}
			proof.Version, proof.TreeGeneration = 1, expected.Accounting.TreeGeneration
			proof.Media, proof.Recordings = expected.Accounting.Media, expected.Accounting.Recordings
			for _, group := range expected.Owners {
				switch group.Kind {
				case "MasterLocal":
					if group.ID != identity.ID {
						return plan, store.ErrNodeState
					}
					proof.LocalObjects, proof.LocalBytes = group.Objects, group.Bytes
					plan.Items = make([]media.RecoveryOpaqueSessionItem, 0, len(group.Media)+len(group.Recordings))
					for _, placements := range [][]sealedtree.RecoveryMediaPlacement{group.Media, group.Recordings} {
						for _, item := range placements {
							plan.Items = append(plan.Items, media.RecoveryOpaqueSessionItem{Placement: item})
						}
					}
				case "Follower":
					proof.FollowerOwners++
				case "S3":
					proof.S3Owners++
				}
			}
			if plan.Items == nil || proof.FollowerOwners != len(request.Manifest.Relations) {
				return plan, store.ErrNodeState
			}
			return plan, plan.Check(ownerContext)
		}, func(observed media.RecoveryOpaqueSessionResult) error {
			if observed.Version != 1 || int64(observed.Objects) != proof.LocalObjects {
				return store.ErrNodeState
			}
			proof.CensusCommitment, proof.ProofCommitment = observed.CensusCommitment, observed.ProofCommitment
			if !proof.Valid() {
				return store.ErrNodeState
			}
			return verifyRebind()
		})
		if err != nil {
			return err
		}
		if err := check(held); err != nil {
			return err
		}
		result = proof
		return nil
	})
	if err != nil {
		return runtimefacts.TreeRetainedLocalProof{}, err
	}
	return result, nil
}

func verifyRetainedOwnerRoster(ctx context.Context, repo *business.Repository, expected []recovery.Relation) error {
	snapshot, err := repo.InspectMaintenance(ctx)
	if err != nil || snapshot.Role != "Master" || snapshot.LogicalIdle || snapshot.Pending["sealed_tree_unrecoverable"] != 1 {
		return store.ErrNodeState
	}
	for name, count := range snapshot.Pending {
		if name != "sealed_tree_unrecoverable" && count != 0 {
			return store.ErrNodeState
		}
	}
	relations, err := repo.Relationships(ctx, false)
	if err != nil || len(relations) != len(expected) || len(expected) > recovery.MaxSetMembers {
		return store.ErrNodeState
	}
	wanted := make(map[string]recovery.Relation, len(expected))
	for _, rel := range expected {
		if rel.Direction != "downstream" || rel.State != "active" || rel.Protocol != protocol.Version || wanted[rel.NodeID].NodeID != "" {
			return store.ErrNodeState
		}
		wanted[rel.NodeID] = rel
	}
	for _, rel := range relations {
		if wanted[rel.PeerID] != (recovery.Relation{NodeID: rel.PeerID, Direction: rel.Direction, State: rel.State, Protocol: rel.Protocol}) {
			return store.ErrNodeState
		}
		delete(wanted, rel.PeerID)
	}
	return nil
}
