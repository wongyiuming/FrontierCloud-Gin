package httpapi

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// ConfigureSealedMaster installs the authenticated Master-side readers and
// catalog. It does not activate a storage node as the public ingress.
func (p *Public) ConfigureSealedMaster(router *gin.Engine, tree *sealedtree.SQLStore) (*OpaqueCatalogPreparer, error) {
	if p == nil || p.control == nil || p.media == nil || p.crypto == nil || tree == nil || p.opaqueTree != tree || p.localCatalogPreparer != nil || !p.control.IngressSelectionConfigured() {
		return nil, store.ErrNodeState
	}
	resolve, err := p.media.SealedCatalogOwnerResolver(tree)
	if err != nil {
		return nil, err
	}
	localMedia, err := RegisterOpaqueMasterLocalMedia(router, p.settings, p.settings.PublicOrigin, p.media, p.control, p.crypto, tree)
	if err != nil {
		return nil, err
	}
	localLyric, err := RegisterOpaqueMasterLocalLyric(router, p.settings, p.settings.PublicOrigin, p.media, p.control, p.crypto, tree)
	if err != nil {
		return nil, err
	}
	localRelay, err := RegisterOpaqueLocalFollowerRelay(router, p.settings, p.settings.PublicOrigin, p.media, p.control, p.crypto, tree)
	if err != nil {
		return nil, err
	}
	peerRelay, err := RegisterOpaqueFollowerRelay(router, p.media, p.control, p.crypto, tree)
	if err != nil {
		return nil, err
	}
	if p.masterDirect != nil {
		if err := p.masterDirect.ConfigureOpaqueLyricTree(tree); err != nil {
			return nil, err
		}
	}
	if err := p.masterRelay.ConfigureOpaqueLyricTree(tree); err != nil {
		return nil, err
	}
	p.opaqueTree, p.masterLocalMedia, p.masterLocalLyric, p.localFollowerRelay = tree, localMedia, localLyric, localRelay
	p.opaqueFollowerRelay = peerRelay
	p.localCatalogPreparer = &OpaqueCatalogPreparer{Router: router, Resolve: resolve, VerifyFacts: media.NativeCatalogFactsVerifier(tree)}
	return p.localCatalogPreparer, nil
}

// ConfigureSealedUploads binds the existing Admin routes to the same crypto
// manager and tree used by the readers. Startup supplies both actual Owners.
func (a *Admin) ConfigureSealedUploads(repo *business.Repository, nodeVault *vault.Vault, gate business.SelectedUploadRuntimeGate, local business.SelectedLocalOwner, relay business.SelectedRelaySender) error {
	if a == nil || a.public == nil || a.public.opaqueTree == nil {
		return store.ErrNodeState
	}
	tree := a.public.opaqueTree
	key, err := tree.CapacityKey()
	if err != nil {
		return err
	}
	defer clear(key)
	runtime, err := business.NewSelectedUploadRuntime(repo, tree, key, a.public.crypto, nodeVault, a.settings.AdminOrigin, gate)
	if err != nil {
		return err
	}
	if err := runtime.ConfigureLocalOwner(local); err != nil {
		return err
	}
	if err := runtime.ConfigureRelaySender(relay); err != nil {
		return err
	}
	return a.ConfigureSelectedUploadRuntime(runtime)
}

// ConfigureSealedRecordingRead installs the Local ciphertext reader on the
// same runtime used by the encrypted Master. Write admission is independent
// and requires the sealed cancellation and deletion lifecycle.
func (a *Admin) ConfigureSealedRecordingRead(accounts *KaraokeAccounts) error {
	if a == nil || accounts == nil || a.identity == nil || a.public == nil || accounts.public != a.public || a.public.media == nil || a.selectedUpload == nil ||
		!a.selectedUpload.Matches(a.public.opaqueTree, a.public.crypto, a.settings.AdminOrigin) {
		return store.ErrNodeState
	}
	return accounts.ConfigureRecordingAudioRead(func(ctx context.Context, tree *sealedtree.SQLStore, ingress store.PublicIngress, user store.KaraokeUser, browser, id string, checkAccount func(context.Context) error) (*business.RecordingAudioStream, error) {
		if ingress.PublicOrigin != a.settings.PublicOrigin || ingress.NodeID != a.identity.ID {
			return nil, store.ErrNodeState
		}
		return a.selectedUpload.OpenRecordingAudioLocal(ctx, tree, ingress, user, browser, id, a.public.media, checkAccount)
	})
}

// ConfigureSealedRecordingDirect binds the recording controls to the same
// encrypted tree, account service and node transport as the Master runtime.
func (a *Admin) ConfigureSealedRecordingDirect(accounts *KaraokeAccounts, repo *business.Repository) error {
	if a == nil || accounts == nil || repo == nil || a.public == nil || accounts.public != a.public ||
		a.public.control == nil || a.selectedUpload == nil || accounts.recordingAudioDirect != nil ||
		!a.selectedUpload.Matches(a.public.opaqueTree, a.public.crypto, a.settings.AdminOrigin) {
		return store.ErrNodeState
	}
	if err := accounts.ConfigureRecordingAudioPreparation(repo.ReserveRecordingAudioPreparation); err != nil {
		return err
	}
	accounts.service.ConfigureSealedUserDeletion(func(ctx context.Context, id string, expected *store.KaraokeUser, audit store.KaraokeAudit) (bool, error) {
		return repo.DeleteEmptySealedUser(ctx, a.public.opaqueTree, id, expected, audit)
	})
	accounts.recordingAudioDirect = a.selectedUpload
	return nil
}

// SealedS3RuntimeGate must be the same lifecycle-owned gate for upload,
// provider configuration, source signing and catalog admission. Startup must
// independently prove pending-provider reconciliation and arrange config and
// delete drains before installing it; a constructed gate alone is not proof.
type SealedS3RuntimeGate interface {
	business.SelectedS3Readiness
	media.OpaqueS3ReadGate
	media.OpaqueS3CatalogGate
	ConfigureSelectedS3Origins(string, string) error
}

// ConfigureSealedS3 is startup-only and targets the already installed Master
// tree and selected upload runtime. No fallback or provider setup is implied.
func (a *Admin) ConfigureSealedS3(provider business.SelectedS3Provider, gate SealedS3RuntimeGate) error {
	if a == nil || a.public == nil || a.public.media == nil || a.public.opaqueTree == nil || a.selectedUpload == nil || !a.selectedUpload.Matches(a.public.opaqueTree, a.public.crypto, a.settings.AdminOrigin) {
		return store.ErrNodeState
	}
	coordinator, err := business.NewSelectedS3Coordinator(a.selectedUpload, provider, gate)
	if err != nil {
		return err
	}
	if err = gate.ConfigureSelectedS3Origins(a.settings.AdminOrigin, a.settings.PublicOrigin); err != nil {
		return err
	}
	if err = a.selectedUpload.ConfigureSelectedS3(coordinator); err != nil {
		return err
	}
	return a.public.media.ConfigureOpaqueS3Read(a.public.opaqueTree, gate)
}
