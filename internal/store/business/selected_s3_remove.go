package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// CheckSelectedS3MemberUnused is called only while the same S3 control gate
// excludes all S3 writers, after CheckSelectedS3Startup authenticated the
// journal. Even terminal selected history keeps its member binding.
func (r *Repository) CheckSelectedS3MemberUnused(ctx context.Context, tree *sealedtree.SQLStore, key []byte, id string) error {
	return r.checkSelectedS3MemberNoHistory(ctx, tree, key, id, true)
}

// CheckSelectedS3MemberNoHistory also accepts an enabled empty member, so the
// gate can disable it without changing its provider location or credentials.
func (r *Repository) CheckSelectedS3MemberNoHistory(ctx context.Context, tree *sealedtree.SQLStore, key []byte, id string) error {
	return r.checkSelectedS3MemberNoHistory(ctx, tree, key, id, false)
}

func (r *Repository) checkSelectedS3MemberNoHistory(ctx context.Context, tree *sealedtree.SQLStore, key []byte, id string, requireDisabled bool) error {
	if !nodeIDPattern.MatchString(id) || !validCapacityKey(key) {
		return store.ErrNodeState
	}
	return r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, _ *sealedtree.CoordinatedMutation) error {
		if checkCapacityVerifier(c, q, key) != nil {
			return store.ErrNodeState
		}
		member, err := r.s3Member(c, q, id, r.lock())
		if err != nil || member.Kind != "S3" || member.Transport != "S3" || member.RelationshipID != nil || requireDisabled && member.Enabled != 0 || member.Used != 0 || member.Reserved != 0 {
			return store.ErrNodeState
		}
		var count int64
		if q.QueryRowContext(c, `SELECT COUNT(*) FROM selected_upload_intents WHERE member_index=?`, opaqueCapacityMemberIndex(key, id)).Scan(&count) != nil || count != 0 {
			return store.ErrNodeState
		}
		return c.Err()
	})
}
