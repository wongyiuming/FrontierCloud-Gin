package business

import (
	"context"
	"errors"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type selectedS3FinishTestGate struct{ err error }

func (g selectedS3FinishTestGate) AcquireSelectedS3(context.Context, *sealedtree.SQLStore, string) (SelectedUploadRuntimeLease, error) {
	return nil, nil
}
func (g selectedS3FinishTestGate) AcquireSelectedS3Admission(context.Context, *sealedtree.SQLStore, string) (SelectedUploadRuntimeLease, error) {
	return nil, nil
}
func (g selectedS3FinishTestGate) CheckSelectedS3Member(context.Context, *sealedtree.SQLStore, store.S3Member) error {
	return nil
}
func (g selectedS3FinishTestGate) CheckSelectedS3PublicOrigin(context.Context, *sealedtree.SQLStore, store.S3Member, string) error {
	return nil
}
func (g selectedS3FinishTestGate) FinishSelectedS3Recovery(context.Context, *sealedtree.SQLStore) error {
	return g.err
}

func TestSelectedS3RecoveryTerminalKeepsRetryOnAuditFailure(t *testing.T) {
	want := errors.New("audit failed")
	for _, tc := range []struct {
		err        error
		shouldFail bool
	}{
		{nil, false}, {ErrSelectedS3RecoveryRequired, false}, {want, true}, {errors.Join(want, ErrSelectedS3RecoveryRequired), true},
	} {
		s := &SelectedS3Coordinator{upload: &SelectedUploadRuntime{tree: &sealedtree.SQLStore{}}, ready: selectedS3FinishTestGate{err: tc.err}}
		err := s.finishRecovery(context.Background())
		if (err != nil) != tc.shouldFail {
			t.Fatalf("audit result %v: %v", tc.err, err)
		}
	}
}
