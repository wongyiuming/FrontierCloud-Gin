package media

import (
	"context"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
)

func TestS3SourceOmitsBusinessFilenameFromProviderGrant(t *testing.T) {
	_, db, service, _ := s3CatalogFixture(t)
	ctx := context.Background()
	plain := publishS3CatalogObject(t, db, "music/SecretArtist/SecretSong.mp3", nil)
	encryption, err := mediacrypto.NewMetadata(128)
	if err != nil {
		t.Fatal(err)
	}
	cipher := publishS3CatalogObject(t, db, "music/EncryptedArtist/EncryptedSong.mp3", &encryption)
	calls := 0
	service.s3 = &mediaS3Control{read: func(_ context.Context, id, filename string) (s3media.SourceGrant, error) {
		calls++
		if filename != "" {
			t.Fatalf("provider received business filename %q", filename)
		}
		return s3media.SourceGrant{ObjectID: id}, nil
	}}
	if _, err = service.PlaintextSource(ctx, plain.Path, plain.ObjectID, false); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ReadSource(ctx, cipher.Path, cipher.ObjectID, false); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected two authorized S3 grants, got %d", calls)
	}
}
