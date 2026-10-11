package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
)

// Audit one issued browser download plan, rather than its playback or Range
// reads. Plain-only plans retain the existing attachment download audit.
func (a *Admin) auditEncryptedDownloadPlan(c *gin.Context, download *media.Download, entries []media.DownloadEntry) error {
	encrypted := 0
	for _, entry := range entries {
		if entry.Encryption != nil {
			encrypted++
		}
	}
	if encrypted == 0 {
		return nil
	}
	if a.auth == nil {
		return errors.New("Admin download audit is unavailable")
	}
	// Download.Items contains the validated, normalized, deduplicated selection.
	// Expanded files can number in the thousands and are not the user's scopes.
	paths := make([]string, 0, len(download.Items))
	for _, item := range download.Items {
		paths = append(paths, item.Path)
	}
	complete, err := json.Marshal(paths)
	if err != nil {
		return err
	}
	source := complete
	omitted := 0
	// The repository bounds source_summary to 10,000 runes. Preserve valid JSON
	// and explicitly identify omitted scopes, instead of silent mid-JSON truncation.
	if utf8.RuneCount(complete) > 8000 {
		source = []byte("[]")
		omitted = len(paths)
		for n := 1; n <= len(paths); n++ {
			candidate, err := json.Marshal(paths[:n])
			if err != nil {
				return err
			}
			if utf8.RuneCount(candidate) > 8000 {
				break
			}
			source, omitted = candidate, len(paths)-n
		}
	}
	sum := sha256.Sum256(complete)
	detail, err := json.Marshal(struct {
		Kind             string `json:"kind"`
		Files            int    `json:"files"`
		EncryptedFiles   int    `json:"encrypted_files"`
		SourcePathsTotal int    `json:"source_paths_total"`
		SourcePathsOmit  int    `json:"source_paths_omitted"`
		SourceSHA256     string `json:"source_sha256"`
	}{"encrypted_download_plan", len(entries), encrypted, len(paths), omitted, hex.EncodeToString(sum[:])})
	if err != nil {
		return err
	}
	return a.auth.Audit(c.Request.Context(), session(c).Hash, "download", string(source), "success", string(detail), len(paths), a.info(c))
}
