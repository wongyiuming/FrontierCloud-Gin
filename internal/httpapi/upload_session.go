package httpapi

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"net/http"
	"time"
	"unicode/utf8"
)

func (a *Admin) storagePool(c *gin.Context) {
	var (
		result map[string]any
		err    error
	)
	selected := a.public.opaqueTree != nil
	if selected {
		ctx, cancel := selectedRuntimeContext(c)
		defer cancel()
		result, err = a.public.media.StoragePoolWithUploadReadiness(ctx, a.selectedUpload.ObserveUploadDestination)
	} else {
		result, err = a.public.media.StoragePool(c.Request.Context())
	}
	if err != nil {
		mediaAdminError(c, err)
		return
	}
	if selected {
		result["selected_upload"] = true
	}
	c.JSON(200, result)
}
func (a *Admin) reserveUpload(c *gin.Context) {
	var body struct {
		Site            string          `json:"site_type"`
		MemberID        json.RawMessage `json:"member_id"`
		StorageMemberID json.RawMessage `json:"storage_member_id"`
		Target          string          `json:"target_dir"`
		Relative        string          `json:"relative_path"`
		Filename        string          `json:"filename"`
		Bytes           int64           `json:"size_bytes"`
		Mode            string          `json:"storage_mode"`
		Encryption      json.RawMessage `json:"encryption"`
		Preparation     string          `json:"preparation_token"`
	}
	if !decodeAdmin(c, &body) {
		return
	}
	var memberID string
	if len(body.MemberID) != 0 || json.Unmarshal(body.StorageMemberID, &memberID) != nil || !node.ValidIdentifier(memberID) {
		detail(c, http.StatusConflict, "请选择具体的目标存储节点；不支持自动选择或备用节点")
		return
	}
	if utf8.RuneCountInString(body.Target) > 1024 || utf8.RuneCountInString(body.Relative) > 1024 || body.Filename == "" || utf8.RuneCountInString(body.Filename) > 255 || body.Bytes <= 0 {
		invalid(c, "body", "upload")
		return
	}
	if !nodeHTTPS(c, a.settings, a.network) {
		return
	}
	encoded := ""
	if len(body.Encryption) > 0 && string(body.Encryption) != "null" {
		encoded = string(body.Encryption)
	}
	meta, ok := a.uploadEncryption(c, body.Mode, encoded, body.Preparation)
	if !ok {
		return
	}
	if body.Bytes != meta.CiphertextSize {
		detail(c, 400, "上传文件大小与准备信息不一致")
		return
	}
	if meta.PlaintextSize > a.settings.AdminMaxUploadBytes {
		detail(c, 413, "文件超过单文件上传限制")
		return
	}
	if body.Site == "s3" && body.Bytes > 10*1024*1024*1024 {
		detail(c, 413, "S3 单个对象最多允许 10 GiB")
		return
	}
	result, err := a.public.media.ReserveSelectedMasterUpload(c.Request.Context(), body.Filename, body.Target, body.Relative, memberID, body.Bytes, a.settings.AdminMaxFilenameLength, a.mutationAudit(c, "upload-reserved", []string{body.Filename}), meta)
	if err != nil {
		if body.Site == "s3" {
			s3HTTPError(c, err)
			return
		}
		uploadError(c, err)
		return
	}
	c.JSON(200, result)
}
func (a *Admin) uploadBytes(c *gin.Context) {
	controller := http.NewResponseController(c.Writer)
	defer controller.SetReadDeadline(time.Time{})
	c.Request.Body = http.MaxBytesReader(c.Writer, &uploadReader{c.Request.Body, controller, time.Duration(min(a.settings.AdminUploadInactivity, 315360000)) * time.Second}, encryptedUploadLimit(a.settings.AdminMaxUploadBytes))
	result, err := a.public.media.UploadMasterBytes(c.Request.Context(), c.Param("upload"), c.Request.Body, a.mutationAudit(c, "upload-finalized", []string{c.Param("upload")}))
	if err != nil {
		uploadError(c, err)
		return
	}
	c.JSON(200, result)
}
func (a *Admin) finalizeUpload(c *gin.Context) {
	result, err := a.public.media.FinalizeMasterUpload(c.Request.Context(), c.Param("upload"), a.mutationAudit(c, "upload-finalized", []string{c.Param("upload")}))
	if err != nil {
		uploadError(c, err)
		return
	}
	c.JSON(200, result)
}
func (a *Admin) cancelUpload(c *gin.Context) {
	if err := a.public.media.CancelMasterUpload(c.Request.Context(), c.Param("upload"), a.mutationAudit(c, "upload-cancelled", []string{c.Param("upload")})); err != nil {
		uploadError(c, err)
		return
	}
	c.JSON(200, gin.H{"status": "cancelled"})
}
