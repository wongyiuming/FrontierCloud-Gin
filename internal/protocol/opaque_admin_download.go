package protocol

import (
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

const opaqueAdminDownloadKind = "selected-admin-opaque-download-v1"

// OpaqueAdminDownloadToken has its own bearer scope. It authenticates one
// encrypted placement and one already-applied Owner policy without asserting
// that the Admin origin is the public ingress.
func OpaqueAdminDownloadToken(credential, relationship, master, owner, alias, adminOrigin, sessionID, blob, transport, targetOrigin string, policyRevision, now, expiresAt, size int64, digest string, meta *mediacrypto.Metadata) (string, error) {
	if meta == nil || !validOpaqueAdminDownloadTransport(transport, targetOrigin) {
		return "", errors.New("invalid opaque Admin download policy")
	}
	base, err := OpaqueIngressMediaToken(credential, relationship, master, owner, alias, master, adminOrigin, sessionID, blob, policyRevision, now, expiresAt, size, digest, meta)
	if err != nil {
		return "", err
	}
	claims, err := verifyCapabilityToken(credential, base)
	if err != nil {
		return "", err
	}
	claims["kind"], claims["transport"], claims["target_origin"] = opaqueAdminDownloadKind, transport, targetOrigin
	return capabilityToken(credential, claims)
}

func VerifyOpaqueAdminDownloadToken(credential, token string, now int64) (map[string]any, error) {
	claims, err := verifyOpaqueMediaToken(credential, token, now, opaqueAdminDownloadKind)
	target, targetOK := claims["target_origin"].(string)
	if err != nil || !targetOK || !validOpaqueAdminDownloadTransport(stringField(claims, "transport"), target) ||
		stringField(claims, "ingress") != stringField(claims, "m") || stringField(claims, "m") == stringField(claims, "o") {
		return nil, errors.New("invalid opaque Admin download capability")
	}
	return claims, nil
}

func validOpaqueAdminDownloadTransport(transport, origin string) bool {
	return transport == "Direct" && validIngressOrigin(origin) || transport == "Relay" && origin == ""
}
