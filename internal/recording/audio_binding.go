package recording

import "github.com/wongyiuming/FrontierCloud-Gin/internal/store"

// AudioPreparationBinding fixes a recording preparation to its authenticated
// account, browser/ingress session and server-generated recording ID. It is
// not an authorization by itself: callers must authenticate the account and
// obtain browser from the server's current browser-binding check.
func AudioPreparationBinding(userID, browser, recordingID string) (string, error) {
	return store.RecordingAudioPreparationBinding(userID, browser, recordingID)
}
