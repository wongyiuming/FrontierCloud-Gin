package operator

import "testing"

func TestReceiptRetainsExactConfiguredIPSelection(t *testing.T) {
	_, runner := fixture(t)
	env := runner.config.Services["web"].Environment
	env["SERVER_NAME"] = "2606:4700:4700:0:0:0:0:1111"
	env["STORAGE_ENDPOINT"] = "https://[2606:4700:4700:0:0:0:0:1111]:443"
	original := selectionHash(runner.config)
	if original != selectionHash(runner.config) {
		t.Fatal("unchanged raw config changed receipt binding")
	}
	env["STORAGE_ENDPOINT"] = "https://[2606:4700:4700::1111]"
	if original == selectionHash(runner.config) {
		t.Fatal("equivalent IP spelling silently changed an existing receipt's configuration contract")
	}
}
