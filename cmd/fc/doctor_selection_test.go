package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
)

func TestDoctorSelectsInstalledRoleAndDatabaseBeforeCompose(t *testing.T) {
	for _, selection := range [][2]string{{"storage", "sqlite"}, {"master", "mysql"}} {
		t.Run(selection[0]+"-"+selection[1], func(t *testing.T) {
			root := t.TempDir()
			dep, err := operator.New(root, selection[0], selection[1])
			if err != nil {
				t.Fatal(err)
			}
			receipt := operator.Receipt{Version: operator.ConfigurationVersion, Revision: strings.Repeat("a", 40), Project: "fixture", Role: selection[0], Database: selection[1], Files: dep.Files}
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, operator.ReceiptFile)
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := doctorDeployment(root, "master", "sqlite", false, false)
			if err != nil || got.Role != selection[0] || !reflect.DeepEqual(got.Files, dep.Files) {
				t.Fatal(got, err)
			}
			if _, err = doctorDeployment(root, selection[0], selection[1], true, true); err != nil {
				t.Fatal(err)
			}
			if _, err = doctorDeployment(root, "invalid", "sqlite", true, false); err == nil {
				t.Fatal("conflicting explicit role accepted")
			}
			if _, err = doctorDeployment(root, selection[0], "invalid", false, true); err == nil {
				t.Fatal("conflicting explicit database accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(raw) {
				t.Fatal("receipt changed", err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 {
				t.Fatal("selection wrote other state", entries, err)
			}
		})
	}
}

func TestDoctorFreshSelectionAndInvalidReceiptRefusal(t *testing.T) {
	root := t.TempDir()
	got, err := doctorDeployment(root, "storage", "sqlite", false, false)
	if err != nil || got.Role != "storage" {
		t.Fatal(got, err)
	}
	if err = os.WriteFile(filepath.Join(root, operator.ReceiptFile), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = doctorDeployment(root, "master", "sqlite", false, false); err == nil {
		t.Fatal("invalid receipt fell back to fresh selection")
	}
}
