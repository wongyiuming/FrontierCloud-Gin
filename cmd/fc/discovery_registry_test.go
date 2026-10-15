package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifiedDeploymentRegistrySurvivesWithoutContainers(t *testing.T) {
	dir := t.TempDir()
	registry, lock := filepath.Join(dir, "registry"), filepath.Join(dir, "lock")
	if e := os.WriteFile(registry, []byte("@compose\n"), 0644); e != nil {
		t.Fatal(e)
	}
	deployment := filepath.Join(dir, "deployment with spaces")
	for i := 0; i < 2; i++ {
		if e := persistDeployment(context.Background(), registry, lock, deployment); e != nil {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(registry)
	if e != nil || string(b) != deployment+"\n@compose\n" {
		t.Fatal(string(b), e)
	}
	if _, e = os.Lstat(lock); !os.IsNotExist(e) {
		t.Fatal("registry lock retained", e)
	}
	for _, bad := range []string{"relative", deployment + "\n/other"} {
		if e = persistDeployment(context.Background(), registry, lock, bad); e == nil {
			t.Fatal("unsafe registration accepted")
		}
	}
	after, _ := os.ReadFile(registry)
	if string(after) != string(b) {
		t.Fatal("refusal changed registry")
	}
	if e = os.Remove(registry); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(filepath.Join(dir, "missing"), registry); e != nil {
		t.Skip(e)
	}
	if e = persistDeployment(context.Background(), registry, lock, deployment); e == nil || !strings.Contains(e.Error(), "unsafe") {
		t.Fatal("registry symlink accepted", e)
	}
}
