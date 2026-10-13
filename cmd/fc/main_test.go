package main

import (
	"context"
	"reflect"
	"testing"
)

func TestGlobalFlagsWorkBeforeOrAfterCommands(t *testing.T) {
	got, e := globalArguments([]string{"install", "storage", "--directory", "/tmp/test", "--revision=abc", "--json"})
	if e != nil || !reflect.DeepEqual(got, []string{"--directory", "/tmp/test", "--revision=abc", "--json", "install", "storage"}) {
		t.Fatal(got, e)
	}
	if _, e = globalArguments([]string{"doctor", "--directory"}); e == nil {
		t.Fatal("missing flag value accepted")
	}
}

func TestBulkRecoveryHasNoFixedDeadlineAndStillHonorsCancellation(t *testing.T) {
	for _, command := range []string{"backup", "restore", "upgrade"} {
		parent, stop := context.WithCancel(context.Background())
		ctx, cancel := commandContext(parent, []string{command})
		if _, ok := ctx.Deadline(); ok {
			t.Fatal("bulk operation has a size-independent deadline", command)
		}
		stop()
		if ctx.Err() != context.Canceled {
			t.Fatal("operator cancellation not propagated", command)
		}
		cancel()
	}
	ctx, cancel := commandContext(context.Background(), []string{"doctor"})
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("readonly control lost its bounded deadline")
	}
}
