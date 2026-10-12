package main

import (
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
