package main

import (
	"fmt"
	"io"
)

// Keep human multi-line output streaming, but retain the first write failure.
type resultWriter struct {
	writer io.Writer
	err    error
}

func (w *resultWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, e := w.writer.Write(data)
	if e == nil && n != len(data) {
		e = io.ErrShortWrite
	}
	if e != nil {
		w.err = e
	}
	return n, e
}
func (w *resultWriter) finish(exitCode *int, diagnostic io.Writer) {
	if w.err != nil {
		fmt.Fprintln(diagnostic, "operation result could not be written; remote recorded state is retained")
		*exitCode = 2
	}
}
