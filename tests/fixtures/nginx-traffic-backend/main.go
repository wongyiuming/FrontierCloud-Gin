// Test-only byte sink and X-Accel upstream. Not a business runtime or fleet node.
package main

import (
	"io"
	"net/http"
	"strconv"
)

func main() {
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		n, e := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 32<<20))
		if e != nil {
			http.Error(w, "bounded fixture upload failed", 400)
			return
		}
		w.Header().Set("X-Fixture-Bytes", strconv.FormatInt(n, 10))
		w.WriteHeader(200)
	})
	http.HandleFunc("/accelerated", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Accel-Redirect", "/_protected_media/payload.bin")
		w.WriteHeader(200)
	})
	if e := http.ListenAndServe("127.0.0.1:8082", nil); e != nil {
		panic("isolated fixture listener failed")
	}
}
