// Test-only byte sink and X-Accel upstream. Not a business runtime or fleet node.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--multiplex" {
		result, e := multiplex(os.Args[2])
		if e != nil {
			fmt.Fprintln(os.Stderr, "isolated HTTP/2 multiplex fixture failed")
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(result)
		return
	}
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

func multiplex(origin string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Only the private loopback CA fixture uses this exception. Explicit HTTP/2
	// and a single transport connection prove that requests share physical TLS.
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true, MaxConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	var mu sync.Mutex
	connections := map[string]bool{}
	var business, excluded int64
	start := make(chan struct{})
	businessHeaders := make(chan struct{}, 2)
	errorsCh := make(chan error, 3)
	for _, path := range []string{"/h2-business", "/h2-business", "/api/v1/media/admin/nodes/migrations/h2-control"} {
		go func(path string) {
			<-start
			if path != "/h2-business" {
				for range 2 {
					select {
					case <-businessHeaders:
					case <-ctx.Done():
						errorsCh <- ctx.Err()
						return
					}
				}
			}
			request, e := http.NewRequestWithContext(ctx, "GET", origin+path, nil)
			if e != nil {
				errorsCh <- e
				return
			}
			length := int64(256 << 10)
			if path != "/h2-business" {
				length = 2 << 20
			}
			request.Header.Set("Range", fmt.Sprintf("bytes=0-%d", length-1))
			trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
				mu.Lock()
				connections[fmt.Sprintf("%p", info.Conn)] = true
				mu.Unlock()
			}}
			reply, e := client.Do(request.WithContext(httptrace.WithClientTrace(ctx, trace)))
			if e != nil {
				errorsCh <- e
				return
			}
			defer reply.Body.Close()
			if path == "/h2-business" {
				businessHeaders <- struct{}{}
			}
			n, e := io.Copy(io.Discard, reply.Body)
			if e != nil || reply.ProtoMajor != 2 || reply.StatusCode != 206 || n != length {
				errorsCh <- errors.New("HTTP/2 protocol, Range or byte count mismatch")
				return
			}
			mu.Lock()
			if path == "/h2-business" {
				business += n
			} else {
				excluded += n
			}
			mu.Unlock()
			errorsCh <- nil
		}(path)
	}
	close(start)
	for range 3 {
		if e := <-errorsCh; e != nil {
			return nil, e
		}
	}
	if len(connections) != 1 {
		return nil, errors.New("requests did not share one TLS connection")
	}
	return map[string]any{"single_connection": true, "http2": true, "control_overlapped_two_business_streams": true, "business_bytes": business, "excluded_bytes": excluded}, nil
}
