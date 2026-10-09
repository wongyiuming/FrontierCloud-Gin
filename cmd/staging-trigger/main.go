// staging-trigger accepts authenticated CI wakeups without Docker or root access.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const stateDirectory = "/var/lib/frontiercloud-staging-trigger"

var validSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

type event struct {
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
	Event      string `json:"event"`
	Conclusion string `json:"conclusion"`
	SHA        string `json:"sha"`
	RunID      int64  `json:"run_id"`
	RunNumber  int64  `json:"run_number"`
	RunAttempt int64  `json:"run_attempt"`
	Timestamp  int64  `json:"timestamp"`
}

type receiver struct {
	secret    []byte
	directory string
	now       func() time.Time
	mu        sync.Mutex
}

func (s *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/staging-ci-success" || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		http.Error(w, "invalid body", http.StatusRequestEntityTooLarge)
		return
	}
	signature, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get("X-FrontierCloud-Signature"), "sha256="))
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(body)
	if err != nil || !strings.HasPrefix(r.Header.Get("X-FrontierCloud-Signature"), "sha256=") || !hmac.Equal(signature, mac.Sum(nil)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var value event
	if json.Unmarshal(body, &value) != nil || value.Repository != "wongyiuming/FrontierCloud-Gin" || value.Branch != "dev" || value.Event != "push" || value.Conclusion != "success" || !validSHA.MatchString(value.SHA) || value.RunID <= 0 || value.RunNumber <= 0 || value.RunAttempt <= 0 || value.Timestamp < s.now().Unix()-300 || value.Timestamp > s.now().Unix()+30 {
		http.Error(w, "ineligible CI event", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Old/replayed deliveries cannot overwrite a newer wakeup. The deployment
	// side independently verifies exact dev HEAD and its newest successful CI.
	var last event
	if previous, readErr := os.ReadFile(filepath.Join(s.directory, "receipt.json")); readErr == nil {
		if json.Unmarshal(previous, &last) != nil {
			http.Error(w, "invalid receipt", http.StatusServiceUnavailable)
			return
		}
		if value.RunNumber < last.RunNumber || (value.RunNumber == last.RunNumber && value.RunAttempt <= last.RunAttempt) {
			w.WriteHeader(http.StatusAccepted)
			return
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		http.Error(w, "receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	// Persist the queue before acknowledging so a failed write is retryable.
	if err = s.persist("pending.json", body); err == nil {
		err = s.persist("receipt.json", body)
	}
	if err != nil {
		log.Print("CI wakeup persistence failed")
		http.Error(w, "queue unavailable", http.StatusServiceUnavailable)
		return
	}
	log.Printf("Accepted dev CI #%d attempt %d sha %s", value.RunNumber, value.RunAttempt, value.SHA)
	w.WriteHeader(http.StatusAccepted)
}

func (s *receiver) persist(name string, body []byte) error {
	file, err := os.CreateTemp(s.directory, ".event-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(body); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(file.Name(), filepath.Join(s.directory, name)); err != nil {
		return err
	}
	directory, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func main() {
	secret, err := os.ReadFile("/etc/frontiercloud-staging-trigger/secret")
	secret = []byte(strings.TrimSpace(string(secret)))
	if err != nil || len(secret) < 32 {
		log.Fatal("CI signing secret unavailable")
	}
	server := &http.Server{
		Addr:              ":9443",
		Handler:           &receiver{secret: secret, directory: stateDirectory, now: time.Now},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second,
		MaxHeaderBytes: 8192,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
	}
	log.Fatal(server.ListenAndServeTLS("/etc/frontiercloud-staging-trigger/fullchain.pem", "/etc/frontiercloud-staging-trigger/privkey.pem"))
}
