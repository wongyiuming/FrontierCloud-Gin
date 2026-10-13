package operator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

type LogFact struct {
	Time      string `json:"time,omitempty"`
	Level     string `json:"level,omitempty"`
	Event     string `json:"event"`
	Status    int    `json:"status,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}
type LogReport struct {
	ReadOnly bool      `json:"read_only"`
	Redacted bool      `json:"redacted"`
	Omitted  int       `json:"omitted_lines"`
	Events   []LogFact `json:"events"`
}

var logIdentifier = regexp.MustCompile(`^[a-f0-9-]{16,64}$`)

// Raw log messages/paths/errors are deliberately not diagnostics: even a
// secret-regex scrubber cannot recognize an arbitrary pairing envelope/key.
func FilterLogs(raw []byte) (LogReport, error) {
	r := LogReport{ReadOnly: true, Redacted: true, Events: []LogFact{}}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var v map[string]json.RawMessage
		if json.Unmarshal(scanner.Bytes(), &v) != nil {
			r.Omitted++
			continue
		}
		var level, stamp, message, request string
		_ = json.Unmarshal(v["level"], &level)
		_ = json.Unmarshal(v["time"], &stamp)
		_ = json.Unmarshal(v["msg"], &message)
		_ = json.Unmarshal(v["request_id"], &request)
		event := "event_details_redacted"
		for _, allowed := range []string{"FrontierCloud stopped", "FrontierCloud listening", "HTTP request", "node heartbeat failed", "backup failed"} {
			if message == allowed {
				event = allowed
			}
		}
		if level != "DEBUG" && level != "INFO" && level != "WARN" && level != "ERROR" {
			level = ""
		}
		if _, e := time.Parse(time.RFC3339Nano, stamp); e != nil {
			stamp = ""
		}
		if !logIdentifier.MatchString(request) {
			request = ""
		}
		var status int
		_ = json.Unmarshal(v["status"], &status)
		if status < 100 || status > 599 {
			status = 0
		}
		if level == "" && stamp == "" && status == 0 && request == "" {
			r.Omitted++
			continue
		}
		r.Events = append(r.Events, LogFact{stamp, level, event, status, request})
	}
	if scanner.Err() != nil {
		return r, errors.New("log line exceeds safe diagnostics limit")
	}
	return r, nil
}
func (d *Deployment) Logs(ctx context.Context, receipt Receipt) (LogReport, error) {
	if _, e := d.ValidateReceipt(ctx, receipt); e != nil {
		return LogReport{}, e
	}
	raw, e := d.Compose(ctx, true, "logs", "--no-color", "--no-log-prefix", "--tail", "200")
	if e != nil {
		return LogReport{}, e
	}
	return FilterLogs(raw)
}
