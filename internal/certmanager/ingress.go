package certmanager

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Check only the fixed private edge route before contacting the CA. This is
// startup ordering evidence; public reachability remains the CA's decision.
func awaitIngress(ctx context.Context, address, host string) error {
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return err
		}
		request.Host = host
		response, err := client.Do(request)
		if err == nil {
			ready := response.StatusCode == http.StatusNotFound && response.Header.Get("X-FrontierCloud-ACME") == "ready"
			response.Body.Close()
			if ready {
				return nil
			}
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("private HTTP-01 ingress is not ready")
		case <-timer.C:
		}
	}
}
