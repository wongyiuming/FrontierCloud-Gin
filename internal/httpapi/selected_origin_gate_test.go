package httpapi

import "testing"

func TestSelectedOriginGateBoundsRateAndConcurrency(t *testing.T) {
	rate := newSelectedOriginGate(2, 0, 2)
	if !rate.acquire() || !rate.acquire() || rate.acquire() {
		t.Fatal("rate bound failed")
	}
	rate.release()
	rate.release()
	if rate.acquire() {
		t.Fatal("rate bound unexpectedly replenished")
	}
	concurrency := newSelectedOriginGate(3, 0, 1)
	if !concurrency.acquire() || concurrency.acquire() {
		t.Fatal("concurrency bound failed")
	}
	concurrency.release()
	if !concurrency.acquire() {
		t.Fatal("released slot unavailable")
	}
	concurrency.release()
}
