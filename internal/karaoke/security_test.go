package karaoke

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestCaptchaHasCompleteGlyphsAndNoAnswerText(t *testing.T) {
	const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	for i := range alphabet {
		glyph, ok := captchaGlyphs[alphabet[i]]
		if !ok {
			t.Fatal("missing glyph", alphabet[i])
		}
		for _, row := range glyph {
			if len(row) != 5 {
				t.Fatal("invalid glyph width")
			}
		}
	}
	image := captchaSVG("A2Z9Q")
	if strings.Contains(image, "A2Z9Q") || len(image) > 16000 {
		t.Fatal("answer disclosure or oversized image")
	}
	d := xml.NewDecoder(strings.NewReader(image))
	paths := 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := token.(xml.CharData); ok {
			t.Fatal("answer-bearing SVG text")
		}
		if start, ok := token.(xml.StartElement); ok {
			if start.Name.Local == "text" || start.Name.Local == "metadata" || start.Name.Local == "title" {
				t.Fatal("answer-bearing SVG element")
			}
			if start.Name.Local == "path" {
				paths++
			}
		}
	}
	if paths < 50 {
		t.Fatal("missing visible glyph outlines")
	}
}

func TestPasswordAdmissionDoesNotQueueOrIgnoreCancellation(t *testing.T) {
	passwordSlots <- struct{}{}
	_, err := passwordKey(context.Background(), "ignored", make([]byte, 16))
	<-passwordSlots
	var denied *Error
	if !errors.As(err, &denied) || denied.Status != 429 || denied.RetryAfter != 1 {
		t.Fatal("unbounded password queue", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := passwordKey(ctx, "ignored", make([]byte, 16)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled request admitted", err)
	}
}

func TestRedisAdmissionAtomicHardLimitsAndBoundedKeys(t *testing.T) {
	raw := os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL")
	if raw == "" {
		t.Skip("disposable Redis not configured")
	}
	opts, err := redis.ParseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(opts)
	t.Cleanup(func() { client.Close() })
	ctx := context.Background()
	reset := func() {
		keys, err := client.Keys(ctx, "karaoke:rate:*").Result()
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) > 0 {
			if err = client.Del(ctx, keys...).Err(); err != nil {
				t.Fatal(err)
			}
		}
	}
	reset()
	t.Cleanup(reset)
	cache := NewRedisCache(client)
	for i := 0; i < 20; i++ {
		ok, err := cache.ReserveRequest(ctx, "captcha", "192.0.2.1", "")
		if err != nil || !ok {
			t.Fatal(i, ok, err)
		}
	}
	if ok, err := cache.ReserveRequest(ctx, "captcha", "192.0.2.1", ""); err != nil || ok {
		t.Fatal("IP bypass", ok, err)
	}
	if ok, err := cache.ReserveRequest(ctx, "captcha", "192.0.2.2", ""); err != nil || !ok {
		t.Fatal("other client denied", ok, err)
	}
	reset()
	for i := 0; i < 10; i++ {
		ok, err := cache.ReserveRequest(ctx, "login", string(rune('a'+i)), "same-account")
		if err != nil || !ok {
			t.Fatal(i, ok, err)
		}
	}
	if ok, err := cache.ReserveRequest(ctx, "login", "new-ip", "same-account"); err != nil || ok {
		t.Fatal("account bypass by IP rotation", ok, err)
	}
	reset()
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 100; i++ {
		wg.Go(func() {
			value := string(rune(1000 + i))
			ok, err := cache.ReserveRequest(ctx, "login", value, value)
			if err != nil {
				t.Error(err)
			}
			if ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if allowed != 60 {
		t.Fatal("global admission overshoot", allowed)
	}
	before, err := client.DBSize(ctx).Result()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		ok, err := cache.ReserveRequest(ctx, "login", string(rune(2000+i)), string(rune(2000+i)))
		if err != nil || ok {
			t.Fatal("global limit bypass", ok, err)
		}
	}
	after, err := client.DBSize(ctx).Result()
	if err != nil || before != after {
		t.Fatal("rejected request created cache keys", before, after, err)
	}
	ttl, err := client.TTL(ctx, "karaoke:rate:credentials:global").Result()
	if err != nil || ttl.Seconds() <= 0 || ttl.Seconds() > 60 {
		t.Fatal("unbounded limiter TTL", ttl, err)
	}
	if _, err := cache.ReserveRequest(ctx, "unknown", "ip", "user"); err == nil {
		t.Fatal("unknown budget allowed")
	}
}
