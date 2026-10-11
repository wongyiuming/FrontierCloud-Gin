package stun

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"net"
	"testing"
	"time"
)

func request() []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b, 1)
	binary.BigEndian.PutUint32(b[4:], cookie)
	copy(b[8:], "0123456789ab")
	return b
}
func TestBindingIPv4IPv6FingerprintAndRefusal(t *testing.T) {
	for _, ip := range []string{"198.51.100.7", "2001:db8::7"} {
		r := request()
		a := &net.UDPAddr{IP: net.ParseIP(ip), Port: 23456}
		b := Binding(r, a)
		if len(b) < 40 || binary.BigEndian.Uint16(b) != 0x101 || string(b[8:20]) != string(r[8:20]) || binary.BigEndian.Uint16(b[26:])^uint16(cookie>>16) != 23456 {
			t.Fatal("binding transaction/port")
		}
		wire := a.IP.To4()
		if wire == nil {
			wire = a.IP.To16()
		}
		for i := range wire {
			if b[28+i]^r[4+i] != wire[i] {
				t.Fatal("XOR address")
			}
		}
		end := len(b) - 8
		if binary.BigEndian.Uint32(b[end+4:]) != crc32.ChecksumIEEE(b[:end])^0x5354554e {
			t.Fatal("fingerprint")
		}
	}
	for _, b := range [][]byte{nil, make([]byte, 513), append(request(), 1), append(request(), 0, 6, 0, 0)} {
		if Binding(b, &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1}) != nil {
			t.Fatal("malformed/required attribute admitted")
		}
	}
}
func TestRealUDPBoundedAndCancel(t *testing.T) {
	s, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, s) }()
	c, e := net.DialUDP("udp4", nil, s.LocalAddr().(*net.UDPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write(request())
	buffer := make([]byte, 100)
	n, _, e := c.ReadFromUDP(buffer)
	if e != nil || n != 40 {
		t.Fatal(n, e)
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown leaked")
	}
}
func TestDatagramFloodCannotProduceUnboundedResponses(t *testing.T) {
	s, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, s) }()
	c, e := net.DialUDP("udp4", nil, s.LocalAddr().(*net.UDPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	for range 500 {
		c.Write(request())
	}
	c.SetReadDeadline(time.Now().Add(550 * time.Millisecond))
	responses := 0
	var b [100]byte
	for {
		_, e = c.Read(b[:])
		if e != nil {
			break
		}
		responses++
	}
	if responses < 1 || responses > 6 {
		t.Fatal("flood escaped global packet budget", responses)
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("flood delayed shutdown")
	}
}
