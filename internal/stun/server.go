// Package stun provides the storage appliance's bounded UDP binding responder.
package stun

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"net"
	"time"
)

const cookie = uint32(0x2112a442)

// Binding supports only RFC 5389 binding requests, never TURN or forwarding.
// Responses are smaller than 80 bytes; malformed or oversized packets get none.
func Binding(request []byte, remote *net.UDPAddr) []byte {
	if len(request) < 20 || len(request) > 512 || binary.BigEndian.Uint16(request) != 1 || binary.BigEndian.Uint32(request[4:]) != cookie || int(binary.BigEndian.Uint16(request[2:])) != len(request)-20 || len(request)%4 != 0 {
		return nil
	}
	for offset := 20; offset < len(request); {
		if offset+4 > len(request) {
			return nil
		}
		n := int(binary.BigEndian.Uint16(request[offset+2:]))
		end := offset + 4 + n
		if end > len(request) {
			return nil
		}
		kind := binary.BigEndian.Uint16(request[offset:])
		if kind == 0x8028 && (n != 4 || end != len(request) || binary.BigEndian.Uint32(request[offset+4:]) != crc32.ChecksumIEEE(request[:offset])^0x5354554e) {
			return nil
		}
		if kind < 0x8000 {
			return nil
		} // No authenticated/TURN/unknown required attributes.
		offset = (end + 3) &^ 3
	}
	ip := remote.IP.To4()
	family := byte(1)
	if ip == nil {
		ip = remote.IP.To16()
		family = 2
	}
	if ip == nil {
		return nil
	}
	response := make([]byte, 20+4+4+len(ip)+8)
	binary.BigEndian.PutUint16(response, 0x101)
	binary.BigEndian.PutUint16(response[2:], uint16(len(response)-20))
	copy(response[4:20], request[4:20])
	binary.BigEndian.PutUint16(response[20:], 0x20)
	binary.BigEndian.PutUint16(response[22:], uint16(4+len(ip)))
	response[25] = family
	binary.BigEndian.PutUint16(response[26:], uint16(remote.Port)^uint16(cookie>>16))
	for i := range ip {
		response[28+i] = ip[i] ^ request[4+i]
	}
	end := len(response) - 8
	binary.BigEndian.PutUint16(response[end:], 0x8028)
	binary.BigEndian.PutUint16(response[end+2:], 4)
	binary.BigEndian.PutUint32(response[end+4:], crc32.ChecksumIEEE(response[:end])^0x5354554e)
	return response
}

// Serve processes at most ten datagrams per second, including invalid traffic.
// One goroutine, one packet buffer and a tiny kernel queue bound flood CPU/RAM.
func Serve(ctx context.Context, conn *net.UDPConn) error {
	defer conn.Close()
	_ = conn.SetReadBuffer(2048)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	buffer := make([]byte, 513)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if response := Binding(buffer[:n], remote); response != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			_, _ = conn.WriteToUDP(response, remote)
		}
	}
}
