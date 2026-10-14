package media

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func tagFixture(version byte, frames ...[]byte) []byte {
	data := bytes.Join(frames, nil)
	n := len(data)
	return append([]byte{'I', 'D', '3', version, 0, 0, byte(n>>21) & 127, byte(n>>14) & 127, byte(n>>7) & 127, byte(n) & 127}, data...)
}
func tagFrame(version byte, name string, data []byte) []byte {
	header := make([]byte, 10)
	copy(header, name)
	if version == 4 {
		n := len(data)
		copy(header[4:8], []byte{byte(n>>21) & 127, byte(n>>14) & 127, byte(n>>7) & 127, byte(n) & 127})
	} else {
		binary.BigEndian.PutUint32(header[4:8], uint32(len(data)))
	}
	return append(header, data...)
}
func TestMusicTagsVersionsAndPicture(t *testing.T) {
	for _, version := range []byte{3, 4} {
		// UTF-16LE title; UTF-8 artist and album. Real JPEG signature for MIME verification.
		jpeg := append([]byte{255, 216, 255, 224, 0, 16, 'J', 'F', 'I', 'F', 0}, make([]byte, 600)...)
		apic := append([]byte{3}, []byte("image/jpeg\x00\x03\x00")...)
		apic = append(apic, jpeg...)
		data := tagFixture(version, tagFrame(version, "TIT2", []byte{1, 255, 254, 0x60, 0x4f, 0x7d, 0x59}), tagFrame(version, "TPE1", append([]byte{3}, []byte("達明一派")...)), tagFrame(version, "TALB", []byte{3, 'M', 'o', 'r', 'e'}), tagFrame(version, "APIC", apic))
		tags := readMusicTags(bytes.NewReader(data))
		if tags.Title != "你好" || tags.Artist != "達明一派" || tags.Album != "More" || tags.MIME != "image/jpeg" || !bytes.Equal(tags.Picture, jpeg) {
			t.Fatalf("version %d: %#v", version, tags)
		}
	}
}
func TestMusicTagsMalformedBoundedFallback(t *testing.T) {
	cases := [][]byte{nil, []byte("not audio"), {'I', 'D', '3', 4, 0, 0, 127, 127, 127, 127}, tagFixture(3, tagFrame(3, "TIT2", []byte{3, 'O', 'K'})[:11]), tagFixture(4, tagFrame(4, "APIC", []byte{3, 'b', 'a', 'd'}))}
	for _, data := range cases {
		tags := readMusicTags(bytes.NewReader(data))
		if len(tags.Picture) != 0 {
			t.Fatal("invalid image accepted")
		}
	}
	p, _, _ := validatedPicture([]byte("<svg onload=alert(1)></svg>"), 3)
	if p != nil {
		t.Fatal("active image accepted")
	}
}
