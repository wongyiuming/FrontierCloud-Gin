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

func TestMusicTagsV24DataLengthIndicator(t *testing.T) {
	jpeg := append([]byte{255, 216, 255, 224, 0, 16, 'J', 'F', 'I', 'F', 0}, make([]byte, 600)...)
	art := append([]byte("\x03image/jpeg\x00\x03\x00"), jpeg...)
	withIndicator := func(name string, body []byte, invalid bool, unsync bool) []byte {
		n := len(body)
		indicator := []byte{byte(n>>21) & 127, byte(n>>14) & 127, byte(n>>7) & 127, byte(n) & 127}
		if invalid {
			indicator[0] = 128
		}
		if unsync {
			body = bytes.ReplaceAll(body, []byte{255}, []byte{255, 0})
		}
		frame := tagFrame(4, name, append(indicator, body...))
		frame[9] = 1
		if unsync {
			frame[9] |= 2
		}
		return frame
	}
	tags := readMusicTags(bytes.NewReader(tagFixture(4, withIndicator("TIT2", []byte("\x03Indicator title"), false, false), withIndicator("APIC", art, false, true))))
	if tags.Title != "Indicator title" || !bytes.Equal(tags.Picture, jpeg) {
		t.Fatal("valid data length indicator lost metadata", tags)
	}
	tags = readMusicTags(bytes.NewReader(tagFixture(4, withIndicator("TIT2", []byte("\x03Invalid"), true, false))))
	if tags.Title != "" {
		t.Fatal("malformed data length accepted", tags)
	}
}

func TestMusicTagsLegacySuffixOnlyFillsMissingFields(t *testing.T) {
	tail := make([]byte, 128)
	copy(tail, "TAG")
	copy(tail[3:33], "Legacy title")
	copy(tail[33:63], "Legacy artist")
	copy(tail[63:93], "Legacy album")
	picture := []byte("original picture")
	tags := legacyMusicTags(MusicTags{Title: "ID3v2 title", Picture: picture, MIME: "image/jpeg"}, tail)
	if tags.Title != "ID3v2 title" || tags.Artist != "Legacy artist" || tags.Album != "Legacy album" || !bytes.Equal(tags.Picture, picture) || tags.MIME != "image/jpeg" {
		t.Fatal("suffix overwrote preferred ID3v2 metadata", tags)
	}
	for _, invalid := range [][]byte{nil, tail[:127], append([]byte("BAD"), tail[3:]...)} {
		if got := legacyMusicTags(MusicTags{}, invalid); got.Title != "" || got.Artist != "" || got.Album != "" {
			t.Fatal("invalid suffix accepted", got)
		}
	}
}
