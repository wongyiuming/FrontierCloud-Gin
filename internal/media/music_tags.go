package media

// Bounded tag reads only: no decoding, transcoding or whole-file buffering.
import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const maxMusicTagBytes = 8 << 20
const maxMusicPictureBytes = 4 << 20

type MusicTags struct {
	Title   string
	Artist  string
	Album   string
	Picture []byte
	MIME    string
}

func tagText(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	encoding, data := data[0], data[1:]
	var value string
	switch encoding {
	case 0:
		runes := make([]rune, len(data))
		for i, b := range data {
			runes[i] = rune(b)
		}
		value = string(runes)
	case 1, 2:
		var order binary.ByteOrder = binary.BigEndian
		if len(data) >= 2 && data[0] == 255 && data[1] == 254 {
			order = binary.LittleEndian
			data = data[2:]
		} else if len(data) >= 2 && data[0] == 254 && data[1] == 255 {
			data = data[2:]
		}
		words := make([]uint16, 0, len(data)/2)
		for len(data) >= 2 {
			words = append(words, order.Uint16(data))
			data = data[2:]
		}
		value = string(utf16.Decode(words))
	case 3:
		value = string(data)
	}
	value = strings.TrimSpace(strings.SplitN(value, "\x00", 2)[0])
	if len(value) > 4096 {
		return ""
	}
	return value
}
func syncSafe(b []byte) int {
	if len(b) != 4 {
		return -1
	}
	n := 0
	for _, v := range b {
		if v&128 != 0 {
			return -1
		}
		n = n<<7 | int(v)
	}
	return n
}
func unSync(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		out = append(out, data[i])
		if data[i] == 255 && i+1 < len(data) && data[i+1] == 0 {
			i++
		}
	}
	return out
}
func picture(data []byte, old bool) ([]byte, string, byte) {
	if len(data) < 5 {
		return nil, "", 0
	}
	encoding := data[0]
	data = data[1:]
	if old {
		if len(data) < 4 {
			return nil, "", 0
		}
		data = data[3:]
	} else {
		end := bytes.IndexByte(data, 0)
		if end < 0 {
			return nil, "", 0
		}
		data = data[end+1:]
	}
	if len(data) == 0 {
		return nil, "", 0
	}
	kind := data[0]
	data = data[1:]
	end := -1
	if encoding == 1 || encoding == 2 {
		for i := 0; i+1 < len(data); i += 2 {
			if data[i] == 0 && data[i+1] == 0 {
				end = i + 2
				break
			}
		}
	} else {
		if i := bytes.IndexByte(data, 0); i >= 0 {
			end = i + 1
		}
	}
	if end < 0 {
		return nil, "", 0
	}
	data = data[end:]
	return validatedPicture(data, kind)
}
func validatedPicture(data []byte, kind byte) ([]byte, string, byte) {
	if len(data) == 0 || len(data) > maxMusicPictureBytes {
		return nil, "", 0
	}
	mime := http.DetectContentType(data)
	if mime != "image/jpeg" && mime != "image/png" && mime != "image/webp" && mime != "image/gif" {
		return nil, "", 0
	}
	return append([]byte(nil), data...), mime, kind
}

func readMusicTags(reader io.Reader) MusicTags {
	var tags MusicTags
	header := make([]byte, 10)
	if _, err := io.ReadFull(reader, header); err != nil {
		return tags
	}
	if string(header[:3]) != "ID3" || header[3] < 2 || header[3] > 4 {
		return tags
	}
	version := header[3]
	size := syncSafe(header[6:10])
	if size < 0 || size > maxMusicTagBytes {
		return tags
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return tags
	}
	if version < 4 && header[5]&128 != 0 {
		data = unSync(data)
	}
	if header[5]&64 != 0 && version >= 3 {
		if len(data) < 4 {
			return tags
		}
		skip := int(binary.BigEndian.Uint32(data[:4])) + 4
		if version == 4 {
			skip = syncSafe(data[:4])
		}
		if skip < 4 || skip > len(data) {
			return tags
		}
		data = data[skip:]
	}
	for len(data) >= 6 {
		width := 10
		name := ""
		length := 0
		flags := byte(0)
		if version == 2 {
			width = 6
			name = string(data[:3])
			length = int(data[3])<<16 | int(data[4])<<8 | int(data[5])
		} else {
			if len(data) < 10 {
				break
			}
			name = string(data[:4])
			length = int(binary.BigEndian.Uint32(data[4:8]))
			if version == 4 {
				length = syncSafe(data[4:8])
			}
			flags = data[9]
		}
		if length <= 0 || length > len(data)-width {
			break
		}
		frame := data[width : width+length]
		data = data[width+length:]
		if version == 3 && flags&0xe0 != 0 || version == 4 && flags&0x4d != 0 {
			continue
		}
		if version == 4 && (header[5]&128 != 0 || flags&2 != 0) {
			frame = unSync(frame)
		}
		switch name {
		case "TIT2", "TT2":
			tags.Title = tagText(frame)
		case "TPE1", "TP1":
			tags.Artist = tagText(frame)
		case "TALB", "TAL":
			tags.Album = tagText(frame)
		case "APIC", "PIC":
			p, m, k := picture(frame, version == 2)
			if len(p) > 0 && (len(tags.Picture) == 0 || k == 3) {
				tags.Picture = p
				tags.MIME = m
			}
		}
	}
	return tags
}

func tagsFromFile(file *os.File, size int64) MusicTags {
	tags := readMusicTags(file)
	if size >= 128 && (tags.Title == "" || tags.Artist == "" || tags.Album == "") {
		tail := make([]byte, 128)
		if _, err := file.ReadAt(tail, size-128); err == nil && string(tail[:3]) == "TAG" {
			if tags.Title == "" {
				tags.Title = tagText(append([]byte{0}, tail[3:33]...))
			}
			if tags.Artist == "" {
				tags.Artist = tagText(append([]byte{0}, tail[33:63]...))
			}
			if tags.Album == "" {
				tags.Album = tagText(append([]byte{0}, tail[63:93]...))
			}
		}
	}
	return tags
}

// Metadata uses the same path/placement authorization as streaming. Remote
// readers are closed after the tag prefix, never after downloading a song.
func (s *Service) MusicMetadata(ctx context.Context, name, id string) (MusicTags, error) {
	return s.musicMetadata(ctx, name, id, true)
}
func (s *Service) cachedMusicTags(key string, read func() (MusicTags, error)) (MusicTags, error) {
	s.tagsMu.Lock()
	tags, ok := s.tagsCache[key]
	s.tagsMu.Unlock()
	if ok {
		return tags, nil
	}
	tags, err := read()
	if err != nil {
		return tags, err
	}
	size := len(tags.Picture) + len(tags.Title) + len(tags.Artist) + len(tags.Album) + len(key) + 256
	s.tagsMu.Lock()
	defer s.tagsMu.Unlock()
	if _, exists := s.tagsCache[key]; exists {
		return s.tagsCache[key], nil
	}
	if len(s.tagsCache) >= 256 || s.tagsBytes+size > 32<<20 {
		s.tagsCache = nil
		s.tagsBytes = 0
	}
	if s.tagsCache == nil {
		s.tagsCache = map[string]MusicTags{}
	}
	s.tagsCache[key] = tags
	s.tagsBytes += size
	return tags, nil
}
func (s *Service) musicMetadata(ctx context.Context, name, id string, checkEncryption bool) (MusicTags, error) {
	release, err := s.acquire(ctx, false)
	if err != nil {
		return MusicTags{}, err
	}
	defer release()
	if err := s.ready(); err != nil {
		return MusicTags{}, err
	}
	role, err := s.role(ctx)
	if err != nil {
		return MusicTags{}, err
	}
	if role == "Follower" {
		return MusicTags{}, os.ErrNotExist
	}
	if role == "Master" {
		row, relation, err := s.resolveGlobal(ctx, id, name)
		if err != nil {
			return MusicTags{}, err
		}
		if row.Kind != "audio" {
			return MusicTags{}, ErrPath
		}
		if checkEncryption {
			if repository, ok := s.repository.(store.EncryptionRepository); ok {
				meta, e := repository.Encryption(ctx, row.ID)
				if e != nil {
					return MusicTags{}, e
				}
				if meta != nil {
					return MusicTags{}, nil
				}
			}
		}
		if relation != nil {
			return s.cachedMusicTags(row.ID+":"+row.ETag, func() (MusicTags, error) {
				reader, err := s.control.ReadGlobalMedia(ctx, row)
				if err != nil {
					return MusicTags{}, err
				}
				defer reader.Close()
				return readMusicTags(reader), nil
			})
		}
		name = row.Path
	}
	object, err := s.ValidateTrack(name)
	if err != nil || object.Kind != "audio" {
		return MusicTags{}, ErrPath
	}
	if checkEncryption && role != "Master" {
		ids, e := s.repository.EnsureObjects(ctx, []store.MediaObject{object})
		if e != nil {
			return MusicTags{}, e
		}
		if repository, ok := s.repository.(store.EncryptionRepository); ok {
			meta, e := repository.Encryption(ctx, ids[name])
			if e != nil {
				return MusicTags{}, e
			}
			if meta != nil {
				return MusicTags{}, nil
			}
		}
	}
	file, err := s.root.Open(name)
	if err != nil {
		return MusicTags{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return MusicTags{}, err
	}
	key := name + ":" + strconv.FormatInt(info.Size(), 10) + ":" + strconv.FormatInt(info.ModTime().UnixNano(), 10)
	return s.cachedMusicTags(key, func() (MusicTags, error) { return tagsFromFile(file, info.Size()), nil })
}
func (s *Service) applyMusicTags(ctx context.Context, track *Track) {
	if track.Type != "audio" || track.Encryption != nil {
		return
	}
	tags, err := s.musicMetadata(ctx, track.MediaPath, track.ResourceID, false)
	if err != nil {
		return
	}
	if tags.Title != "" {
		track.Title = tags.Title
	}
	if tags.Artist != "" {
		track.Artist = tags.Artist
	}
	track.Album = tags.Album
	if len(tags.Picture) > 0 {
		track.Cover = "/api/v1/media/cover?" + url.Values{"file_path": {track.MediaPath}, "resource_id": {track.ResourceID}}.Encode()
	}
}
func (s *Service) DecorateMusicTracks(ctx context.Context, tracks []Track) {
	covers := map[string]string{}
	for i := range tracks {
		s.applyMusicTags(ctx, &tracks[i])
		if strings.HasPrefix(tracks[i].Cover, "/api/v1/media/cover?") {
			covers[path.Dir(tracks[i].MediaPath)+":"+tracks[i].Album] = tracks[i].Cover
		}
	}
	for i := range tracks {
		if tracks[i].Encryption == nil && tracks[i].Cover == "/favicon.ico" && tracks[i].Album != "" {
			if cover := covers[path.Dir(tracks[i].MediaPath)+":"+tracks[i].Album]; cover != "" {
				tracks[i].Cover = cover
			}
		}
	}
}
