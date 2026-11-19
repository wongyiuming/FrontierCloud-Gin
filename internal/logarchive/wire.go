package logarchive

import (
	"bytes"
	"encoding/json"
)

// ControlValue converts log DTOs to the existing canonical protocol's JSON
// types. In particular, ciphertext is base64, structs become objects, and
// integers remain exact. Do not change the shared signing protocol for logs.
func ControlValue(value any) (any, error) {
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > 384<<10 {
		return nil, ErrPolicy
	}
	var result any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if e = decoder.Decode(&result); e != nil {
		return nil, e
	}
	return result, nil
}
