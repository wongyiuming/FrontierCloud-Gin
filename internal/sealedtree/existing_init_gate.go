package sealedtree

import "errors"

// ErrLegacyWritersUnfenced blocks the product-facing initialization entry
// until every old writer and offline worker enforces the durable tree marker.
var ErrLegacyWritersUnfenced = errors.New("existing business writers are not fenced for the sealed tree")
