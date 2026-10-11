// Package contracts embeds language-neutral protocol artifacts. No runtime
// generation step imports a Python application.
package contracts

import _ "embed"

// OpenAPI is the reviewed effective public API schema for the native runtime.
//
//go:embed v2/openapi.json
var OpenAPI []byte
