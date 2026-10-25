package operator

import "github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"

// RuntimeFact is an allowlist. It excludes credentials, endpoints, arbitrary
// peer summaries, authentication material and certificate export envelopes.
type RuntimeFact = runtimefacts.RuntimeFact
type NodeFact = runtimefacts.NodeFact
