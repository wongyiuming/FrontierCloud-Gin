package protocol

// MaxOpaquePlainBytes matches the native storage allocation ceiling. It is a
// structural upper bound, not permission to allocate memory proportional to an
// object. Encrypted media v1 retains its own smaller metadata-format bound.
const MaxOpaquePlainBytes int64 = 10 * 1024 * 1024 * 1024 * 1024
