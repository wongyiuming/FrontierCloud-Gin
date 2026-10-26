package recovery

import "github.com/wongyiuming/FrontierCloud-Gin/migrations"

// Generations 6 and 7 are explicit native source boundaries for generation 8.
// Keep the already-defined generation-6 archive readable while admitting the
// deployed generation-7 source of this additive S3 upgrade. A future schema
// must independently define and test its boundary; current-1 is not inferred.
func SupportedSchemaGeneration(generation int) bool {
	return generation == migrations.Generation || migrations.Generation == 8 && (generation == 6 || generation == 7)
}
