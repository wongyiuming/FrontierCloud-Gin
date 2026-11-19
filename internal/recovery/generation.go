package recovery

import "github.com/wongyiuming/FrontierCloud-Gin/migrations"

// Generations 10 and 11 add dormant tables. Nonempty tree/intent state is
// refused until protected backup and restore are implemented.
func SupportedSchemaGeneration(generation int) bool {
	return generation == migrations.Generation || migrations.Generation == 11 && (generation == 6 || generation == 7 || generation == 8 || generation == 9 || generation == 10)
}
