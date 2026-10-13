package recovery

import "github.com/wongyiuming/FrontierCloud-Gin/migrations"

// Generation 6 is the deployed native baseline for the explicit generation-7
// additive migration. This is not an automatic current-1 compatibility grant:
// a later schema must independently define and test its recovery boundary.
func SupportedSchemaGeneration(generation int) bool {
	return generation == migrations.Generation || migrations.Generation == 7 && generation == 6
}
