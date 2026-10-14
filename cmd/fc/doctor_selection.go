package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
)

// Existing deployments bind doctor to their receipt, not fresh-install defaults.
func doctorDeployment(directory, role, database string, roleExplicit, databaseExplicit bool) (*operator.Deployment, error) {
	if _, err := os.Lstat(filepath.Join(directory, operator.ReceiptFile)); os.IsNotExist(err) {
		return operator.New(directory, role, database)
	} else if err != nil {
		return nil, errors.New("deployment receipt cannot be inspected")
	}
	deployment, receipt, err := operator.Open(directory)
	if err != nil {
		return nil, err
	}
	if roleExplicit && role != receipt.Role || databaseExplicit && database != receipt.Database {
		return nil, errors.New("explicit doctor role/database differs from the recorded deployment")
	}
	return deployment, nil
}
