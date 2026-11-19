//go:build !linux

package operator

import (
	"context"
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
)

func (d *Deployment) ImportBusinessState(context.Context, Receipt, string, backup.Expectation, string) (backup.BusinessStateReport, error) {
	return backup.BusinessStateReport{}, errors.New("business state import requires a Linux Docker host")
}

func (d *Deployment) PrepareBusinessState(context.Context, Receipt, string) (runtimefacts.BusinessPreparationReport, error) {
	return runtimefacts.BusinessPreparationReport{}, errors.New("business state preparation requires a Linux Docker host")
}

func (d *Deployment) ActivateBusinessState(context.Context, Receipt, string, string) (runtimefacts.BusinessActivationReport, error) {
	return runtimefacts.BusinessActivationReport{}, errors.New("business state activation requires a Linux Docker host")
}
