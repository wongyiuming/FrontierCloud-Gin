package runtimefacts

// BusinessPreparationReport acknowledges the offline preparation of one empty
// SQLite Master. It carries no authority to open the site to traffic.
type BusinessPreparationReport struct {
	TargetMasterID string `json:"target_master_id"`
	Prepared       bool   `json:"prepared"`
	RestoreReady   bool   `json:"restore_ready"`
}

type BusinessNativeResumeReport struct {
	TargetMasterID string `json:"target_master_id"`
	Resumed        bool   `json:"resumed"`
	RestoreReady   bool   `json:"restore_ready"`
}

// BusinessActivationReport describes a Master available for Admin reingest
// with the public maintenance marker still present.
type BusinessActivationReport struct {
	TargetMasterID    string `json:"target_master_id"`
	SourceSHA256      string `json:"source_sha256"`
	ServicesStarted   bool   `json:"services_started"`
	ManualMaintenance bool   `json:"manual_maintenance"`
	RestoreReady      bool   `json:"restore_ready"`
}
