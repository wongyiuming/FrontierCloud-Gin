package updater

import "testing"

func TestStagingStatusComesFromActualExecutorNotPersistedState(t *testing.T) {
	for _, staging := range []bool{false, true} {
		d := Daemon{status: Status{StagingCD: !staging}, executor: &DockerExecutor{Source: Source{Staging: staging}}}
		if d.Status().StagingCD != staging {
			t.Fatal("persisted state overrode executor CD mode")
		}
	}
}
