package release

import "testing"

func TestOnlyCanonicalBranchPolicyIsAccepted(t *testing.T) {
	if !DefaultPolicy().Valid() {
		t.Fatal("canonical policy refused")
	}
	for _, policy := range []Policy{{"gin_main", "gin_dev"}, {"main", "main"}, {"dev", "main"}, {"main", "candidate"}, {}} {
		if policy.Valid() {
			t.Fatal("noncanonical policy accepted", policy)
		}
		if _, err := NewVerifier(policy, ""); err == nil {
			t.Fatal("verifier accepted noncanonical policy", policy)
		}
	}
}
