package recording

import (
	"strings"
	"testing"
)

func TestAudioPreparationBindingSeparatesAuthenticatedInputs(t *testing.T) {
	user, id := strings.Repeat("1", 32), strings.Repeat("2", 32)
	browser := "browser:v2:" + strings.Repeat("a", 64)
	base, err := AudioPreparationBinding(user, browser, id)
	if err != nil || strings.Contains(base, browser) {
		t.Fatal("valid binding was rejected or exposed the session")
	}
	for _, args := range [][3]string{
		{strings.Repeat("3", 32), browser, id},
		{user, "browser:v2:" + strings.Repeat("b", 64), id},
		{user, browser, strings.Repeat("4", 32)},
	} {
		other, err := AudioPreparationBinding(args[0], args[1], args[2])
		if err != nil || other == base {
			t.Fatal("distinct authorization scope was not bound")
		}
	}
	for _, args := range [][3]string{
		{"", browser, id}, {strings.Repeat("A", 32), browser, id},
		{user, "browser:v2:" + strings.Repeat("A", 64), id},
		{user, "browser:v1:" + strings.Repeat("a", 64), id},
		{user, browser, strings.Repeat("2", 31)},
	} {
		if _, err := AudioPreparationBinding(args[0], args[1], args[2]); err == nil {
			t.Fatal("invalid authorization scope was accepted")
		}
	}
}
