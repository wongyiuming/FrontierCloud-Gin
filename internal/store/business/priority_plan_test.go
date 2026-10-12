package business

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func assertPriorityPlan(t *testing.T, items []store.PriorityEntry, kind string) {
	t.Helper()
	for i, item := range items {
		if item.Preference < store.PriorityMinimum || item.Preference > store.PriorityMaximum {
			t.Fatal("range", item)
		}
		if i > 0 && (items[i-1].Preference < item.Preference || items[i-1].Preference == item.Preference && !priorityTie(items[i-1], item, kind)) {
			t.Fatal("target order cannot be represented", items[i-1], item)
		}
	}
}

func TestPriorityPlannerExhaustionNeverPartiallyChanges(t *testing.T) {
	items := []store.PriorityEntry{{Path: "c", Preference: 0}, {Path: "a", Preference: 0}, {Path: "b", Preference: 0}}
	if err := planPriorityRange(items, 0, "media", 0, 0); !errors.Is(err, store.ErrPriorityRange) {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Preference != 0 {
			t.Fatal("partial plan", items)
		}
	}
}

func TestPriorityPlannerEqualCollisionAndBoundaries(t *testing.T) {
	for _, kind := range []string{"media", "directory"} {
		for _, value := range []int{-7, 99, 100, 500, 499999, 500000} {
			items := []store.PriorityEntry{{Path: "a", Preference: value}, {Path: "c", Preference: min(500000, value+1)}, {Path: "b", Preference: value}, {Path: "d", Preference: max(-7, value-1)}}
			if err := planPriority(items, 1, kind); err != nil {
				t.Fatal(value, err)
			}
			assertPriorityPlan(t, items, kind)
			if items[3].Preference != max(-7, value-1) && value != -7 {
				t.Fatal("unrelated lower group changed", items)
			}
		}
	}
}

func TestPriorityPlannerRandomMovesAndLargeTies(t *testing.T) {
	random := rand.New(rand.NewPCG(24, 11))
	for _, kind := range []string{"media", "directory"} {
		for run := 0; run < 600; run++ {
			n := 3 + random.IntN(400)
			items := make([]store.PriorityEntry, n)
			for i := range items {
				items[i] = store.PriorityEntry{Path: fmt.Sprintf("music/scope/%04d", i), Preference: random.IntN(22) - 7}
			}
			sort.Slice(items, func(i, j int) bool {
				if items[i].Preference != items[j].Preference {
					return items[i].Preference > items[j].Preference
				}
				return priorityTie(items[i], items[j], kind)
			})
			from, to := random.IntN(n), random.IntN(n)
			moved := items[from]
			items = slices.Delete(items, from, from+1)
			items = slices.Insert(items, to, moved)
			if err := planPriority(items, to, kind); err != nil {
				t.Fatal(run, err)
			}
			assertPriorityPlan(t, items, kind)
		}
	}
	items := make([]store.PriorityEntry, 20000)
	for i := range items {
		items[i] = store.PriorityEntry{Path: fmt.Sprintf("%08d", i), Preference: 100}
	}
	moved := items[len(items)-1]
	items = slices.Insert(items[:len(items)-1], 1, moved)
	if err := planPriority(items, 1, "media"); err != nil {
		t.Fatal(err)
	}
	assertPriorityPlan(t, items, "media")
}
