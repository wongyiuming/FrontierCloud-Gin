package httpapi

import (
	"context"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/search"
)

func TestSelectedLyricSearchUsesLegacyAliases(t *testing.T) {
	items := []sealedtree.NativeLyricScopeItem{
		{Path: "music/現場/跨年/重慶夜曲.mp3", ID: "wanted", LinkedLyricID: "linked"},
		{Path: "music/其他/晚安.wav", ID: "other"},
	}
	for _, input := range []string{"重庆夜曲", "chongqingyequ", "xianchangkuanian", "現場/跨年"} {
		query, err := search.Query(input)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := selectLyricSearchRows(context.Background(), items, query, nil)
		if err != nil || len(rows) != 1 || rows[0].ID != "wanted" {
			t.Fatalf("search %q: got %v, %v", input, rows, err)
		}
	}
	rows, err := selectLyricSearchRows(context.Background(), items, "", func(item sealedtree.NativeLyricScopeItem) bool { return item.LinkedLyricID == "" })
	if err != nil || len(rows) != 1 || rows[0].ID != "other" {
		t.Fatalf("filter rejected valid result: %v, %v", rows, err)
	}
}
