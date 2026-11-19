package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestSealedRetirementRefusesLegacyInventory(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		a := &Admin{public: &Public{}}
		if sealed {
			a.public.opaqueTree = &sealedtree.SQLStore{}
		}
		if rejectSealedRetirement(c, a) != sealed {
			t.Fatal("retirement admission disagrees with catalog mode")
		}
		if sealed && (w.Code != 409 || !strings.Contains(w.Body.String(), `"code":"sealed_retirement_unavailable"`) || strings.Contains(w.Body.String(), `"report"`)) {
			t.Fatal("sealed inventory returned a misleading report", w.Code, w.Body.String())
		}
		if !sealed && w.Body.Len() != 0 {
			t.Fatal("legacy admission wrote a response")
		}
	}
}
