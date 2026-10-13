package operator

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

var ErrRetirementIncomplete = errors.New("retirement is blocked or incomplete; any established write fence remains; inspect and retry through the same Master")

func (c *NodeClient) RetirementApply(ctx context.Context, member, confirmation string) (result store.RetirementFence, e error) {
	if !nodeClientID(member) || confirmation != member || c.csrf == "" {
		return result, ErrNodeAuthority
	}
	var nodes struct {
		Role          string               `json:"role"`
		ID            string               `json:"node_id"`
		Relationships []store.Relationship `json:"relationships"`
	}
	status, e := c.request(ctx, "GET", "/nodes", "", "application/json", &nodes)
	if e != nil || status != 200 {
		return result, ErrNodeClient
	}
	if nodes.Role != "Master" || !nodeClientID(nodes.ID) || nodes.ID == member {
		return result, ErrNodeAuthority
	}
	relationship := ""
	for _, rel := range nodes.Relationships {
		if rel.PeerID == member && rel.Direction == "downstream" && (rel.State == "active" || rel.State == "retiring" || rel.State == "revoked") {
			if relationship != "" || !nodeClientID(rel.ID) {
				return result, ErrNodeAuthority
			}
			relationship = rel.ID
		}
	}
	if relationship == "" {
		return result, ErrNodeAuthority
	}
	raw, _ := json.Marshal(map[string]string{"member_id": member, "confirm_member_id": confirmation})
	var response json.RawMessage
	status, e = c.request(ctx, "POST", "/nodes/"+relationship+"/retire/apply", string(raw), "application/json", &response)
	if e != nil {
		return result, e
	}
	if status == 409 {
		var failed struct {
			Code  string                `json:"code"`
			Fence store.RetirementFence `json:"fence"`
		}
		if json.Unmarshal(response, &failed) != nil || failed.Code != "retirement_incomplete" {
			return result, ErrNodeClient
		}
		result = failed.Fence
		if result == (store.RetirementFence{}) {
			return result, ErrRetirementIncomplete
		}
	} else if json.Unmarshal(response, &result) != nil {
		return result, ErrNodeClient
	}
	if result.MemberID != member || result.MasterID != nodes.ID || result.RelationshipID != relationship || result.FencedAt <= 0 || result.FencedAt > time.Now().Unix()+30 || result.CompletedAt > time.Now().Unix()+30 || result.CompletedAt != 0 && result.CompletedAt < result.FencedAt {
		return store.RetirementFence{}, ErrNodeClient
	}
	if status == 409 {
		return result, ErrRetirementIncomplete
	}
	if result.CompletedAt == 0 || result.CompletedAt > time.Now().Unix()+30 {
		return store.RetirementFence{}, ErrNodeClient
	}
	return result, nil
}
