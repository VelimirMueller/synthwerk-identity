package entitlements

import (
	"context"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"
)

// Event type and schema (synthwerk-contracts events/identity).
const (
	Changed       = "dev.synthwerk.identity.org.entitlements_changed.v1"
	ChangedSchema = "https://schemas.synthwerk.dev/events/identity/org.entitlements_changed.v1.json"
)

// Reason of a change (event field reason).
type Reason string

// Reasons.
const (
	// ReasonPlanAssigned: the org got its first plan (new org, or an org from before #31).
	ReasonPlanAssigned Reason = "plan_assigned"
	// ReasonDefaultsChanged: the limits of the org's plan changed in config.
	ReasonDefaultsChanged Reason = "plan_defaults_changed"
)

// LimitsData is the limits object of the event.
type LimitsData struct {
	LLMTokensPerUserPerDay int64 `json:"llm_tokens_per_user_per_day"`
	LLMTokensPerOrgPerDay  int64 `json:"llm_tokens_per_org_per_day"`
	AppsPerOrg             int32 `json:"apps_per_org"`
}

// ChangedData is the data of org.entitlements_changed.v1: the full new state.
type ChangedData struct {
	OrgID   string     `json:"org_id"`
	Plan    string     `json:"plan"`
	Limits  LimitsData `json:"limits"`
	Version int64      `json:"version"`
	Reason  Reason     `json:"reason"`
}

func changed(ctx context.Context, source string, e Entitlements, why Reason) (cloudevents.Event, error) {
	return cloudevents.New(ctx, Changed, source,
		ChangedData{
			OrgID: e.OrgID, Plan: e.Plan, Version: e.Version, Reason: why,
			Limits: LimitsData{
				LLMTokensPerUserPerDay: e.Limits.LLMTokensPerUserPerDay,
				LLMTokensPerOrgPerDay:  e.Limits.LLMTokensPerOrgPerDay,
				AppsPerOrg:             e.Limits.AppsPerOrg,
			},
		},
		cloudevents.WithSubject(e.OrgID),
		cloudevents.WithOrg(e.OrgID),
		cloudevents.WithActor("system"),
		cloudevents.WithDataSchema(ChangedSchema),
	)
}
