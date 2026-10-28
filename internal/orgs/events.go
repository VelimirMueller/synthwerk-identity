package orgs

import (
	"context"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"
)

// Event types and schemas (synthwerk-contracts events/identity).
const (
	OrgCreated        = "dev.synthwerk.identity.org.created.v1"
	OrgCreatedSchema  = "https://schemas.synthwerk.dev/events/identity/org.created.v1.json"
	RoleChanged       = "dev.synthwerk.identity.member.role_changed.v1"
	RoleChangedSchema = "https://schemas.synthwerk.dev/events/identity/member.role_changed.v1.json"
)

// OrgCreatedData is the data of org.created.v1.
type OrgCreatedData struct {
	OrgID    string `json:"org_id"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	OwnerSub string `json:"owner_sub"`
}

// RoleChangedData is the data of member.role_changed.v1.
type RoleChangedData struct {
	OrgID   string `json:"org_id"`
	UserSub string `json:"user_sub"`
	OldRole Role   `json:"old_role"`
	NewRole Role   `json:"new_role"`
}

func orgCreated(ctx context.Context, source string, org Org, ownerSub string) (cloudevents.Event, error) {
	return cloudevents.New(ctx, OrgCreated, source,
		OrgCreatedData{OrgID: org.ID, Name: org.Name, Slug: org.Slug, OwnerSub: ownerSub},
		cloudevents.WithSubject(org.ID),
		cloudevents.WithOrg(org.ID),
		cloudevents.WithActor("system"),
		cloudevents.WithDataSchema(OrgCreatedSchema),
	)
}

func roleChanged(ctx context.Context, source string, org Org, sub string, from, to Role, actor string) (cloudevents.Event, error) {
	return cloudevents.New(ctx, RoleChanged, source,
		RoleChangedData{OrgID: org.ID, UserSub: sub, OldRole: from, NewRole: to},
		cloudevents.WithSubject(sub),
		cloudevents.WithOrg(org.ID),
		cloudevents.WithActor(actor),
		cloudevents.WithDataSchema(RoleChangedSchema),
	)
}
