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

// Member events of synthwerk#37 (synthwerk-contracts events/identity).
const (
	MemberInvited             = "dev.synthwerk.identity.member.invited.v1"
	MemberInvitedSchema       = "https://schemas.synthwerk.dev/events/identity/member.invited.v1.json"
	MemberInviteRevoked       = "dev.synthwerk.identity.member.invite_revoked.v1"
	MemberInviteRevokedSchema = "https://schemas.synthwerk.dev/events/identity/member.invite_revoked.v1.json"
	MemberDeactivated         = "dev.synthwerk.identity.member.deactivated.v1"
	MemberDeactivatedSchema   = "https://schemas.synthwerk.dev/events/identity/member.deactivated.v1.json"
	MemberReactivated         = "dev.synthwerk.identity.member.reactivated.v1"
	MemberReactivatedSchema   = "https://schemas.synthwerk.dev/events/identity/member.reactivated.v1.json"
)

// MemberFactData is the data of member.deactivated and member.reactivated: ids
// and the role, no email.
type MemberFactData struct {
	OrgID   string `json:"org_id"`
	UserSub string `json:"user_sub"`
	Role    Role   `json:"role"`
}

func memberFact(ctx context.Context, typ, schema, source string, org Org, sub string, role Role, actor string) (cloudevents.Event, error) {
	return cloudevents.New(ctx, typ, source,
		MemberFactData{OrgID: org.ID, UserSub: sub, Role: role},
		cloudevents.WithSubject(sub),
		cloudevents.WithOrg(org.ID),
		cloudevents.WithActor(actor),
		cloudevents.WithDataSchema(schema),
	)
}

// InvitedData is the data of member.invited: the invitation id and the role. No
// email and no subject id, so the event is the same for every email.
type InvitedData struct {
	OrgID        string `json:"org_id"`
	InvitationID string `json:"invitation_id"`
	Role         Role   `json:"role"`
}

func invitedFact(ctx context.Context, source string, org Org, inv Invitation) (cloudevents.Event, error) {
	return invitationFact(ctx, MemberInvited, MemberInvitedSchema, source, org, inv, inv.InvitedBy)
}

// invitationFact is member.invited or member.invite_revoked: the same data.
func invitationFact(ctx context.Context, typ, schema, source string, org Org, inv Invitation, actorSub string) (cloudevents.Event, error) {
	return cloudevents.New(ctx, typ, source,
		InvitedData{OrgID: org.ID, InvitationID: inv.ID, Role: inv.Role},
		cloudevents.WithSubject(inv.ID),
		cloudevents.WithOrg(org.ID),
		cloudevents.WithActor("user:"+actorSub),
		cloudevents.WithDataSchema(schema),
	)
}
