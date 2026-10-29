package account

import (
	"context"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"
)

// Event type and schema (synthwerk-contracts events/identity/user.deleted.v1).
const (
	UserDeleted       = "dev.synthwerk.identity.user.deleted.v1"
	UserDeletedSchema = "https://schemas.synthwerk.dev/events/identity/user.deleted.v1.json"
)

// UserDeletedData is the data of user.deleted.v1.
type UserDeletedData struct {
	UserSub     string       `json:"user_sub"`
	DeletedOrgs []DeletedOrg `json:"deleted_orgs"`
}

// userDeleted has no orgid extension: the fact spans every org of the user.
func userDeleted(ctx context.Context, source, sub string, deleted []DeletedOrg) (cloudevents.Event, error) {
	return cloudevents.New(ctx, UserDeleted, source,
		UserDeletedData{UserSub: sub, DeletedOrgs: deleted},
		cloudevents.WithSubject(sub),
		cloudevents.WithActor("user:"+sub),
		cloudevents.WithDataSchema(UserDeletedSchema),
	)
}
