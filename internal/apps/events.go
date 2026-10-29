package apps

import (
	"context"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"
)

// Event type and schema (synthwerk-contracts events/identity).
const (
	AppCreated       = "dev.synthwerk.identity.app.created.v1"
	AppCreatedSchema = "https://schemas.synthwerk.dev/events/identity/app.created.v1.json"
)

// AppCreatedData is the data of app.created.v1. No origins: EVT_IDENTITY carries
// ids and names only.
type AppCreatedData struct {
	AppID string `json:"app_id"`
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
}

func appCreated(ctx context.Context, source string, a App, actorSub string) (cloudevents.Event, error) {
	return cloudevents.New(ctx, AppCreated, source,
		AppCreatedData{AppID: a.ID, OrgID: a.OrgID, Name: a.Name},
		cloudevents.WithSubject(a.ID),
		cloudevents.WithOrg(a.OrgID),
		cloudevents.WithActor("user:"+actorSub),
		cloudevents.WithDataSchema(AppCreatedSchema),
	)
}
