package app

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// StreamName is the JetStream stream of identity facts (contracts events/catalog.yaml).
const StreamName = "EVT_IDENTITY"

// EnsureStream creates or updates EVT_IDENTITY. The outbox relay publishes into it.
func EnsureStream(ctx context.Context, js jetstream.JetStream) error {
	_, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:        StreamName,
		Description: "Facts of synthwerk-identity (CloudEvents, ids only, no personal data).",
		Subjects:    []string{"evt.identity.>"},
		Storage:     jetstream.FileStorage,
		MaxAge:      30 * 24 * time.Hour,
		Duplicates:  2 * time.Minute, // >= relay restart time, see kit/outbox
	})
	if err != nil {
		return fmt.Errorf("app: stream %s: %w", StreamName, err)
	}
	return nil
}
