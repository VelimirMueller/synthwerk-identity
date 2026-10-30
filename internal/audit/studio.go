package audit

// The page builder changes of studio in the audit list (synthwerk#106). Studio
// owns the pages and writes dev.synthwerk.studio.page.{created,published,
// rolled_back}.v1 to its builder_events table; its relay publishes them on
// EVT_STUDIO. This JetStream durable consumer copies each valid event into
// identity.audit_events, with the rules of consumer.go. Studio owns EVT_STUDIO:
// identity never creates it.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"regexp"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"
)

// Names of the facts and their place on the bus (synthwerk-contracts events/catalog.yaml).
const (
	StudioPageCreatedType    = "dev.synthwerk.studio.page.created.v1"
	StudioPagePublishedType  = "dev.synthwerk.studio.page.published.v1"
	StudioPageRolledBackType = "dev.synthwerk.studio.page.rolled_back.v1"
	StudioStreamName         = "EVT_STUDIO"
	// StudioPagesDurable is the consumer name. All replicas share it, so each
	// event reaches one replica.
	StudioPagesDurable = "identity-studio-pages"
)

// StudioPageSubjects are the NATS subjects of the three types, in catalog order.
var StudioPageSubjects = []string{
	"evt.studio.page.created.v1",
	"evt.studio.page.published.v1",
	"evt.studio.page.rolled_back.v1",
}

// Limits of the data schemas (events/studio/page.*.v1.schema.json).
var (
	slugRe        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	studioLocales = map[string]bool{"de": true, "en": true}
)

// studioPageData mirrors the three data schemas. Pointers find a missing field;
// raw previous_version tells null from missing.
type studioPageData struct {
	OrgID           *string         `json:"org_id"`
	PageID          *string         `json:"page_id"`
	Slug            *string         `json:"slug"`
	Locale          *string         `json:"locale"`
	Version         *int64          `json:"version"`
	PreviousVersion json.RawMessage `json:"previous_version"`
}

// ParseStudioPage decodes and checks one CloudEvent of a studio page type.
// Every error wraps ErrMalformed and names the rule, never a value.
func ParseStudioPage(raw []byte) (Entry, error) {
	var ev cloudevents.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return Entry{}, malformed("envelope is not JSON")
	}
	if err := ev.Validate(); err != nil {
		return Entry{}, malformed("envelope is not a valid CloudEvent")
	}
	created := ev.Type == StudioPageCreatedType
	if !created && ev.Type != StudioPagePublishedType && ev.Type != StudioPageRolledBackType {
		return Entry{}, malformed("type is not a studio page type")
	}
	if !actorRe.MatchString(ev.Actor) {
		return Entry{}, malformed("actor is not user:[A-Za-z0-9_-]{1,128}")
	}
	// The schemas say additionalProperties: false. ev.Data is one JSON value: the
	// envelope decode checked that.
	dec := json.NewDecoder(bytes.NewReader(ev.Data))
	dec.DisallowUnknownFields()
	var d studioPageData
	if err := dec.Decode(&d); err != nil {
		return Entry{}, malformed("data does not match the schema")
	}
	if err := d.check(created); err != nil {
		return Entry{}, err
	}
	if ev.OrgID != *d.OrgID {
		return Entry{}, malformed("orgid and data.org_id are not the same")
	}
	if ev.Subject != *d.PageID {
		return Entry{}, malformed("subject and data.page_id are not the same")
	}
	data, err := d.canonical(created)
	if err != nil {
		return Entry{}, malformed("data does not encode")
	}
	return Entry{
		ID: ev.ID, Type: ev.Type, OrgID: *d.OrgID, Actor: ev.Actor, Subject: ev.Subject,
		Time: ev.Time.UTC(), Data: data, UserSub: ev.Actor[len("user:"):],
	}, nil
}

func (d studioPageData) check(created bool) error {
	if d.OrgID == nil || !lowerUUID(*d.OrgID) {
		return malformed("org_id is missing or not a lowercase UUID")
	}
	if d.PageID == nil || !lowerUUID(*d.PageID) {
		return malformed("page_id is missing or not a lowercase UUID")
	}
	if d.Slug == nil || !slugRe.MatchString(*d.Slug) {
		return malformed("slug is missing or not a slug")
	}
	if d.Locale == nil || !studioLocales[*d.Locale] {
		return malformed("locale is missing or not de or en")
	}
	if created {
		if d.Version != nil || d.PreviousVersion != nil {
			return malformed("page.created has no version")
		}
		return nil
	}
	if d.Version == nil || *d.Version < 1 {
		return malformed("version is missing or below 1")
	}
	if d.PreviousVersion == nil {
		return malformed("previous_version is missing")
	}
	if !bytes.Equal(d.PreviousVersion, []byte("null")) {
		var p int64
		if json.Unmarshal(d.PreviousVersion, &p) != nil || p < 1 {
			return malformed("previous_version is not null or a version")
		}
	}
	return nil
}

// canonical encodes the checked fields only, with the schema key names. The audit
// row stores this copy, never the received bytes: Go's decoder matches keys without
// case and keeps the last of two equal keys (security review, synthwerk#106).
func (d studioPageData) canonical(created bool) (json.RawMessage, error) {
	out := map[string]any{"org_id": *d.OrgID, "page_id": *d.PageID, "slug": *d.Slug, "locale": *d.Locale}
	if !created {
		out["version"] = *d.Version
		var prev *int64
		if err := json.Unmarshal(d.PreviousVersion, &prev); err != nil {
			return nil, err
		}
		out["previous_version"] = prev
	}
	return json.Marshal(out)
}

func lowerUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s
}

// studioSource is the EVT_STUDIO consumer of the page builder changes.
var studioSource = source{
	name:        "studio",
	label:       "studio page",
	stream:      StudioStreamName,
	durable:     StudioPagesDurable,
	description: "synthwerk-identity: copy the page builder changes of studio to the audit list (synthwerk#106).",
	subjects:    StudioPageSubjects,
	parse:       ParseStudioPage,
}

// StudioJetStreamConfig is the durable consumer identity creates or updates on
// EVT_STUDIO. Other studio subjects stay in the stream.
func StudioJetStreamConfig(c ConsumerConfig) jetstream.ConsumerConfig {
	return studioSource.jetStream(c)
}

// NewStudioConsumer returns the page builder consumer on EVT_STUDIO. Call Run.
func NewStudioConsumer(js jetstream.JetStream, rec Recorder, logger *slog.Logger, cfg ConsumerConfig) *Consumer {
	return newConsumer(studioSource, js, rec, logger, cfg)
}
