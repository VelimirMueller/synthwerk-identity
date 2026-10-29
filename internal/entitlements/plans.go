// Package entitlements holds the plan of each org and the limits it gives
// (synthwerk#31). Every active org has a plan. The default plan is free; paid
// plans come in M5 (synthwerk#50).
//
// Identity stores the resolved limits per org and writes
// org.entitlements_changed.v1 to the outbox in the same transaction as every
// change. Other services read the limits over HTTP (GET /v1/me/entitlements with
// the caller's token, GET /v1/orgs/{orgId}/entitlements) and may cache them from
// the event.
package entitlements

import (
	"errors"
	"fmt"
	"strconv"
)

// Free is the plan of every new org.
const Free = "free"

// Limits of a plan. 0 means no limit. A day is a UTC day.
type Limits struct {
	LLMTokensPerUserPerDay int64
	LLMTokensPerOrgPerDay  int64
	AppsPerOrg             int32
}

// MaxApps is the highest apps_per_org the contract allows.
const MaxApps = 10000

// FreeDefaults are the limits of the free plan when no config sets them. The
// numbers are placeholders until the product decides (synthwerk#31). They match
// the llm defaults (SYNTHWERK_LLM_QUOTA_USER_TOKENS, _ORG_TOKENS).
var FreeDefaults = Limits{LLMTokensPerUserPerDay: 50000, LLMTokensPerOrgPerDay: 500000, AppsPerOrg: 3}

// Plan is a plan name and its limits.
type Plan struct {
	Name   string
	Limits Limits
}

// Validate reports limits the contract does not allow.
func (l Limits) Validate() error {
	var errs []error
	if l.LLMTokensPerUserPerDay < 0 {
		errs = append(errs, errors.New("llm tokens per user per day must be 0 or more"))
	}
	if l.LLMTokensPerOrgPerDay < 0 {
		errs = append(errs, errors.New("llm tokens per org per day must be 0 or more"))
	}
	if l.AppsPerOrg < 0 || l.AppsPerOrg > MaxApps {
		errs = append(errs, fmt.Errorf("apps per org must be 0 to %d", MaxApps))
	}
	return errors.Join(errs...)
}

// Env names of the free plan limits, without the SYNTHWERK_IDENTITY_ prefix.
const (
	EnvUserTokens = "FREE_LLM_TOKENS_PER_USER_PER_DAY" //nolint:gosec // G101: an env name, not a credential
	EnvOrgTokens  = "FREE_LLM_TOKENS_PER_ORG_PER_DAY"  //nolint:gosec // G101: an env name, not a credential
	EnvApps       = "FREE_APPS_PER_ORG"
)

// FreePlan reads the free plan from config. lookup returns the value of an env
// name (see Env*), or "" when it is unset; unset keeps the FreeDefaults value.
func FreePlan(lookup func(name string) string) (Plan, error) {
	l := FreeDefaults
	var errs []error
	if v := lookup(EnvUserTokens); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err != nil {
			errs = append(errs, fmt.Errorf("%s: not a whole number", EnvUserTokens))
		} else {
			l.LLMTokensPerUserPerDay = n
		}
	}
	if v := lookup(EnvOrgTokens); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err != nil {
			errs = append(errs, fmt.Errorf("%s: not a whole number", EnvOrgTokens))
		} else {
			l.LLMTokensPerOrgPerDay = n
		}
	}
	if v := lookup(EnvApps); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err != nil {
			errs = append(errs, fmt.Errorf("%s: not a whole number", EnvApps))
		} else {
			l.AppsPerOrg = int32(n)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return Plan{}, fmt.Errorf("entitlements: free plan: %w", err)
	}
	if err := l.Validate(); err != nil {
		return Plan{}, fmt.Errorf("entitlements: free plan: %w", err)
	}
	return Plan{Name: Free, Limits: l}, nil
}
