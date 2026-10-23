package zitadelhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader is the header Zitadel signs every Action call with:
// "t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">". One v1 per signing key.
// Source: zitadel pkg/actions/signing.go (v4.20.0), measured on the local stack 2026-10-23.
const SignatureHeader = "ZITADEL-Signature"

// Tolerance is the maximum age of a signature, as in Zitadel's own validator.
const Tolerance = 300 * time.Second

// Signature errors. The handler answers 401 for all of them and logs only the kind.
var (
	ErrNotSigned     = errors.New("no signature header")
	ErrBadHeader     = errors.New("signature header does not parse")
	ErrTooOld        = errors.New("signature timestamp outside the tolerance")
	ErrBadSignature  = errors.New("no valid signature")
	ErrNoSigningKeys = errors.New("no signing key")
)

// Verify checks header against body with key. now is time.Now in production.
// A timestamp in the future counts like an old one: both are outside the tolerance.
func Verify(body []byte, header, key string, now time.Time) error {
	if key == "" {
		return ErrNoSigningKeys
	}
	if header == "" {
		return ErrNotSigned
	}
	var ts string
	var sigs [][]byte
	for pair := range strings.SplitSeq(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			return ErrBadHeader
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			sig, err := hex.DecodeString(v)
			if err != nil {
				return ErrBadHeader
			}
			sigs = append(sigs, sig)
		}
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 {
		return ErrBadHeader
	}
	if age := now.Sub(time.Unix(unix, 0)); age > Tolerance || age < -Tolerance {
		return ErrTooOld
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, sig := range sigs {
		if hmac.Equal(want, sig) {
			return nil
		}
	}
	return ErrBadSignature
}

// Sign returns a header value for body, as Zitadel builds it. For tests.
func Sign(body []byte, key string, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}
