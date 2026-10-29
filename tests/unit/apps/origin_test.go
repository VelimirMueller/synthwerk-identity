package apps_test

import (
	"strings"
	"testing"

	"github.com/VelimirMueller/synthwerk-identity/internal/apps"
)

func TestCanonicalOrigin(t *testing.T) {
	ok := []struct{ in, want string }{
		{"https://shop.example", "https://shop.example"},
		{"https://Shop.Example", "https://shop.example"},
		{"HTTPS://shop.example", "https://shop.example"},
		{"https://shop.example:443", "https://shop.example"},
		{"https://shop.example:8443", "https://shop.example:8443"},
		{"https://xn--bcher-kva.example", "https://xn--bcher-kva.example"},
		{"https://localhost", "https://localhost"},
		{"http://localhost:3000", "http://localhost:3000"},
		{"http://localhost:80", "http://localhost"},
		{"http://127.0.0.1:5173", "http://127.0.0.1:5173"},
		{"http://[::1]:8080", "http://[::1]:8080"},
		{"https://[2001:DB8:0:0::1]", "https://[2001:db8::1]"},
		{"https://192.0.2.10", "https://192.0.2.10"},
	}
	for _, c := range ok {
		t.Run("CanonicalOrigin - "+c.in+" - "+c.want, func(t *testing.T) {
			got, err := apps.CanonicalOrigin(c.in)
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}

	bad := []struct{ name, in string }{
		{"empty", ""},
		{"null origin", "null"},
		{"no scheme", "shop.example"},
		{"other scheme", "ftp://shop.example"},
		{"javascript scheme", "javascript://shop.example"},
		{"http on a public host", "http://shop.example"},
		{"http on a lookalike of localhost", "http://localhost.evil.test"},
		{"trailing slash", "https://shop.example/"},
		{"path", "https://shop.example/widget"},
		{"query", "https://shop.example?a=1"},
		{"fragment", "https://shop.example#x"},
		{"user info", "https://shop.example@evil.test"},
		{"wildcard", "https://*.shop.example"},
		{"percent encoding", "https://shop%2eexample"},
		{"backslash", `https://shop.example\evil.test`},
		{"space", "https://shop .example"},
		{"tab", "https://shop.example\t"},
		{"CRLF", "https://shop.example\r\nX: y"},
		{"non-ASCII host", "https://bücher.example"},
		{"kelvin sign folds to k", "https://Kexample.com"},
		{"trailing dot", "https://shop.example."},
		{"empty label", "https://shop..example"},
		{"label starts with hyphen", "https://-shop.example"},
		{"label ends with hyphen", "https://shop-.example"},
		{"label too long", "https://" + strings.Repeat("a", 64) + ".example"},
		{"underscore", "https://shop_1.example"},
		{"empty port", "https://shop.example:"},
		{"port 0", "https://shop.example:0"},
		{"port too big", "https://shop.example:65536"},
		{"port with leading zero", "https://shop.example:0443"},
		{"port with sign", "https://shop.example:+443"},
		{"two ports", "https://shop.example:1:2"},
		{"IPv4 with leading zero", "https://010.0.0.1"},
		{"IPv4 short", "https://1.2.3"},
		{"IPv6 without brackets", "https://2001:db8::1"},
		{"IPv6 with zone", "https://[fe80::1%25en0]"},
		{"IPv6 unclosed", "https://[::1"},
		{"IPv6 junk after bracket", "https://[::1]x"},
		{"IPv4 in brackets", "https://[127.0.0.1]"},
		{"too long", "https://" + strings.Repeat("a.", 130) + "example"},
	}
	for _, c := range bad {
		t.Run("CanonicalOrigin - "+c.name+" - refused", func(t *testing.T) {
			if got, err := apps.CanonicalOrigin(c.in); err == nil {
				t.Fatalf("accepted %q as %q", c.in, got)
			}
		})
	}
}

func TestMatchOrigin(t *testing.T) {
	allowed, _, err := apps.CanonicalOrigins([]string{"https://shop.example", "http://localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{"exact", "https://shop.example", true},
		{"exact with default port", "https://shop.example:443", true},
		{"exact upper case host", "https://SHOP.example", true},
		{"localhost with port", "http://localhost:3000", true},
		{"suffix trick", "https://shop.example.evil.test", false},
		{"prefix trick", "https://evilshop.example", false},
		{"hyphen prefix trick", "https://evil-shop.example", false},
		{"subdomain", "https://a.shop.example", false},
		{"parent domain", "https://example", false},
		{"other scheme", "http://shop.example", false},
		{"other port", "https://shop.example:8443", false},
		{"localhost other port", "http://localhost:3001", false},
		{"localhost without port", "http://localhost", false},
		{"https localhost", "https://localhost:3000", false},
		{"user info trick", "https://shop.example@evil.test", false},
		{"path", "https://shop.example/", false},
		{"null", "null", false},
		{"missing", "", false},
	}
	for _, c := range cases {
		t.Run("MatchOrigin - "+c.name, func(t *testing.T) {
			got, ok := apps.MatchOrigin(allowed, c.header)
			if ok != c.want {
				t.Fatalf("match %q = %v, want %v", c.header, ok, c.want)
			}
			if ok && got != allowed[0] && got != allowed[1] {
				t.Fatalf("canonical %q not in the list", got)
			}
		})
	}
}

func TestCanonicalOrigins(t *testing.T) {
	t.Run("CanonicalOrigins - same origin twice after canonical form - refused at index 1", func(t *testing.T) {
		_, bad, err := apps.CanonicalOrigins([]string{"https://shop.example", "https://SHOP.example:443"})
		if err == nil || bad != 1 {
			t.Fatalf("bad %d, err %v", bad, err)
		}
	})
	t.Run("CanonicalOrigins - empty list - refused, no index", func(t *testing.T) {
		if _, bad, err := apps.CanonicalOrigins(nil); err == nil || bad != -1 {
			t.Fatalf("bad %d, err %v", bad, err)
		}
	})
	t.Run("CanonicalOrigins - 21 origins - refused", func(t *testing.T) {
		in := make([]string, apps.MaxOrigins+1)
		for i := range in {
			in[i] = "https://s" + strings.Repeat("a", i+1) + ".example"
		}
		if _, _, err := apps.CanonicalOrigins(in); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("CanonicalOrigins - valid list - canonical forms in order", func(t *testing.T) {
		got, _, err := apps.CanonicalOrigins([]string{"https://B.example:443", "http://127.0.0.1:80"})
		if err != nil || len(got) != 2 || got[0] != "https://b.example" || got[1] != "http://127.0.0.1" {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}
