package threatfeed

import (
	"regexp"
	"testing"
)

var ja4re = regexp.MustCompile(`^[tq]\d{2}[di]\d{2}\d{2}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func TestLoad(t *testing.T) {
	f, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) == 0 {
		t.Fatal("no entries")
	}
	for _, e := range f.Entries {
		if !ja4re.MatchString(e.JA4) {
			t.Errorf("%s: bad JA4 %q", e.Label, e.JA4)
		}
		if e.Provenance.Method != "measured" && e.Provenance.Method != "cited" {
			t.Errorf("%s: bad provenance.method %q", e.Label, e.Provenance.Method)
		}
		if e.Category == "browser" && e.Verdict != "allow" {
			t.Errorf("%s: browser must be allow, got %q", e.Label, e.Verdict)
		}
	}
}

func TestAllowDenyDisjoint(t *testing.T) {
	f, _ := Load()
	allow := map[string]struct{}{}
	for _, j := range f.AllowJA4() {
		allow[j] = struct{}{}
	}
	for _, j := range f.DenyJA4() {
		if _, ok := allow[j]; ok {
			t.Errorf("JA4 %s is both allow and deny", j)
		}
	}
	if len(f.AllowJA4()) == 0 || len(f.DenyJA4()) == 0 {
		t.Fatal("expected both allow and deny entries")
	}
}
