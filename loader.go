// Package threatfeed loads the embedded JA4 client-identity threat feed and
// derives allow / deny JA4 sets for consumers such as ja4-guard.
package threatfeed

import (
	_ "embed"
	"encoding/json"
	"sort"
)

//go:embed feed.json
var raw []byte

type Provenance struct {
	Method  string `json:"method"`
	Date    string `json:"date"`
	Tool    string `json:"tool,omitempty"`
	Version string `json:"version,omitempty"`
	Ref     string `json:"ref,omitempty"`
}

type Entry struct {
	JA4        string     `json:"ja4"`
	JA4H       string     `json:"ja4h,omitempty"`
	AkamaiH2   string     `json:"akamai_h2,omitempty"`
	Category   string     `json:"category"`
	Label      string     `json:"label"`
	Verdict    string     `json:"verdict"`
	Source     string     `json:"source"`
	Provenance Provenance `json:"provenance"`
}

type Feed struct {
	Metadata map[string]any `json:"metadata"`
	Entries  []Entry        `json:"entries"`
}

func Load() (*Feed, error) {
	var f Feed
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *Feed) ja4sFor(verdicts ...string) []string {
	want := map[string]struct{}{}
	for _, v := range verdicts {
		want[v] = struct{}{}
	}
	set := map[string]struct{}{}
	for _, e := range f.Entries {
		if _, ok := want[e.Verdict]; ok {
			set[e.JA4] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for j := range set {
		out = append(out, j)
	}
	sort.Strings(out)
	return out
}

// AllowJA4 returns the browser allow-list JA4s.
func (f *Feed) AllowJA4() []string { return f.ja4sFor("allow") }

// DenyJA4 returns the non-browser / suspicious JA4s.
func (f *Feed) DenyJA4() []string { return f.ja4sFor("non-browser", "suspicious") }

// Lookup returns every entry matching ja4.
func (f *Feed) Lookup(ja4 string) []Entry {
	var out []Entry
	for _, e := range f.Entries {
		if e.JA4 == ja4 {
			out = append(out, e)
		}
	}
	return out
}
