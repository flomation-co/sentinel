package listener

import (
	"strings"
	"testing"
	"time"

	"flomation.app/sentinel/internal/assets"
	"flomation.app/sentinel/internal/persistence"
)

// TestMFANudgeDue covers the cadence: a user who has never been asked is due,
// a recent decline is respected, and an old one has expired.
func TestMFANudgeDue(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }

	cases := []struct {
		name  string
		state *persistence.MFANudgeState
		want  bool
	}{
		{"never asked — no row at all", nil, true},
		{"never declined", &persistence.MFANudgeState{}, true},
		{"declined a moment ago", &persistence.MFANudgeState{DismissedAt: at(-time.Minute), Count: 1}, false},
		{"declined just inside the interval", &persistence.MFANudgeState{DismissedAt: at(-mfaNudgeInterval + time.Hour), Count: 1}, false},
		{"declined just outside the interval", &persistence.MFANudgeState{DismissedAt: at(-mfaNudgeInterval - time.Hour), Count: 1}, true},
		{"declined long ago, many times", &persistence.MFANudgeState{DismissedAt: at(-365 * 24 * time.Hour), Count: 9}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mfaNudgeDue(c.state, now); got != c.want {
				t.Errorf("mfaNudgeDue = %v, want %v", got, c.want)
			}
		})
	}
}

// TestMFANudgeFragment guards the contract between the fragment and the
// handler. The form_state values are the only thing linking the two, so a
// renamed constant has to fail here rather than at somebody's login.
func TestMFANudgeFragment(t *testing.T) {
	b, err := assets.Fragments.ReadFile("authenticate/fragment/" + fragmentMFANudge + ".html")
	if err != nil {
		t.Fatalf("nudge fragment is not embedded: %v", err)
	}
	html := string(b)

	for _, want := range []string{
		`value="` + fragmentMFANudgeEnable + `"`,
		fragmentMFANudgeSkip,
		"Enable MFA",
		"Continue without enhanced security",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("fragment is missing %q", want)
		}
	}

	// The primary action must be the submit button and the decline a plain
	// link, not the other way round.
	if !strings.Contains(html, `class="button button-continue"`) {
		t.Error("Enable MFA should be the primary button")
	}
	if !strings.Contains(html, `class="password-reset-link"`) {
		t.Error("the decline should use the subdued link style")
	}
}
