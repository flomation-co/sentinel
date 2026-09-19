package listener

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"flomation.app/sentinel/internal/assets"
)

/*
The sign-in pages are hand-written HTML with an inline stylesheet, so the only
thing that normally notices a mistake in them is a person looking at a browser.
These cover the four that got through that way.

They read the embedded assets, which is what actually ships, rather than the
files on disk.
*/

// templates returns every embedded HTML file, keyed by its path.
func templates(t *testing.T) map[string]string {
	t.Helper()

	out := map[string]string{}
	for _, src := range []struct {
		fs   interface{ ReadFile(string) ([]byte, error) }
		dirs []string
	}{
		{assets.Fragments, []string{"authenticate/default", "authenticate/fragment"}},
		{assets.Passkey, []string{"passkey"}},
	} {
		for _, dir := range src.dirs {
			entries, err := os.ReadDir(filepath.Join("../assets", dir))
			if err != nil {
				t.Fatalf("read %s: %v", dir, err)
			}
			for _, e := range entries {
				if !strings.HasSuffix(e.Name(), ".html") {
					continue
				}
				name := dir + "/" + e.Name()
				b, err := src.fs.ReadFile(name)
				if err != nil {
					t.Fatalf("embedded read %s: %v", name, err)
				}
				out[name] = string(b)
			}
		}
	}

	if len(out) == 0 {
		t.Fatal("no templates found; this test is not looking where it thinks it is")
	}
	return out
}

var assetRef = regexp.MustCompile(`["(]/assets/([^"')\s]+)`)

// Every /assets/ URL in a template must resolve to a file that is actually
// embedded.
//
// The passkey management page asked for flomation-wordtype-white.png, which has
// never existed in the repository. An onerror handler hid the broken image, so
// the page simply had no logo on it and nothing ever said so.
func TestTemplateAssetsExist(t *testing.T) {
	for name, body := range templates(t) {
		for _, m := range assetRef.FindAllStringSubmatch(body, -1) {
			ref := m[1]
			if _, err := assets.Static.ReadFile("static/" + ref); err != nil {
				t.Errorf("%s references /assets/%s, which is not embedded", name, ref)
			}
		}
	}
}

var cssComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

var submitInput = regexp.MustCompile(`(?s)<input[^>]*type="(?:submit|button)"[^>]*>`)

// The stylesheet's base button rule is matched on the .button class alone, so a
// submit input without it renders as a browser default control.
func TestEveryButtonInputCarriesTheButtonClass(t *testing.T) {
	sources := templates(t)

	// The MFA settings screens build their markup in Go rather than as
	// fragments, so they are held to the same rule from here.
	mfa, err := os.ReadFile("mfa.go")
	if err != nil {
		t.Fatalf("read mfa.go: %v", err)
	}
	sources["internal/listener/mfa.go"] = string(mfa)

	found := 0
	for name, body := range sources {
		for _, tag := range submitInput.FindAllString(body, -1) {
			found++
			if !strings.Contains(tag, `class="button `) && !strings.Contains(tag, `class="button"`) {
				t.Errorf("%s has a submit/button input with no .button class:\n  %s", name, tag)
			}
		}
	}
	if found == 0 {
		t.Fatal("matched no submit inputs at all; the pattern has stopped working")
	}
}

// The base button rule must stay class-only.
//
// An `input[type="submit"]` selector alongside `.button` outranks a bare
// `.button-danger`, so the base `border: 0` won and the Disable MFA control
// rendered as floating red text with no outline. Adding the element selectors
// back would silently break every button modifier the same way.
func TestBaseButtonRuleHasNoElementSelector(t *testing.T) {
	header, err := assets.Fragments.ReadFile("authenticate/default/header.html")
	if err != nil {
		t.Fatalf("read header: %v", err)
	}

	css := string(header)
	start := strings.Index(css, "\n        .button {")
	if start < 0 {
		t.Fatal("could not find the base .button rule; this test needs updating")
	}
	// Everything between the previous rule's close and this rule's brace is the
	// selector list, minus any comment -- the comment above this very rule
	// explains the trap by naming the selector, and would otherwise trip it.
	prefix := css[strings.LastIndex(css[:start], "}")+1 : start+len("\n        .button {")]
	prefix = cssComment.ReplaceAllString(prefix, "")
	if strings.Contains(prefix, "input[") {
		t.Errorf("the base .button rule has regained an element selector, which "+
			"outranks .button-danger and .button-back:\n%s", strings.TrimSpace(prefix))
	}
}

// The pages are light now. A colour literal written for the old dark scheme is
// invisible on paper, and an inline style cannot be reached by the palette to
// be corrected.
//
// The passkey prompt carried three: the status line, the error line and the
// fallback link were all near-white text on a near-white card.
func TestFragmentsCarryNoDarkSchemeColours(t *testing.T) {
	// Matches white-ish and the old accent teal in rgb()/rgba() form.
	dark := regexp.MustCompile(`rgba?\(\s*255\s*,\s*255\s*,\s*255|rgba?\(\s*0\s*,\s*170\s*,\s*156`)

	for name, body := range templates(t) {
		if strings.HasSuffix(name, "default/header.html") {
			// The stylesheet itself is allowed colour literals; that is what it
			// is for.
			continue
		}
		if loc := dark.FindString(body); loc != "" {
			t.Errorf("%s contains the dark-scheme colour %q; use a palette variable "+
				"or a class in the header stylesheet", name, loc)
		}
	}
}

var (
	classAttr     = regexp.MustCompile(`class="([^"]*)"`)
	cssClassNames = regexp.MustCompile(`\.([A-Za-z_][\w-]*)`)
)

// jsOnlyClasses are referenced by scripts rather than by the stylesheet, so
// they are expected to have no rule of their own.
var jsOnlyClasses = map[string]bool{
	"password-input": true, // togglePasswordVisibility finds the input by it
	"input_bg":       true, // legacy hook, styled only for the cursor
}

// Every class a template uses must have a rule in the header stylesheet.
//
// The stylesheet is one big block, so a rewrite can drop a rule without
// anything failing: the class stays in the fragment, the selector no longer
// matches, and the element quietly falls back to browser defaults. That is how
// the registration consent row lost its styling and became a bare checkbox.
func TestEveryTemplateClassIsStyled(t *testing.T) {
	header, err := assets.Fragments.ReadFile("authenticate/default/header.html")
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	css := string(header)
	css = css[strings.Index(css, "<style>"):strings.Index(css, "</style>")]
	css = cssComment.ReplaceAllString(css, "")

	styled := map[string]bool{}
	for _, m := range cssClassNames.FindAllStringSubmatch(css, -1) {
		styled[m[1]] = true
	}

	for name, body := range templates(t) {
		// The passkey page and the header carry their own stylesheets.
		if strings.HasPrefix(name, "passkey/") || strings.HasSuffix(name, "default/header.html") {
			continue
		}
		for _, m := range classAttr.FindAllStringSubmatch(body, -1) {
			for _, class := range strings.Fields(m[1]) {
				if styled[class] || jsOnlyClasses[class] {
					continue
				}
				t.Errorf("%s uses class %q, which no rule in the header stylesheet matches", name, class)
			}
		}
	}
}
