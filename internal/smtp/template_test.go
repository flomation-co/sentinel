package smtp

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"

	"flomation.app/sentinel/internal/assets"
)

// render exercises the real email template with the same data shape
// SendTemplatedEmail passes, without needing an SMTP server.
func render(t *testing.T, message string, details []EmailDetail) string {
	t.Helper()

	b, err := assets.Email.ReadFile("email/default_template.html")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	tmpl, err := template.New("main").Parse(string(b))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct {
		Header          string
		Message         string
		Details         []EmailDetail
		ButtonText      string
		ButtonURL       string
		TransactionID   string
		TransactionTime string
	}{
		Header:          "Header",
		Message:         message,
		Details:         details,
		ButtonText:      "Button",
		ButtonURL:       "https://example.invalid/",
		TransactionID:   "test",
		TransactionTime: time.Now().Format(time.RFC1123),
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	return buf.String()
}

/*
Nothing a caller passes may reach the reader as markup.

The new-device notification used to build a string of HTML with the request's
User-Agent inside it, and the template rendered that unescaped through a "safe"
function. A User-Agent is whatever the client sends, so anyone able to log in as
a user could write arbitrary HTML into the very email warning that user their
account had been signed into -- in a message genuinely from us, passing our SPF
and DKIM, which is exactly the sort of mail a person trusts.
*/
func TestTemplateEscapesEverythingACallerSupplies(t *testing.T) {
	const attack = `<a href="https://phish.invalid/">Secure your account</a>`

	for _, c := range []struct {
		name    string
		message string
		details []EmailDetail
	}{
		{"in the message", attack, nil},
		{"in a detail value", "ok", []EmailDetail{{Label: "Device", Value: attack}}},
		{"in a detail label", "ok", []EmailDetail{{Label: attack, Value: "ok"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := render(t, c.message, c.details)

			if strings.Contains(out, attack) {
				t.Error("the payload reached the email as live markup")
			}
			if strings.Contains(out, "phish.invalid/\">") {
				t.Error("an anchor tag survived")
			}
			// It must still be readable -- escaped, not dropped.
			if !strings.Contains(out, "&lt;a href=") {
				t.Error("the payload was not rendered in escaped form at all")
			}
		})
	}
}

// The details block is what callers use instead of markup, so it has to
// actually render.
func TestTemplateRendersDetails(t *testing.T) {
	out := render(t, "A sign-in was detected.", []EmailDetail{
		{Label: "IP Address", Value: "203.0.113.7"},
		{Label: "Device", Value: "Mozilla/5.0"},
	})

	for _, want := range []string{"IP Address", "203.0.113.7", "Device", "Mozilla/5.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing from the rendered email", want)
		}
	}
	// The labels are meant to read as labels.
	if !strings.Contains(out, "<strong>IP Address</strong>") {
		t.Error("detail labels are not emphasised")
	}
}

// With no details the block must not leave an empty table behind.
func TestTemplateOmitsTheDetailsBlockWhenThereAreNone(t *testing.T) {
	out := render(t, "Nothing to show here.", nil)

	if strings.Contains(out, "<strong></strong>") {
		t.Error("an empty detail row was rendered")
	}
	if !strings.Contains(out, "Nothing to show here.") {
		t.Error("the message is missing")
	}
}
