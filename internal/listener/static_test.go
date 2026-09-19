package listener

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"flomation.app/sentinel/internal/assets"
	"github.com/gin-gonic/gin"
)

// serveAsset runs one request through the real handler.
func serveAsset(t *testing.T, path, ifNoneMatch string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	c.Request = req

	(&Service{}).staticAssets(c)
	return rec
}

/*
A changed asset has to reach people who already hold the old one.

These URLs carry no content hash, so a far-future max-age is a promise the
bytes will not change, and that promise is false every deploy. A day-long
max-age here left a corrected image sitting behind a stale copy in an already
warmed browser cache.
*/
func TestStaticAssetsRevalidateRatherThanExpire(t *testing.T) {
	rec := serveAsset(t, "/assets/images/key-art-security.jpg", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}

	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-cache") {
		t.Errorf("Cache-Control is %q; it must ask the browser to revalidate", cc)
	}
	// The specific hazard: any max-age above zero lets a stale asset survive a
	// deploy for that long.
	if strings.Contains(cc, "max-age") && !strings.Contains(cc, "max-age=0") {
		t.Errorf("Cache-Control is %q; a non-zero max-age on an unversioned URL "+
			"hides a changed asset until it lapses", cc)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("no ETag, so a revalidation request has nothing to compare and " +
			"every load refetches the whole body")
	}
}

// The point of the ETag is the cheap second request.
func TestStaticAssetsReturn304WhenUnchanged(t *testing.T) {
	first := serveAsset(t, "/assets/images/flomation-wordmark-ink.png", "")
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the first response")
	}

	second := serveAsset(t, "/assets/images/flomation-wordmark-ink.png", etag)
	if second.Code != http.StatusNotModified {
		t.Errorf("status %d with a matching If-None-Match, want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Errorf("304 carried %d bytes of body", second.Body.Len())
	}

	// A stale validator must not be honoured, or we are back where we started.
	stale := serveAsset(t, "/assets/images/flomation-wordmark-ink.png", `"0000000000000000"`)
	if stale.Code != http.StatusOK {
		t.Errorf("status %d for a stale ETag, want 200 with the new bytes", stale.Code)
	}
}

// Distinct assets must not share a validator, or one would be served in place
// of another after a revalidation.
func TestStaticAssetETagsFollowContent(t *testing.T) {
	a := serveAsset(t, "/assets/images/key-art-security.jpg", "").Header().Get("ETag")
	b := serveAsset(t, "/assets/images/flomation-wordmark-ink.png", "").Header().Get("ETag")

	if a == "" || b == "" {
		t.Fatal("missing ETag")
	}
	if a == b {
		t.Errorf("two different assets share the ETag %s", a)
	}

	// And the digest must be of the bytes, not of the path: same file, same tag.
	again := serveAsset(t, "/assets/images/key-art-security.jpg", "").Header().Get("ETag")
	if again != a {
		t.Errorf("the same asset produced %s then %s", a, again)
	}
}

func TestMatchesETag(t *testing.T) {
	const tag = `"abc123"`

	for _, c := range []struct {
		header string
		want   bool
	}{
		{"", false},
		{tag, true},
		{`W/` + tag, true},        // weak validator, same bytes
		{`"other", ` + tag, true}, // list
		{`"other"`, false},
		{"*", true},
		{`"abc"`, false}, // prefix must not match
	} {
		if got := matchesETag(c.header, tag); got != c.want {
			t.Errorf("matchesETag(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}

// Guard the embedded FS is what is being read, not the working directory.
func TestStaticAssetsServeFromTheEmbeddedFS(t *testing.T) {
	want, err := assets.Static.ReadFile("static/images/favicon.svg")
	if err != nil {
		t.Fatalf("embedded read: %v", err)
	}
	rec := serveAsset(t, "/assets/images/favicon.svg", "")
	if rec.Body.String() != string(want) {
		t.Error("served bytes differ from the embedded asset")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("Content-Type %q; a browser will not paint an <img> that is not image/svg+xml", ct)
	}
}
