package persistence

import (
	"testing"

	"flomation.app/sentinel/internal/config"
	"github.com/google/uuid"
	. "github.com/onsi/gomega"
)

// TestRegisterUserPersistsUTMParameters verifies that the UTM attribution
// passed to RegisterUser lands on the underlying user row. We round-trip it
// via the raw SQL columns rather than a getter because the User struct
// intentionally doesn't expose UTM — they're attribution data for reports,
// not data the auth flow ever needs to read back at request time.
func TestRegisterUserPersistsUTMParameters(t *testing.T) {
	RegisterTestingT(t)

	dbCfg, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbCfg).To(Not(BeNil()))

	db, err := NewService(&config.Config{Database: *dbCfg})
	Expect(err).To(BeNil())

	utm := UTMParameters{
		Source:   "newsletter",
		Medium:   "email",
		Campaign: "spring-launch",
		Term:     "automation",
		Content:  "hero-cta",
		Referrer: "https://blog.flomation.co/post",
	}

	u, err := db.RegisterUser(uuid.NewString(), utm)
	Expect(err).To(BeNil())
	Expect(u).To(Not(BeNil()))

	var got UTMParameters
	err = db.db.Get(&got,
		`SELECT utm_source, utm_medium, utm_campaign, utm_term, utm_content, utm_referrer FROM "user" WHERE id = $1`,
		u.ID,
	)
	Expect(err).To(BeNil())
	Expect(got).To(Equal(utm))
}

// TestRegisterUserEmptyUTMStoredAsNull confirms that an empty UTMParameters
// struct round-trips as NULL columns. Empty strings would silently corrupt
// downstream attribution reports — "no campaign" must be distinguishable
// from a campaign called "".
func TestRegisterUserEmptyUTMStoredAsNull(t *testing.T) {
	RegisterTestingT(t)

	dbCfg, err := setupContainer(t)
	Expect(err).To(BeNil())

	db, err := NewService(&config.Config{Database: *dbCfg})
	Expect(err).To(BeNil())

	u, err := db.RegisterUser(uuid.NewString(), UTMParameters{})
	Expect(err).To(BeNil())

	var nulls [6]bool
	err = db.db.QueryRowx(
		`SELECT
			utm_source     IS NULL,
			utm_medium     IS NULL,
			utm_campaign   IS NULL,
			utm_term       IS NULL,
			utm_content    IS NULL,
			utm_referrer   IS NULL
		FROM "user" WHERE id = $1`, u.ID,
	).Scan(&nulls[0], &nulls[1], &nulls[2], &nulls[3], &nulls[4], &nulls[5])
	Expect(err).To(BeNil())
	for i, isNull := range nulls {
		Expect(isNull).To(BeTrue(), "column %d should be NULL when no UTM provided", i)
	}
}

// TestCreateSSOAccountPersistsUTMParameters covers the per-link attribution
// path: an SSO account row records the UTM that drove that specific link,
// independent of the user account's original sign-up attribution.
func TestCreateSSOAccountPersistsUTMParameters(t *testing.T) {
	RegisterTestingT(t)

	dbCfg, err := setupContainer(t)
	Expect(err).To(BeNil())

	db, err := NewService(&config.Config{Database: *dbCfg})
	Expect(err).To(BeNil())

	u, err := db.RegisterUser(uuid.NewString(), UTMParameters{})
	Expect(err).To(BeNil())

	utm := UTMParameters{
		Source:   "linkedin",
		Medium:   "social",
		Campaign: "growth-q3",
	}
	provider := "google"
	providerUserID := uuid.NewString()

	err = db.CreateSSOAccount(u.ID, provider, providerUserID, "u@example.com", utm)
	Expect(err).To(BeNil())

	var got UTMParameters
	err = db.db.Get(&got,
		`SELECT
			COALESCE(utm_source, '')   AS utm_source,
			COALESCE(utm_medium, '')   AS utm_medium,
			COALESCE(utm_campaign, '') AS utm_campaign,
			COALESCE(utm_term, '')     AS utm_term,
			COALESCE(utm_content, '')  AS utm_content,
			COALESCE(utm_referrer, '') AS utm_referrer
		FROM sso_account
		WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	)
	Expect(err).To(BeNil())
	Expect(got).To(Equal(utm))
}
