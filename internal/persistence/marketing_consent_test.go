package persistence

import (
	"testing"

	"flomation.app/sentinel/internal/config"
	"github.com/google/uuid"
	. "github.com/onsi/gomega"
)

// TestMarketingConsentAsked covers the distinction the whole consent record
// exists to preserve: a user who declined and a user who was never asked both
// have OptIn false, and must not be reported as the same thing.
func TestMarketingConsentAsked(t *testing.T) {
	RegisterTestingT(t)

	Expect(MarketingConsent{}.Asked()).To(BeFalse())
	Expect(MarketingConsent{OptIn: true}.Asked()).To(BeFalse())
	Expect(MarketingConsent{Source: MarketingConsentSourceRegistrationForm}.Asked()).To(BeTrue())
	Expect(MarketingConsent{
		OptIn:  false,
		Source: MarketingConsentSourceRegistrationForm,
	}.Asked()).To(BeTrue())
}

func TestRegisterUserRecordsMarketingConsent(t *testing.T) {
	RegisterTestingT(t)

	dbConfig, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbConfig).To(Not(BeNil()))

	db, err := NewService(&config.Config{
		Database: *dbConfig,
	})
	Expect(err).To(BeNil())
	Expect(db).To(Not(BeNil()))

	t.Run("granted at sign-up", func(t *testing.T) {
		RegisterTestingT(t)

		u, err := db.RegisterUser(uuid.NewString(), UTMParameters{}, MarketingConsent{
			OptIn:   true,
			Source:  MarketingConsentSourceRegistrationForm,
			Version: MarketingConsentWordingSignupV1,
		})
		Expect(err).To(BeNil())
		Expect(u).To(Not(BeNil()))

		Expect(u.MarketingOptIn).To(BeTrue())
		Expect(u.MarketingConsentAt).To(Not(BeNil()))
		Expect(u.MarketingConsentSource).To(Not(BeNil()))
		Expect(*u.MarketingConsentSource).To(Equal(MarketingConsentSourceRegistrationForm))
		Expect(u.MarketingConsentVersion).To(Not(BeNil()))
		Expect(*u.MarketingConsentVersion).To(Equal(MarketingConsentWordingSignupV1))
	})

	t.Run("refused at sign-up is evidenced, not silent", func(t *testing.T) {
		RegisterTestingT(t)

		u, err := db.RegisterUser(uuid.NewString(), UTMParameters{}, MarketingConsent{
			OptIn:   false,
			Source:  MarketingConsentSourceRegistrationForm,
			Version: MarketingConsentWordingSignupV1,
		})
		Expect(err).To(BeNil())
		Expect(u).To(Not(BeNil()))

		// An unticked box is a decision. It is timestamped and attributed so it
		// is distinguishable from an account that was never asked.
		Expect(u.MarketingOptIn).To(BeFalse())
		Expect(u.MarketingConsentAt).To(Not(BeNil()))
		Expect(u.MarketingConsentSource).To(Not(BeNil()))
		Expect(*u.MarketingConsentSource).To(Equal(MarketingConsentSourceRegistrationForm))
	})

	t.Run("never asked leaves no consent evidence", func(t *testing.T) {
		RegisterTestingT(t)

		u, err := db.RegisterUser(uuid.NewString(), UTMParameters{}, MarketingConsent{})
		Expect(err).To(BeNil())
		Expect(u).To(Not(BeNil()))

		Expect(u.MarketingOptIn).To(BeFalse())
		Expect(u.MarketingConsentAt).To(BeNil())
		Expect(u.MarketingConsentSource).To(BeNil())
		Expect(u.MarketingConsentVersion).To(BeNil())
	})
}
