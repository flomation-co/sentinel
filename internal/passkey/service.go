// Package passkey wraps the go-webauthn library for passkey registration and authentication.
package passkey

import (
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/persistence"
)

// Service provides WebAuthn registration and authentication operations.
type Service struct {
	wa *webauthn.WebAuthn
	db *persistence.Service
}

// New creates a WebAuthn service from the application config.
func New(cfg *config.WebAuthnConfig, db *persistence.Service) (*Service, error) {
	if cfg == nil {
		return nil, fmt.Errorf("webauthn config is nil")
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("initialise webauthn: %w", err)
	}

	return &Service{wa: wa, db: db}, nil
}

// BeginRegistration starts the passkey registration ceremony for a user.
func (s *Service) BeginRegistration(user *persistence.User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	u := newWebAuthnUser(user, nil)

	// Exclude existing credentials to prevent re-registration.
	existing, _ := s.db.GetWebAuthnCredentialsByUserID(user.ID)
	u.credentials = toWebAuthnCredentials(existing)

	opts, session, err := s.wa.BeginRegistration(u,
		webauthn.WithExclusions(u.credentialDescriptors()),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("begin registration: %w", err)
	}

	return opts, session, nil
}

// FinishRegistration completes the passkey registration ceremony and returns the new credential.
func (s *Service) FinishRegistration(user *persistence.User, session webauthn.SessionData, r *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	u := newWebAuthnUser(user, nil)

	cred, err := s.wa.CreateCredential(u, session, r)
	if err != nil {
		return nil, fmt.Errorf("create credential: %w", err)
	}

	return cred, nil
}

// BeginLogin starts the passkey authentication ceremony.
func (s *Service) BeginLogin(user *persistence.User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	creds, err := s.db.GetWebAuthnCredentialsByUserID(user.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("load credentials: %w", err)
	}

	u := newWebAuthnUser(user, toWebAuthnCredentials(creds))

	opts, session, err := s.wa.BeginLogin(u,
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("begin login: %w", err)
	}

	return opts, session, nil
}

// FinishLogin completes the passkey authentication ceremony.
func (s *Service) FinishLogin(user *persistence.User, session webauthn.SessionData, r *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	creds, err := s.db.GetWebAuthnCredentialsByUserID(user.ID)
	if err != nil {
		return nil, fmt.Errorf("load credentials: %w", err)
	}

	u := newWebAuthnUser(user, toWebAuthnCredentials(creds))

	cred, err := s.wa.ValidateLogin(u, session, r)
	if err != nil {
		return nil, fmt.Errorf("validate login: %w", err)
	}

	// Update sign count.
	_ = s.db.UpdateWebAuthnSignCount(cred.ID, cred.Authenticator.SignCount)

	return cred, nil
}

// ── webauthn.User interface adapter ──────────────────────────────────

type webAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func newWebAuthnUser(u *persistence.User, creds []webauthn.Credential) *webAuthnUser {
	displayName := u.Username
	if u.DisplayName != nil && *u.DisplayName != "" {
		displayName = *u.DisplayName
	}
	return &webAuthnUser{
		id:          []byte(u.ID),
		name:        u.Username,
		displayName: displayName,
		credentials: creds,
	}
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webAuthnUser) WebAuthnName() string                       { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (u *webAuthnUser) credentialDescriptors() []protocol.CredentialDescriptor {
	var descs []protocol.CredentialDescriptor
	for _, c := range u.credentials {
		descs = append(descs, protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    c.ID,
			Transport:       c.Transport,
		})
	}
	return descs
}

// ── Credential conversion helpers ────────────────────────────────────

func toWebAuthnCredentials(dbCreds []persistence.WebAuthnCredential) []webauthn.Credential {
	var creds []webauthn.Credential
	for _, dc := range dbCreds {
		cred := webauthn.Credential{
			ID:              dc.CredentialID,
			PublicKey:       dc.PublicKey,
			AttestationType: "",
			Authenticator: webauthn.Authenticator{
				AAGUID:    dc.AAGUID,
				SignCount: dc.SignCount,
			},
			Flags: webauthn.CredentialFlags{
				BackupEligible: dc.BackupEligible,
				BackupState:    dc.BackupState,
			},
		}
		if dc.Transports != nil {
			for _, t := range strings.Split(*dc.Transports, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					cred.Transport = append(cred.Transport, protocol.AuthenticatorTransport(t))
				}
			}
		}
		creds = append(creds, cred)
	}
	return creds
}

// TransportsToString converts transport slice to comma-separated string for storage.
func TransportsToString(transports []protocol.AuthenticatorTransport) *string {
	if len(transports) == 0 {
		return nil
	}
	var parts []string
	for _, t := range transports {
		parts = append(parts, string(t))
	}
	s := strings.Join(parts, ",")
	return &s
}