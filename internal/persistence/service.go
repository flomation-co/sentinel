package persistence

import (
	"encoding/json"
	"errors"
	"fmt"

	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/utils"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type Service struct {
	config *config.Config
	db     *sqlx.DB

	stmtGetConfiguration    *sqlx.NamedStmt
	stmtUpdateConfiguration *sqlx.NamedStmt
	stmtInsertConfiguration *sqlx.NamedStmt

	stmtDoesUserExist                *sqlx.NamedStmt
	stmtGetUserByUsername            *sqlx.NamedStmt
	stmtGetUserByID                  *sqlx.NamedStmt
	stmtGetUserByUsernameAndPassword *sqlx.NamedStmt
	stmtGetUserByVerificationToken   *sqlx.NamedStmt
	stmtInsertUser                   *sqlx.NamedStmt
	stmtUpdateUserPassword           *sqlx.NamedStmt
	stmtLockUser                     *sqlx.NamedStmt
	stmtUnlockUser                   *sqlx.NamedStmt
	stmtUpdateFailedAttempts         *sqlx.NamedStmt
	stmtResetFailedAttempts          *sqlx.NamedStmt
	stmtVerifyUser                   *sqlx.NamedStmt

	stmtInsertSession           *sqlx.NamedStmt
	stmtClearSession            *sqlx.NamedStmt
	stmtClearUserSessions       *sqlx.NamedStmt
	stmtUpdateSessionState      *sqlx.NamedStmt
	stmtUpdateSessionExpiration *sqlx.NamedStmt
	stmtUpdateSessionUserID     *sqlx.NamedStmt
	stmtGetSessionState         *sqlx.NamedStmt
	stmtGetSessionUserID        *sqlx.NamedStmt
	stmtGetSessionUsername      *sqlx.NamedStmt
	stmtGetSessionRedirectURL   *sqlx.NamedStmt
}

type baseConfiguration struct {
	InstanceID string `json:"instance_id"`
}

func NewService(config *config.Config) (*Service, error) {
	if config.Database.EncryptionKey == "" {
		return nil, errors.New("database encryption key not set")
	}

	s := Service{
		config: config,
	}

	connectionString := fmt.Sprintf("postgres://%v:%v@%v:%d/%v?sslmode=%v", config.Database.Username, config.Database.Password, config.Database.Hostname, config.Database.Port, config.Database.Database, config.Database.SSLModeOverride)
	conn, err := sqlx.Connect("postgres", connectionString)
	if err != nil {
		return nil, err
	}

	conn.SetMaxIdleConns(config.Database.MaxIdleConnections)
	conn.SetMaxOpenConns(config.Database.MaxOpenConnections)

	s.db = conn

	if err := s.configure(); err != nil {
		return nil, err
	}

	base, err := s.GetConfiguration("base")
	if err != nil {
		return nil, errors.New("invalid database encryption key")
	}

	if base == nil {
		c := baseConfiguration{
			InstanceID: utils.GenerateRandomString(64),
		}

		b, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}

		if err := s.InsertConfiguration("base", b); err != nil {
			return nil, err
		}
	}

	return &s, nil
}

func (s *Service) configure() error {
	var err error
	s.stmtGetConfiguration, err = s.db.PrepareNamed(`
		SELECT
		    PGP_SYM_DECRYPT(setting, :key) AS setting
		FROM
		    configuration
		WHERE
		    name = :name;
	`)
	if err != nil {
		return err
	}

	s.stmtInsertConfiguration, err = s.db.PrepareNamed(`
		INSERT INTO configuration (
		   name, 
		   setting
	   ) VALUES (
			:name, 
			PGP_SYM_ENCRYPT(:setting, :key)
		);
	`)
	if err != nil {
		return err
	}

	s.stmtUpdateConfiguration, err = s.db.PrepareNamed(`
		UPDATE 
		    configuration
		SET 
		    setting = PGP_SYM_ENCRYPT(:setting, :key)
		WHERE 
			name = :name
	`)
	if err != nil {
		return err
	}

	s.stmtDoesUserExist, err = s.db.PrepareNamed(`
		SELECT
		    COUNT(1)
		FROM
		    "user"
		WHERE
		    username_hash = DIGEST(LOWER(:username), 'sha256')
	`)
	if err != nil {
		return err
	}

	s.stmtGetUserByUsername, err = s.db.PrepareNamed(`
		SELECT
		    id,
		    PGP_SYM_DECRYPT(username, :key) AS username,
		    created_at,
		    locked,
		    failed_attempt
		FROM
		    "user"
		WHERE
		    username_hash = DIGEST(LOWER(:username), 'sha256')
	`)
	if err != nil {
		return err
	}

	s.stmtGetUserByID, err = s.db.PrepareNamed(`
		SELECT
		    id,
		    PGP_SYM_DECRYPT(username, :key) AS username,
		    created_at,
			verification_token,
		    locked,
		    failed_attempt
		FROM
		    "user"
		WHERE
		    id = :id
	`)
	if err != nil {
		return err
	}

	s.stmtGetUserByUsernameAndPassword, err = s.db.PrepareNamed(`
		SELECT
		    id,
		    PGP_SYM_DECRYPT(username, :key) AS username,
		    created_at,
		    locked,
		    failed_attempt
		FROM
		    "user"
		WHERE
		    username_hash = DIGEST(LOWER(:username), 'sha256')
		AND
		    PGP_SYM_DECRYPT(password, :key) = :password
		AND
		    locked = false
	`)
	if err != nil {
		return err
	}

	s.stmtGetUserByVerificationToken, err = s.db.PrepareNamed(`
		SELECT
		    id,
		    PGP_SYM_DECRYPT(username, :key) AS username,
		    created_at,
		    locked,
		    failed_attempt
		FROM
		    "user"
		WHERE
		    verification_token = :token
	`)
	if err != nil {
		return err
	}

	s.stmtInsertUser, err = s.db.PrepareNamed(`
		INSERT INTO "user" (
		    username,
		    username_hash
		) VALUES (
		    PGP_SYM_ENCRYPT(LOWER(:username), :key),
		  	DIGEST(LOWER(:username), 'sha256')
		) RETURNING id;
	`)
	if err != nil {
		return err
	}

	s.stmtUpdateUserPassword, err = s.db.PrepareNamed(`
		UPDATE
		    "user"
		SET
		    password = PGP_SYM_ENCRYPT(:password, :key)
		WHERE
		    id = :id
	`)
	if err != nil {
		return err
	}

	s.stmtLockUser, err = s.db.PrepareNamed(`
		UPDATE
		    "user"
		SET
			locked = true
		WHERE
		    id = :id
	`)
	if err != nil {
		return err
	}

	s.stmtUnlockUser, err = s.db.PrepareNamed(`
		UPDATE
		    "user"
		SET
			locked = false
		WHERE
		    id = :id
	`)
	if err != nil {
		return err
	}

	s.stmtUpdateFailedAttempts, err = s.db.PrepareNamed(`
		UPDATE
		    "user"
		SET
			failed_attempt = failed_attempt + 1
		WHERE
		    id = :id
	`)
	if err != nil {
		return err
	}

	s.stmtResetFailedAttempts, err = s.db.PrepareNamed(`
		UPDATE
		    "user"
		SET
			failed_attempt = 0
		WHERE
		    id = :id
	`)
	if err != nil {
		return err
	}

	s.stmtVerifyUser, err = s.db.PrepareNamed(`
		UPDATE
		    "user"
		SET
			verification_token = NULL
		WHERE
		    id = :id
	`)
	if err != nil {
		return err
	}

	s.stmtInsertSession, err = s.db.PrepareNamed(`
		INSERT INTO session (
		    user_id,
			ip_address,
		    location,
		    device,
		    metadata
		) VALUES (
		    :user_id,
			PGP_SYM_ENCRYPT(:ip_address, :key),
		    PGP_SYM_ENCRYPT(:location, :key),
		    PGP_SYM_ENCRYPT(:device, :key),
		    :metadata
		) RETURNING id;
	`)
	if err != nil {
		return err
	}

	s.stmtClearSession, err = s.db.PrepareNamed(`
		UPDATE 
		    session
		SET
		    state = 999
		WHERE
		    id = :id;
	`)
	if err != nil {
		return err
	}

	s.stmtClearUserSessions, err = s.db.PrepareNamed(`
		UPDATE 
		    session
		SET
		    state = 999
		WHERE
		    user_id = :user_id;
	`)
	if err != nil {
		return err
	}

	s.stmtUpdateSessionState, err = s.db.PrepareNamed(`
		UPDATE 
		    session
		SET
		    state = :state
		WHERE
		    id = :id;
	`)
	if err != nil {
		return err
	}

	s.stmtUpdateSessionExpiration, err = s.db.PrepareNamed(`
		UPDATE 
		    session
		SET
		    expiration = :expiration
		WHERE
		    id = :id;
	`)
	if err != nil {
		return err
	}

	s.stmtUpdateSessionUserID, err = s.db.PrepareNamed(`
		UPDATE 
		    session
		SET
		    user_id = :user_id
		WHERE
		    id = :id;
	`)
	if err != nil {
		return err
	}

	s.stmtGetSessionState, err = s.db.PrepareNamed(`
		SELECT	
		    state
		FROM
		    session
		WHERE
		    id = :id;
	`)
	if err != nil {
		return err
	}

	s.stmtGetSessionUserID, err = s.db.PrepareNamed(`
		SELECT	
		    user_id
		FROM
		    session
		WHERE
		    id = :id;
	`)
	if err != nil {
		return err
	}

	s.stmtGetSessionUsername, err = s.db.PrepareNamed(`
		SELECT	
		    PGP_SYM_DECRYPT(u.username, :key) AS username
		FROM
		    session s
		INNER JOIN
		    "user" u
		ON
			s.user_id = u.id
		WHERE
		    s.id = :id;
	`)
	if err != nil {
		return err
	}

	s.stmtGetSessionRedirectURL, err = s.db.PrepareNamed(`
		SELECT	
		    metadata->>'redirect_url'
		FROM
		    session s
		WHERE
		    s.id = :id;
	`)
	if err != nil {
		return err
	}

	return nil
}
