package persistence

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"flomation.app/sentinel/internal/config"
	"github.com/google/uuid"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

//func setupLocal(t *testing.T) (*config.DatabaseConfig, error) {
//	cfg := config.DatabaseConfig{
//		Hostname:        "localhost",
//		Port:            int(5434),
//		Username:        "postgres",
//		Password:        "Password1234",
//		Database:        "postgres",
//		SSLModeOverride: "disable",
//		EncryptionKey:   "Test1234!",
//	}
//
//	if err := CheckAndUpdate(&config.Config{
//		Database: cfg,
//	}); err != nil {
//		return nil, err
//	}
//
//	return &cfg, nil
//}

func setupContainer(t *testing.T) (*config.DatabaseConfig, error) {
	ctx := context.Background()

	const (
		DBName = "postgres"
		DBUser = "admin"
		DBPass = "admin"
	)

	pgContainer, err := postgres.Run(ctx,
		"postgres:latest",
		postgres.WithDatabase(DBName),
		postgres.WithUsername(DBUser),
		postgres.WithPassword(DBPass),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(5*time.Second)))
	if err != nil {
		return nil, err
	}

	t.Cleanup(func() {
		if err = pgContainer.Terminate(ctx); err != nil {
			t.Fatal(err)
		}
	})

	str, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, err
	}

	port, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(str, "postgres://admin:admin@localhost:"), "/postgres?sslmode=disable"), 10, 64)
	if err != nil {
		return nil, err
	}

	cfg := config.DatabaseConfig{
		Hostname:        "localhost",
		Port:            int(port),
		Username:        DBUser,
		Password:        DBPass,
		Database:        DBName,
		SSLModeOverride: "disable",
		EncryptionKey:   uuid.NewString(),
	}

	if err := CheckAndUpdate(&config.Config{
		Database: cfg,
	}); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func TestMissingEncryptionKey(t *testing.T) {
	RegisterTestingT(t)

	dbCfg, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbCfg).To(Not(BeNil()))

	dbCfg.EncryptionKey = ""

	db, err := NewService(&config.Config{
		Database: *dbCfg,
	})
	Expect(err).To(Not(BeNil()))
	Expect(db).To(BeNil())
}

func TestInvalidEncryptionKey(t *testing.T) {
	RegisterTestingT(t)

	dbCfg, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbCfg).To(Not(BeNil()))

	db, err := NewService(&config.Config{
		Database: *dbCfg,
	})
	Expect(err).To(BeNil())
	Expect(db).To(Not(BeNil()))

	dbCfg.EncryptionKey = uuid.NewString()

	newDb, err := NewService(&config.Config{
		Database: *dbCfg,
	})
	Expect(err).To(Not(BeNil()))
	Expect(newDb).To(BeNil())
}

func TestMissingDatabaseCredentials(t *testing.T) {
	RegisterTestingT(t)

	db, err := NewService(&config.Config{
		Database: config.DatabaseConfig{
			EncryptionKey: uuid.NewString(),
		},
	})
	Expect(err).To(Not(BeNil()))
	Expect(db).To(BeNil())
}
