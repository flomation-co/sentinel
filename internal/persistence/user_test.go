package persistence

import (
	"testing"

	"flomation.app/sentinel/internal/config"
	"github.com/google/uuid"
	. "github.com/onsi/gomega"
)

func TestUserExists(t *testing.T) {
	RegisterTestingT(t)

	dbConfig, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbConfig).To(Not(BeNil()))

	db, err := NewService(&config.Config{
		Database: *dbConfig,
	})
	Expect(err).To(BeNil())
	Expect(db).To(Not(BeNil()))

	username := uuid.NewString()
	password := uuid.NewString()

	u, err := db.RegisterUser(username, password)
	Expect(err).To(BeNil())
	Expect(u).To(Not(BeNil()))

	Expect(u.Username).To(Equal(username))
	Expect(u.Locked).To(BeFalse())
	Expect(u.FailedAttempts).To(Equal(int64(0)))

	exists, err := db.UserExists(username)
	Expect(err).To(BeNil())
	Expect(exists).To(BeTrue())

	exists, err = db.UserExists("missing-user")
	Expect(err).To(BeNil())
	Expect(exists).To(BeFalse())
}

func TestRegisterExistingUser(t *testing.T) {
	RegisterTestingT(t)

	dbConfig, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbConfig).To(Not(BeNil()))

	db, err := NewService(&config.Config{
		Database: *dbConfig,
	})
	Expect(err).To(BeNil())
	Expect(db).To(Not(BeNil()))

	username := uuid.NewString()
	password := uuid.NewString()

	u, err := db.RegisterUser(username, password)
	Expect(err).To(BeNil())
	Expect(u).To(Not(BeNil()))

	Expect(u.Username).To(Equal(username))
	Expect(u.Locked).To(BeFalse())
	Expect(u.FailedAttempts).To(Equal(int64(0)))

	exists, err := db.UserExists(username)
	Expect(err).To(BeNil())
	Expect(exists).To(BeTrue())

	u, err = db.RegisterUser(username, password)
	Expect(err).To(Not(BeNil()))
	Expect(u).To(BeNil())
}

func TestGetByUsername(t *testing.T) {
	RegisterTestingT(t)

	dbConfig, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbConfig).To(Not(BeNil()))

	db, err := NewService(&config.Config{
		Database: *dbConfig,
	})
	Expect(err).To(BeNil())
	Expect(db).To(Not(BeNil()))

	username := uuid.NewString()
	password := uuid.NewString()

	u, err := db.RegisterUser(username, password)
	Expect(err).To(BeNil())
	Expect(u).To(Not(BeNil()))

	Expect(u.Username).To(Equal(username))
	Expect(u.Locked).To(BeFalse())
	Expect(u.FailedAttempts).To(Equal(int64(0)))

	existingUser, err := db.GetUserByUsername(username)
	Expect(err).To(BeNil())
	Expect(existingUser).To(Not(BeNil()))
	Expect(existingUser.ID).To(Equal(u.ID))
	Expect(existingUser.Username).To(Equal(username))

	missingUser, err := db.GetUserByUsername("missing-user")
	Expect(err).To(BeNil())
	Expect(missingUser).To(BeNil())
}

func TestGetByUserID(t *testing.T) {
	RegisterTestingT(t)

	dbConfig, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbConfig).To(Not(BeNil()))

	db, err := NewService(&config.Config{
		Database: *dbConfig,
	})
	Expect(err).To(BeNil())
	Expect(db).To(Not(BeNil()))

	username := uuid.NewString()
	password := uuid.NewString()

	u, err := db.RegisterUser(username, password)
	Expect(err).To(BeNil())
	Expect(u).To(Not(BeNil()))

	Expect(u.Username).To(Equal(username))
	Expect(u.Locked).To(BeFalse())
	Expect(u.FailedAttempts).To(Equal(int64(0)))

	existingUser, err := db.GetUserByID(u.ID)
	Expect(err).To(BeNil())
	Expect(existingUser).To(Not(BeNil()))
	Expect(existingUser.ID).To(Equal(u.ID))
	Expect(existingUser.Username).To(Equal(username))

	missingUser, err := db.GetUserByID(uuid.NewString())
	Expect(err).To(BeNil())
	Expect(missingUser).To(BeNil())
}

func TestGetByUserAndPassword(t *testing.T) {
	RegisterTestingT(t)

	dbConfig, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbConfig).To(Not(BeNil()))

	db, err := NewService(&config.Config{
		Database: *dbConfig,
	})
	Expect(err).To(BeNil())
	Expect(db).To(Not(BeNil()))

	username := uuid.NewString()
	password := uuid.NewString()

	u, err := db.RegisterUser(username, password)
	Expect(err).To(BeNil())
	Expect(u).To(Not(BeNil()))

	Expect(u.Username).To(Equal(username))
	Expect(u.Locked).To(BeFalse())
	Expect(u.FailedAttempts).To(Equal(int64(0)))

	existingUser, err := db.GetUserByUsernameAndPassword(username, password)
	Expect(err).To(BeNil())
	Expect(existingUser).To(Not(BeNil()))
	Expect(existingUser.ID).To(Equal(u.ID))
	Expect(existingUser.Username).To(Equal(username))

	missingUser, err := db.GetUserByUsernameAndPassword(username, "bad-password")
	Expect(err).To(BeNil())
	Expect(missingUser).To(BeNil())
}

func TestPasswordReset(t *testing.T) {
	RegisterTestingT(t)

	dbConfig, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbConfig).To(Not(BeNil()))

	db, err := NewService(&config.Config{
		Database: *dbConfig,
	})
	Expect(err).To(BeNil())
	Expect(db).To(Not(BeNil()))

	username := uuid.NewString()
	password := uuid.NewString()

	u, err := db.RegisterUser(username, password)
	Expect(err).To(BeNil())
	Expect(u).To(Not(BeNil()))

	Expect(u.Username).To(Equal(username))
	Expect(u.Locked).To(BeFalse())
	Expect(u.FailedAttempts).To(Equal(int64(0)))

	newPassword := uuid.NewString()
	err = db.UpdatePassword(u.ID, newPassword)
	Expect(err).To(BeNil())

	badPasswordUser, err := db.GetUserByUsernameAndPassword(username, password)
	Expect(err).To(BeNil())
	Expect(badPasswordUser).To(BeNil())

	existingUser, err := db.GetUserByUsernameAndPassword(username, newPassword)
	Expect(err).To(BeNil())
	Expect(existingUser).To(Not(BeNil()))
	Expect(existingUser.ID).To(Equal(u.ID))
	Expect(existingUser.Username).To(Equal(username))
}

func TestLockUser(t *testing.T) {
	RegisterTestingT(t)

	dbConfig, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbConfig).To(Not(BeNil()))

	db, err := NewService(&config.Config{
		Database: *dbConfig,
	})
	Expect(err).To(BeNil())
	Expect(db).To(Not(BeNil()))

	username := uuid.NewString()
	password := uuid.NewString()

	u, err := db.RegisterUser(username, password)
	Expect(err).To(BeNil())
	Expect(u).To(Not(BeNil()))

	Expect(u.Username).To(Equal(username))
	Expect(u.Locked).To(BeFalse())
	Expect(u.FailedAttempts).To(Equal(int64(0)))

	err = db.LockUser(u.ID)
	Expect(err).To(BeNil())

	u, err = db.GetUserByID(u.ID)
	Expect(err).To(BeNil())
	Expect(u.Locked).To(BeTrue())

	err = db.UnlockUser(u.ID)
	Expect(err).To(BeNil())

	u, err = db.GetUserByID(u.ID)
	Expect(err).To(BeNil())
	Expect(u.Locked).To(BeFalse())
}

func TestUserFailedAttempts(t *testing.T) {
	RegisterTestingT(t)

	dbConfig, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbConfig).To(Not(BeNil()))

	db, err := NewService(&config.Config{
		Database: *dbConfig,
	})
	Expect(err).To(BeNil())
	Expect(db).To(Not(BeNil()))

	username := uuid.NewString()
	password := uuid.NewString()

	u, err := db.RegisterUser(username, password)
	Expect(err).To(BeNil())
	Expect(u).To(Not(BeNil()))

	Expect(u.Username).To(Equal(username))
	Expect(u.Locked).To(BeFalse())
	Expect(u.FailedAttempts).To(Equal(int64(0)))

	err = db.UpdateFailedAttempts(u.ID)
	Expect(err).To(BeNil())

	u, err = db.GetUserByID(u.ID)
	Expect(err).To(BeNil())
	Expect(u.FailedAttempts).To(Equal(int64(1)))

	err = db.ResetFailedAttempts(u.ID)
	Expect(err).To(BeNil())

	u, err = db.GetUserByID(u.ID)
	Expect(err).To(BeNil())
	Expect(u.FailedAttempts).To(BeZero())
}
