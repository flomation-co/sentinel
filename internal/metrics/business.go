package metrics

import (
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
)

// ── Counters (incremented inline by handlers) ────────────────────────

// LoginsTotal is incremented on each successful login.
var LoginsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "flomation_logins_total",
	Help: "Total successful logins since service start.",
})

// LoginFailuresTotal is incremented on each failed login attempt.
var LoginFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "flomation_login_failures_total",
	Help: "Total failed login attempts since service start.",
})

// MFAVerificationsTotal is incremented on each MFA verification attempt.
var MFAVerificationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "flomation_mfa_verifications_total",
	Help: "Total MFA verification attempts by result.",
}, []string{"result"})

// ── Gauges (updated by the periodic collector) ───────────────────────

var activeSessions = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "flomation_auth_active_sessions",
	Help: "Number of active (non-expired) sessions.",
})

var registeredUsers = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "flomation_auth_registered_users",
	Help: "Total number of registered users.",
})

var staleUsers = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "flomation_auth_stale_users",
	Help: "Number of users whose last session was more than 28 days ago or who have never logged in.",
})

var mfaEnabledPercent = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "flomation_auth_mfa_enabled_percent",
	Help: "Percentage of registered users with MFA enabled.",
})

// StartCollector launches a background goroutine that periodically
// queries the database to update gauge metrics.
func StartCollector(db *sqlx.DB, interval time.Duration) {
	go func() {
		time.Sleep(5 * time.Second)
		collect(db)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			collect(db)
		}
	}()
	log.WithField("interval", interval).Info("metrics collector started")
}

func collect(db *sqlx.DB) {
	var count int64

	// Active sessions
	if err := db.Get(&count, `SELECT COUNT(*) FROM session WHERE expiration > NOW()`); err == nil {
		activeSessions.Set(float64(count))
	}

	// Total registered users
	var totalUsers int64
	if err := db.Get(&totalUsers, `SELECT COUNT(*) FROM "user"`); err == nil {
		registeredUsers.Set(float64(totalUsers))
	}

	// Stale users: last session > 28 days ago, or never logged in
	if err := db.Get(&count, `
		SELECT COUNT(*) FROM "user" u
		WHERE NOT EXISTS (
			SELECT 1 FROM session s
			WHERE s.user_id = u.id
			  AND s.expiration > NOW() - INTERVAL '28 days'
		)`); err == nil {
		staleUsers.Set(float64(count))
	}

	// MFA enabled percentage
	if totalUsers > 0 {
		var mfaCount int64
		if err := db.Get(&mfaCount, `SELECT COUNT(DISTINCT user_id) FROM mfa_device WHERE enabled = TRUE`); err == nil {
			mfaEnabledPercent.Set(float64(mfaCount) / float64(totalUsers) * 100.0)
		}
	} else {
		mfaEnabledPercent.Set(0)
	}
}
