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
	if err := db.Get(&count, `SELECT COUNT(*) FROM session WHERE expires_at > NOW()`); err == nil {
		activeSessions.Set(float64(count))
	}
}
