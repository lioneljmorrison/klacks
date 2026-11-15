package store

import (
	"context"
	"errors"
	"net"
	"strings"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/jackc/pgx/v5/pgconn"
)

// Unavailable reports whether err is a store outage or timeout rather than
// a bug or a rejected request (S-46): the stores could not be reached, did
// not answer in time, were overloaded or shutting down, or a room lock
// could not be had in time. Nothing was committed by the failed call
// unless its commit itself timed out (plan §3.3c), so the client may retry
// once the stores answer. context.Canceled is not an outage: the caller
// went away.
func Unavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || pgconn.Timeout(err) {
		return true
	}
	for _, e := range []error{
		gocql.ErrTimeoutNoResponse, gocql.ErrConnectionClosed, gocql.ErrNoStreams,
		gocql.ErrNoConnections, gocql.ErrUnavailable,
		gocql.ErrSessionClosed,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	var (
		unavail   *gocql.RequestErrUnavailable
		wTimeout  *gocql.RequestErrWriteTimeout
		rTimeout  *gocql.RequestErrReadTimeout
		overload  *gocql.RequestErrOverloaded
		bootstrap *gocql.RequestErrBootstrapping
		connect   *pgconn.ConnectError
		netErr    *net.OpError
		pgErr     *pgconn.PgError
	)
	switch {
	case errors.As(err, &unavail), errors.As(err, &wTimeout), errors.As(err, &rTimeout),
		errors.As(err, &overload), errors.As(err, &bootstrap),
		errors.As(err, &connect), errors.As(err, &netErr):
		return true
	case errors.As(err, &pgErr):
		return pgUnavailable(pgErr.Code)
	}
	return false
}

// pgUnavailable reports whether a PostgreSQL SQLSTATE is an outage or
// timeout: connection exceptions (class 08), insufficient resources (class
// 53), shutdown or startup (57P01–57P03), and the room lock's timeouts:
// lock_not_available (55P03, lock_timeout), query_canceled (57014,
// statement_timeout) and idle_in_transaction_session_timeout (25P03).
// Codes as in PostgreSQL's errcodes.txt.
func pgUnavailable(code string) bool {
	switch {
	case strings.HasPrefix(code, "08"), strings.HasPrefix(code, "53"):
		return true
	}
	switch code {
	case "57P01", "57P02", "57P03", "55P03", "57014", "25P03":
		return true
	}
	return false
}
