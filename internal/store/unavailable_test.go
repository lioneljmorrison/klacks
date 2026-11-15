package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/jackc/pgx/v5/pgconn"
)

// S-46: store outages and timeouts are told apart from everything else, so
// clients can retry the one and not the other.
func TestUnavailable(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("post message: rooms: lock: %w", err) }
	yes := []error{
		context.DeadlineExceeded,
		gocql.ErrTimeoutNoResponse,
		gocql.ErrConnectionClosed,
		gocql.ErrNoStreams,
		gocql.ErrNoConnections,
		gocql.ErrUnavailable,
		gocql.ErrSessionClosed,
		&gocql.RequestErrUnavailable{},
		&gocql.RequestErrWriteTimeout{},
		&gocql.RequestErrReadTimeout{},
		&gocql.RequestErrOverloaded{},
		&gocql.RequestErrBootstrapping{},
		&pgconn.ConnectError{},
		&pgconn.PgError{Code: "08006"}, // connection_failure
		&pgconn.PgError{Code: "53300"}, // too_many_connections
		&pgconn.PgError{Code: "57P01"}, // admin_shutdown
		&pgconn.PgError{Code: "57P03"}, // cannot_connect_now
		&pgconn.PgError{Code: "55P03"}, // lock_not_available (lock_timeout)
		&pgconn.PgError{Code: "57014"}, // query_canceled (statement_timeout)
		&pgconn.PgError{Code: "25P03"}, // idle_in_transaction_session_timeout
		&net.OpError{Op: "dial", Err: errors.New("connection refused")},
	}
	for _, err := range yes {
		if !Unavailable(wrap(err)) {
			t.Errorf("Unavailable(%T %v) = false; want true", err, err)
		}
	}
	no := []error{
		nil,
		context.Canceled, // the caller went away; nothing to retry
		ErrRoomNotFound,
		errors.New("boom"),
		&pgconn.PgError{Code: "23505"}, // unique_violation
		&pgconn.PgError{Code: "42P01"}, // undefined_table: a bug, not an outage
		&gocql.RequestErrSyntax{},
	}
	for _, err := range no {
		if Unavailable(wrap(err)) && err != nil {
			t.Errorf("Unavailable(%T %v) = true; want false", err, err)
		}
	}
	if Unavailable(nil) {
		t.Error("Unavailable(nil) = true")
	}
}
