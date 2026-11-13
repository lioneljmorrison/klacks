package store

import (
	"fmt"

	gocql "github.com/apache/cassandra-gocql-driver/v2"

	"github.com/lioneljmorrison/klacks/internal/config"
)

// ScyllaCluster builds a cluster config from cfg. keyspace may be empty, for
// work such as creating the keyspace itself.
func ScyllaCluster(cfg config.Scylla, keyspace string) *gocql.ClusterConfig {
	c := gocql.NewCluster(cfg.Hosts...)
	c.Keyspace = keyspace
	c.Timeout = cfg.Timeout.D()
	c.ConnectTimeout = cfg.Timeout.D()
	c.Consistency = gocql.Quorum
	if cfg.Username != "" {
		c.Authenticator = gocql.PasswordAuthenticator{Username: cfg.Username, Password: cfg.Password}
	}
	return c
}

// OpenScylla opens a session bound to cfg.Keyspace.
func OpenScylla(cfg config.Scylla) (*gocql.Session, error) {
	s, err := ScyllaCluster(cfg, cfg.Keyspace).CreateSession()
	if err != nil {
		return nil, fmt.Errorf("scylla: %w", err)
	}
	return s, nil
}
