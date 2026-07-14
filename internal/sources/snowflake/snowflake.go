// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package snowflake

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/googleapis/mcp-toolbox/internal/sources"
	"github.com/jmoiron/sqlx"
	sf "github.com/snowflakedb/gosnowflake"
	"go.opentelemetry.io/otel/trace"
)

const SourceType string = "snowflake"

// validate interface
var _ sources.SourceConfig = Config{}

func init() {
	if !sources.Register(SourceType, newConfig) {
		panic(fmt.Sprintf("source type %q already registered", SourceType))
	}
}

func newConfig(ctx context.Context, name string, decoder *yaml.Decoder) (sources.SourceConfig, error) {
	actual := Config{Name: name}
	if err := decoder.DecodeContext(ctx, &actual); err != nil {
		return nil, err
	}
	return actual, nil
}

type Config struct {
	Name    string `yaml:"name" validate:"required"`
	Type    string `yaml:"type" validate:"required"`
	Account string `yaml:"account" validate:"required"`
	User    string `yaml:"user" validate:"required"`
	// Password is used for basic auth. Optional: provide either Password or
	// PrivateKey (key-pair / JWT auth). PrivateKey takes precedence.
	Password string `yaml:"password"`
	// PrivateKey enables key-pair (JWT) auth. Accepts an unencrypted PKCS8 RSA
	// private key as PEM, or that PEM base64-encoded (single-line, env-safe).
	PrivateKey string `yaml:"privateKey"`
	Database   string `yaml:"database" validate:"required"`
	Schema     string `yaml:"schema" validate:"required"`
	Warehouse  string `yaml:"warehouse"`
	Role       string `yaml:"role"`
}

func (r Config) SourceConfigType() string {
	return SourceType
}

func (r Config) Initialize(ctx context.Context, tracer trace.Tracer) (sources.Source, error) {
	if r.Password == "" && r.PrivateKey == "" {
		return nil, fmt.Errorf("snowflake source %q requires either 'password' or 'privateKey'", r.Name)
	}

	db, err := initSnowflakeConnection(ctx, tracer, r.Name, r.Account, r.User, r.Password, r.PrivateKey, r.Database, r.Schema, r.Warehouse, r.Role)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection: %w", err)
	}

	err = db.PingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to connect successfully: %w", err)
	}

	s := &Source{
		Config: r,
		DB:     db,
	}
	return s, nil
}

var _ sources.Source = &Source{}

type Source struct {
	Config
	DB *sqlx.DB
}

func (s *Source) SourceType() string {
	return SourceType
}

func (s *Source) ToConfig() sources.SourceConfig {
	return s.Config
}

func (s *Source) SnowflakeDB() *sqlx.DB {
	return s.DB
}

func (s *Source) RunSQL(ctx context.Context, statement string, params []any) (any, error) {
	rows, err := s.DB.QueryxContext(ctx, statement, params...)
	if err != nil {
		return nil, fmt.Errorf("unable to execute query: %w", err)
	}
	defer rows.Close()

	var out []any
	for rows.Next() {
		cols, err := rows.Columns()
		if err != nil {
			return nil, fmt.Errorf("unable to get columns: %w", err)
		}

		values := make([]interface{}, len(cols))
		valuePtrs := make([]interface{}, len(cols))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("unable to scan row: %w", err)
		}

		vMap := make(map[string]any)
		for i, col := range cols {
			vMap[col] = values[i]
		}
		out = append(out, vMap)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return out, nil
}

func initSnowflakeConnection(ctx context.Context, tracer trace.Tracer, name, account, user, password, privateKey, database, schema, warehouse, role string) (*sqlx.DB, error) {
	//nolint:all // Reassigned ctx
	ctx, span := sources.InitConnectionSpan(ctx, tracer, SourceType, name)
	defer span.End()

	// Set defaults for optional parameters
	if warehouse == "" {
		warehouse = "COMPUTE_WH"
	}
	if role == "" {
		role = "ACCOUNTADMIN"
	}

	var dsn string
	if privateKey != "" {
		// Key-pair (JWT) auth. Build the DSN through gosnowflake's own config so
		// the private key is passed as a parsed *rsa.PrivateKey.
		rsaKey, err := parseRSAPrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %w", err)
		}
		cfg := &sf.Config{
			Account:       account,
			User:          user,
			Database:      database,
			Schema:        schema,
			Warehouse:     warehouse,
			Role:          role,
			Authenticator: sf.AuthTypeJwt,
			PrivateKey:    rsaKey,
		}
		dsn, err = sf.DSN(cfg)
		if err != nil {
			return nil, fmt.Errorf("unable to build key-pair DSN: %w", err)
		}
	} else {
		// Basic auth.
		// Snowflake DSN format: user:password@account/database/schema?warehouse=warehouse&role=role
		dsn = fmt.Sprintf("%s:%s@%s/%s/%s?warehouse=%s&role=%s", user, password, account, database, schema, warehouse, role)
	}

	db, err := sqlx.ConnectContext(ctx, "snowflake", dsn)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection: %w", err)
	}

	return db, nil
}

// parseRSAPrivateKey accepts an unencrypted PKCS8 RSA private key, either as a
// PEM string or as that PEM base64-encoded (single line), and returns the parsed
// key. Base64 lets the key travel as an environment variable without newlines.
func parseRSAPrivateKey(s string) (*rsa.PrivateKey, error) {
	pemBytes := []byte(s)
	if !strings.Contains(s, "BEGIN") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("private key is neither PEM nor valid base64: %w", err)
		}
		pemBytes = decoded
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key (must be unencrypted): %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}
	return rsaKey, nil
}
