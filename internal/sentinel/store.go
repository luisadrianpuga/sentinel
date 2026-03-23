package sentinel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type Event struct {
	ID        int64
	Timestamp time.Time
	PID       int
	Comm      string
	Syscall   string
	Arg       string
	AgentRun  string
}

type QueryFilter struct {
	Syscall     string
	ArgContains string
	AgentRun    string
	Limit       int
}

type DiffResult struct {
	OnlyInLeft  []string
	OnlyInRight []string
}

type Store struct {
	db          *sql.DB
	placeholder func(int) string
	postgres    bool
}

func OpenStore(ctx context.Context, cfg Config) (*Store, error) {
	driver, dsn, placeholder, err := resolveDatabase(cfg)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db, placeholder: placeholder, postgres: driver == "pgx"}, nil
}

func resolveDatabase(cfg Config) (driver string, dsn string, placeholder func(int) string, err error) {
	if cfg.DatabaseURL == "" {
		if err := os.MkdirAll(filepath.Dir(cfg.SQLitePath), 0o755); err != nil {
			return "", "", nil, err
		}
		return "sqlite", cfg.SQLitePath, func(_ int) string { return "?" }, nil
	}

	if strings.HasPrefix(cfg.DatabaseURL, "postgres://") || strings.HasPrefix(cfg.DatabaseURL, "postgresql://") {
		return "pgx", cfg.DatabaseURL, func(idx int) string { return fmt.Sprintf("$%d", idx) }, nil
	}

	return "sqlite", cfg.DatabaseURL, func(_ int) string { return "?" }, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	tsDefault := "CURRENT_TIMESTAMP"
	idColumn := "INTEGER PRIMARY KEY AUTOINCREMENT"
	if s.postgres {
		tsDefault = "NOW()"
		idColumn = "BIGSERIAL PRIMARY KEY"
	}

	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS agent_events (
			id %s,
			ts TIMESTAMPTZ DEFAULT %s,
			pid INTEGER NOT NULL,
			comm TEXT NOT NULL,
			syscall TEXT NOT NULL,
			arg TEXT NOT NULL,
			agent_run TEXT
		)`, idColumn, tsDefault),
		`CREATE INDEX IF NOT EXISTS idx_agent_events_ts ON agent_events (ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_events_syscall ON agent_events (syscall)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_events_agent_run ON agent_events (agent_run)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) InsertEvent(ctx context.Context, event Event) error {
	stmt := fmt.Sprintf(
		"INSERT INTO agent_events (ts, pid, comm, syscall, arg, agent_run) VALUES (%s, %s, %s, %s, %s, %s)",
		s.placeholder(1),
		s.placeholder(2),
		s.placeholder(3),
		s.placeholder(4),
		s.placeholder(5),
		s.placeholder(6),
	)
	_, err := s.db.ExecContext(ctx, stmt, event.Timestamp, event.PID, event.Comm, event.Syscall, event.Arg, nullIfEmpty(event.AgentRun))
	return err
}

func (s *Store) Query(ctx context.Context, filter QueryFilter) ([]Event, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}

	var (
		clauses []string
		args    []any
		idx     = 1
	)
	if filter.Syscall != "" {
		clauses = append(clauses, fmt.Sprintf("syscall = %s", s.placeholder(idx)))
		args = append(args, filter.Syscall)
		idx++
	}
	if filter.ArgContains != "" {
		clauses = append(clauses, fmt.Sprintf("arg LIKE %s", s.placeholder(idx)))
		args = append(args, "%"+filter.ArgContains+"%")
		idx++
	}
	if filter.AgentRun != "" {
		clauses = append(clauses, fmt.Sprintf("agent_run = %s", s.placeholder(idx)))
		args = append(args, filter.AgentRun)
		idx++
	}

	query := "SELECT id, ts, pid, comm, syscall, arg, COALESCE(agent_run, '') FROM agent_events"
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY ts DESC LIMIT %s", s.placeholder(idx))
	args = append(args, filter.Limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.Timestamp, &event.PID, &event.Comm, &event.Syscall, &event.Arg, &event.AgentRun); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) DiffSessions(ctx context.Context, left, right string) (DiffResult, error) {
	if left == "" || right == "" {
		return DiffResult{}, errors.New("both session identifiers are required")
	}

	leftRows, err := s.Query(ctx, QueryFilter{AgentRun: left, Limit: 10000})
	if err != nil {
		return DiffResult{}, err
	}
	rightRows, err := s.Query(ctx, QueryFilter{AgentRun: right, Limit: 10000})
	if err != nil {
		return DiffResult{}, err
	}

	leftSet := make(map[string]struct{}, len(leftRows))
	rightSet := make(map[string]struct{}, len(rightRows))
	for _, event := range leftRows {
		leftSet[event.signature()] = struct{}{}
	}
	for _, event := range rightRows {
		rightSet[event.signature()] = struct{}{}
	}

	var diff DiffResult
	for signature := range leftSet {
		if _, ok := rightSet[signature]; !ok {
			diff.OnlyInLeft = append(diff.OnlyInLeft, signature)
		}
	}
	for signature := range rightSet {
		if _, ok := leftSet[signature]; !ok {
			diff.OnlyInRight = append(diff.OnlyInRight, signature)
		}
	}
	sort.Strings(diff.OnlyInLeft)
	sort.Strings(diff.OnlyInRight)
	return diff, nil
}

func (e Event) signature() string {
	return fmt.Sprintf("%s %s %s", e.Comm, e.Syscall, e.Arg)
}

func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
