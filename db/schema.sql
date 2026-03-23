CREATE TABLE IF NOT EXISTS agent_events (
    id        INTEGER PRIMARY KEY,
    ts        TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    pid       INTEGER NOT NULL,
    comm      TEXT NOT NULL,
    syscall   TEXT NOT NULL,
    arg       TEXT NOT NULL,
    agent_run TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_events_ts ON agent_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_agent_events_syscall ON agent_events (syscall);
CREATE INDEX IF NOT EXISTS idx_agent_events_agent_run ON agent_events (agent_run);
