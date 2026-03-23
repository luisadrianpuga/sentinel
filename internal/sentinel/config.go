package sentinel

import "time"

type Config struct {
	AgentCommand  string
	AgentRun      string
	PID           int
	DatabaseURL   string
	SQLitePath    string
	BPFObjectPath string
	PollInterval  time.Duration
}

func DefaultConfig() Config {
	return Config{
		SQLitePath:    "data/sentinel.db",
		BPFObjectPath: "bpf/trace.bpf.o",
		PollInterval:  250 * time.Millisecond,
	}
}
