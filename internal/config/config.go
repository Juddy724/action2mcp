package config

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	Port        int      `json:"port"`
	Browser     string   `json:"browser"`
	BrowserArgs []string `json:"browser_args"`
	NoSandbox   bool     `json:"no_sandbox"`
	OpenConsole *bool    `json:"open_console,omitempty"`
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	exe, _ = filepath.EvalSymlinks(exe)
	return filepath.Dir(exe)
}

func ResolveDataDir() string {
	if d := os.Getenv("A2M_DATA"); d != "" {
		if abs, err := filepath.Abs(d); err == nil {
			return abs
		}
		return d
	}
	return filepath.Join(exeDir(), "data")
}

func LoadConfig(dataDir string) Config {
	cfg := Config{Port: 7788}
	p := filepath.Join(dataDir, "config.json")
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			log.Printf("config.json 格式错误: %v", err)
		}
	} else {
		os.MkdirAll(dataDir, 0o755)
		b, _ := json.MarshalIndent(map[string]any{"port": 7788, "browser": "", "browser_args": []string{}, "no_sandbox": false}, "", "  ")
		os.WriteFile(p, b, 0o644)
	}
	if v := os.Getenv("A2M_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Port = n
		}
	}
	if v := os.Getenv("A2M_BROWSER"); v != "" {
		cfg.Browser = v
	}
	if os.Getenv("A2M_NO_SANDBOX") == "1" {
		cfg.NoSandbox = true
	}
	if cfg.Port == 0 {
		cfg.Port = 7788
	}
	return cfg
}
