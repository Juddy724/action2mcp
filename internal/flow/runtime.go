// Package flow detects script runtimes, executes embedded/external scripts,
// and orchestrates serial/parallel tool and script stages.
package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type RuntimeInfo struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Builtin   bool   `json:"builtin,omitempty"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

func enrichedPATH() string {
	cur := os.Getenv("PATH")
	if runtime.GOOS == "windows" {
		return cur
	}
	extra := []string{"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/local/go/bin"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		extra = append(extra, filepath.Join(home, "go", "bin"), filepath.Join(home, ".local", "bin"))
	}
	parts := []string{}
	seen := map[string]bool{}
	for _, p := range filepath.SplitList(cur) {
		if p != "" && !seen[p] {
			seen[p] = true
			parts = append(parts, p)
		}
	}
	for _, p := range extra {
		if !seen[p] {
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				seen[p] = true
				parts = append(parts, p)
			}
		}
	}
	return strings.Join(parts, string(os.PathListSeparator))
}

func lookPathEnriched(names ...string) (string, bool) {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p, true
		}
	}
	pathEnv := enrichedPATH()
	for _, dir := range filepath.SplitList(pathEnv) {
		for _, n := range names {
			cand := filepath.Join(dir, n)
			if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(cand), ".exe") {
				if st, err := os.Stat(cand + ".exe"); err == nil && !st.IsDir() {
					return cand + ".exe", true
				}
			}
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				return cand, true
			}
		}
	}
	return "", false
}

func probeVersion(bin string, args ...string) string {
	var out bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}

// DetectRuntimes inspects the built-in JS engine and local PATH runtimes.
func DetectRuntimes() []RuntimeInfo {
	out := []RuntimeInfo{
		{
			ID:        "builtin_js",
			Label:     "JavaScript (内置引擎 · 零依赖)",
			Builtin:   true,
			Available: true,
			Version:   "Built-in ES6",
		},
	}

	probe := func(id, label, hint string, verArgs []string, bins ...string) RuntimeInfo {
		info := RuntimeInfo{ID: id, Label: label, Hint: hint}
		if p, ok := lookPathEnriched(bins...); ok {
			info.Available = true
			info.Path = p
			info.Hint = ""
			info.Version = probeVersion(p, verArgs...)
		}
		return info
	}

	out = append(out,
		probe("python", "Python", "当前电脑未检测到 Python 环境或未配置 PATH 环境变量，请先安装 Python3 并配置环境变量", []string{"--version"}, "python3", "python"),
		probe("go", "Go", "当前电脑未检测到 Go 环境或未配置 PATH 环境变量，请先安装 Go 并配置 PATH", []string{"version"}, "go"),
		probe("java", "Java (JDK 11+)", "当前电脑未检测到 Java 环境或未配置 PATH 环境变量，请先安装 JDK (11+) 并配置 PATH", []string{"-version"}, "java"),
		probe("node", "Node.js", "当前电脑未检测到 Node.js 环境或未配置 PATH 环境变量，请先安装 Node.js 并配置 PATH（或改用内置 JS）", []string{"--version"}, "node"),
	)
	if runtime.GOOS == "windows" {
		out = append(out, probe("shell", "Shell / PowerShell", "当前电脑未检测到 PowerShell / Bash 环境", []string{"-Command", "$PSVersionTable.PSVersion.ToString()"}, "powershell", "pwsh", "bash"))
	} else {
		out = append(out, probe("shell", "Shell (Bash/Sh)", "当前电脑未检测到 Bash/Sh 环境", []string{"--version"}, "bash", "sh"))
	}
	return out
}

func findRuntimeInfo(runtimeID string) (RuntimeInfo, error) {
	id := strings.ToLower(strings.TrimSpace(runtimeID))
	if id == "" {
		id = "builtin_js"
	}
	for _, rt := range DetectRuntimes() {
		if rt.ID == id {
			if !rt.Available {
				return rt, errors.New(rt.Hint)
			}
			return rt, nil
		}
	}
	return RuntimeInfo{}, fmt.Errorf("不支持的脚本运行环境：%s", runtimeID)
}

func runExternalScript(ctx context.Context, runtimeID, code string, payload []byte) (any, string, error) {
	rt, err := findRuntimeInfo(runtimeID)
	if err != nil {
		return nil, "", err
	}
	tmpDir, err := os.MkdirTemp("", "a2m-flow-*")
	if err != nil {
		return nil, "", fmt.Errorf("创建临时目录失败：%v", err)
	}
	defer os.RemoveAll(tmpDir)

	ctxFile := filepath.Join(tmpDir, "context.json")
	if err := os.WriteFile(ctxFile, payload, 0o600); err != nil {
		return nil, "", fmt.Errorf("写入上下文文件失败：%v", err)
	}

	var scriptPath string
	var cmd *exec.Cmd
	switch rt.ID {
	case "python":
		scriptPath = filepath.Join(tmpDir, "script.py")
		if err := os.WriteFile(scriptPath, []byte(code), 0o600); err != nil {
			return nil, "", err
		}
		cmd = exec.CommandContext(ctx, rt.Path, scriptPath)
	case "go":
		scriptPath = filepath.Join(tmpDir, "main.go")
		if err := os.WriteFile(scriptPath, []byte(code), 0o600); err != nil {
			return nil, "", err
		}
		// Add minimal go.mod so `go run main.go` works regardless of working directory.
		_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module a2mscript\n\ngo 1.21\n"), 0o600)
		cmd = exec.CommandContext(ctx, rt.Path, "run", scriptPath)
	case "java":
		scriptPath = filepath.Join(tmpDir, "Main.java")
		if err := os.WriteFile(scriptPath, []byte(code), 0o600); err != nil {
			return nil, "", err
		}
		cmd = exec.CommandContext(ctx, rt.Path, scriptPath)
	case "node":
		scriptPath = filepath.Join(tmpDir, "script.js")
		if err := os.WriteFile(scriptPath, []byte(code), 0o600); err != nil {
			return nil, "", err
		}
		cmd = exec.CommandContext(ctx, rt.Path, scriptPath)
	case "shell":
		if strings.Contains(strings.ToLower(filepath.Base(rt.Path)), "powershell") || strings.Contains(strings.ToLower(filepath.Base(rt.Path)), "pwsh") {
			scriptPath = filepath.Join(tmpDir, "script.ps1")
			if err := os.WriteFile(scriptPath, []byte(code), 0o600); err != nil {
				return nil, "", err
			}
			cmd = exec.CommandContext(ctx, rt.Path, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
		} else {
			scriptPath = filepath.Join(tmpDir, "script.sh")
			if err := os.WriteFile(scriptPath, []byte(code), 0o700); err != nil {
				return nil, "", err
			}
			cmd = exec.CommandContext(ctx, rt.Path, scriptPath)
		}
	default:
		return nil, "", fmt.Errorf("不支持的外部脚本运行时：%s", rt.ID)
	}

	cmd.Dir = tmpDir
	cmd.Stdin = bytes.NewReader(payload)
	env := os.Environ()
	env = setEnvVar(env, "PATH", enrichedPATH())
	env = setEnvVar(env, "A2M_CONTEXT_FILE", ctxFile)
	env = setEnvVar(env, "PYTHONIOENCODING", "utf-8")
	if rt.ID == "go" && os.Getenv("GOCACHE") == "" {
		env = setEnvVar(env, "GOCACHE", filepath.Join(os.TempDir(), "a2m-go-cache"))
	}
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	outStr := strings.TrimSpace(stdout.String())
	errStr := strings.TrimSpace(stderr.String())
	logs := joinLogs(outStr, errStr)
	if runErr != nil {
		msg := errStr
		if msg == "" {
			msg = outStr
		}
		if msg == "" {
			msg = runErr.Error()
		}
		return nil, logs, fmt.Errorf("脚本执行失败（%v）：%s", runErr, msg)
	}

	parsed := parseScriptOutputJSON(outStr)
	return parsed, logs, nil
}

func setEnvVar(env []string, key, val string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if strings.HasPrefix(e, prefix) || (runtime.GOOS == "windows" && strings.EqualFold(strings.SplitN(e, "=", 2)[0], key)) {
			continue
		}
		out = append(out, e)
	}
	return append(out, prefix+val)
}

func joinLogs(stdout, stderr string) string {
	switch {
	case stdout != "" && stderr != "":
		return "[stdout]\n" + stdout + "\n[stderr]\n" + stderr
	case stderr != "":
		return "[stderr]\n" + stderr
	default:
		return stdout
	}
}

func parseScriptOutputJSON(outStr string) any {
	if outStr == "" {
		return map[string]any{}
	}
	var val any
	dec := json.NewDecoder(strings.NewReader(outStr))
	dec.UseNumber()
	if err := dec.Decode(&val); err == nil {
		var trailing any
		if dec.Decode(&trailing) != nil {
			return normalizeJSONNumbers(val)
		}
	}
	// Check lines from bottom to top for the last valid JSON object/array/value.
	lines := strings.Split(outStr, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var lv any
		ldec := json.NewDecoder(strings.NewReader(line))
		ldec.UseNumber()
		if err := ldec.Decode(&lv); err == nil {
			return normalizeJSONNumbers(lv)
		}
	}
	return map[string]any{"output": outStr}
}

func normalizeJSONNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	case map[string]any:
		for k, val := range x {
			x[k] = normalizeJSONNumbers(val)
		}
		return x
	case []any:
		for i := range x {
			x[i] = normalizeJSONNumbers(x[i])
		}
		return x
	default:
		return v
	}
}
