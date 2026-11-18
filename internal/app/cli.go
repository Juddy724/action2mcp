package app

import (
	"action2mcp/internal/config"
	"action2mcp/internal/mcp"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const usage = `Action2MCP %s —— 把浏览器里的业务操作录成 AI 可调用的 MCP 工具

用法:
  a2m                       启动本地服务并打开控制台（同 a2m serve）
  a2m serve [--no-open]     启动本地服务（http://localhost:7788）
  a2m rec <名称> [起始网址]   开始录制（会自动启动服务并打开专用浏览器）
  a2m stop                  结束当前录制
  a2m login [网址]           打开专用浏览器登录（不录制），登录态会被工具调用复用
  a2m status                查看状态
  a2m export <文件.a2m>      导出工具和流程包（不含任何登录态）
  a2m import <文件.a2m>      导入工具和流程包
  a2m mcp                   以 stdio 方式提供 MCP（给只支持 stdio 的客户端用）
  a2m quit                  关闭后台服务
  a2m version               版本号

数据目录: %s
`

// Main runs the Action2MCP CLI. Arguments, stdio, and exit codes are unchanged.
// exitServer ends the serve process; cmdServe installs the real shutdown.
var exitServer = func() {}

func Main() {
	log.SetFlags(log.Ltime)
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	dataDir := config.ResolveDataDir()
	var err error
	switch cmd {
	case "serve", "start":
		open := true
		for _, a := range args {
			if a == "--no-open" {
				open = false
			}
		}
		err = cmdServe(dataDir, open)
	case "rec", "record":
		if len(args) == 0 {
			err = errors.New("请提供录制名称，例如: a2m rec 查询客户 https://crm.example.com")
			break
		}
		u := ""
		if len(args) > 1 {
			u = args[1]
		}
		err = cmdRec(dataDir, args[0], u)
	case "stop":
		err = cmdStop(dataDir)
	case "login", "browser":
		u := ""
		if len(args) > 0 {
			u = args[0]
		}
		err = cmdLogin(dataDir, u)
	case "status":
		err = cmdStatus(dataDir)
	case "export":
		if len(args) == 0 {
			args = []string{"action2mcp-" + time.Now().Format("20060102-1504") + ".a2m"}
		}
		err = cmdExport(dataDir, args[0])
	case "import":
		if len(args) == 0 {
			err = errors.New("请提供要导入的文件，例如: a2m import tools.a2m")
			break
		}
		err = cmdImport(dataDir, args[0])
	case "mcp", "stdio":
		err = cmdStdio(dataDir)
	case "quit", "shutdown":
		err = cmdQuit(dataDir)
	case "version", "-v", "--version":
		fmt.Println("Action2MCP", Version)
	case "help", "-h", "--help":
		fmt.Printf(usage, Version, dataDir)
	default:
		fmt.Printf(usage, Version, dataDir)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		if len(os.Args) == 1 {
			// launched by double-click: keep the window open so the message can be read
			fmt.Fprintln(os.Stderr, "\n按回车键关闭此窗口…")
			bufio.NewReader(os.Stdin).ReadString('\n')
		}
		os.Exit(1)
	}
}

func baseURL(dataDir string) string {
	cfg := config.LoadConfig(dataDir)
	return fmt.Sprintf("http://127.0.0.1:%d", cfg.Port)
}

func apiCall(dataDir, method, path string, in any, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, baseURL(dataDir)+path, body)
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil {
		json.Unmarshal(b, out)
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(b))
		}
		return resp.StatusCode, errors.New(e.Error)
	}
	return resp.StatusCode, nil
}

func serverAlive(dataDir string) bool {
	alive, other := probeServer(dataDir)
	return alive && other == ""
}

// probeServer reports whether an Action2MCP server answers on this data dir's
// port, and if so whether it belongs to a different data dir (another copy of
// the program unzipped elsewhere).
func probeServer(dataDir string) (alive bool, otherDir string) {
	var st Status
	_, err := apiCall(dataDir, "GET", "/api/status", nil, &st)
	if err != nil || st.Version == "" {
		return false, ""
	}
	if st.DataDir != "" && !samePath(st.DataDir, dataDir) {
		return true, st.DataDir
	}
	return true, ""
}

func samePath(a, b string) bool {
	norm := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		return filepath.Clean(p)
	}
	a, b = norm(a), norm(b)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func portTakenErr(dataDir, other string) error {
	cfg := config.LoadConfig(dataDir)
	return fmt.Errorf("端口 %d 已被另一份 Action2MCP 占用（它的数据目录: %s）。\n请先在那份程序目录里执行 a2m quit 关闭它，或者修改本目录 data/config.json 里的 port 换一个端口", cfg.Port, other)
}

// ensureServer starts the server in the background if it is not running.
func ensureServer(dataDir string) error {
	if alive, other := probeServer(dataDir); alive {
		if other != "" {
			return portTakenErr(dataDir, other)
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	os.MkdirAll(dataDir, 0o755)
	logf, _ := os.OpenFile(filepath.Join(dataDir, "server.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	c := exec.Command(exe, "serve", "--no-open")
	c.Env = append(os.Environ(), "A2M_DATA="+dataDir)
	c.Stdout, c.Stderr, c.Stdin = logf, logf, nil
	detach(c)
	if err := c.Start(); err != nil {
		return fmt.Errorf("启动后台服务失败: %v", err)
	}
	c.Process.Release()
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		if serverAlive(dataDir) {
			return nil
		}
	}
	return errors.New("后台服务启动超时，请查看 data/server.log")
}

func cmdServe(dataDir string, open bool) error {
	cfg := config.LoadConfig(dataDir)
	consoleURL := fmt.Sprintf("http://localhost:%d/", cfg.Port)
	if _, other := probeServer(dataDir); other != "" {
		return portTakenErr(dataDir, other)
	}
	if serverAlive(dataDir) {
		fmt.Println("Action2MCP 已经在运行:", consoleURL)
		if open {
			openURL(consoleURL)
		}
		return nil
	}
	app, err := NewApp(dataDir)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.Port))
	if err != nil {
		return fmt.Errorf("端口 %d 被占用: %v（可在 data/config.json 修改 port）", cfg.Port, err)
	}
	if err := app.store.Approvals.CancelPending(); err != nil {
		ln.Close()
		app.Shutdown()
		return fmt.Errorf("清理遗留审批失败：%w", err)
	}
	srv := &http.Server{Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second}
	done := make(chan struct{})
	shutdown := func() {
		select {
		case <-done:
			return
		default:
		}
		close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}
	exitServer = shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("正在关闭…")
		app.Shutdown()
		shutdown()
	}()
	fmt.Printf("\n  Action2MCP %s 已启动\n\n  控制台:   %s\n  MCP 地址: http://localhost:%d/mcp\n  数据目录: %s\n\n  开始录制: 在控制台点「开始录制」，或另开命令行执行  a2m rec 查询客户 https://你的网站\n  关闭服务: 关闭这个窗口或按 Ctrl+C\n\n", Version, consoleURL, cfg.Port, dataDir)
	if open && (cfg.OpenConsole == nil || *cfg.OpenConsole) {
		go func() { time.Sleep(400 * time.Millisecond); openURL(consoleURL) }()
	}
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}

func openURL(u string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		c = exec.Command("open", u)
	default:
		c = exec.Command("xdg-open", u)
	}
	if err := c.Start(); err != nil {
		fmt.Println("请在浏览器中打开:", u)
		return
	}
	go c.Wait()
}

func cmdRec(dataDir, name, u string) error {
	if err := ensureServer(dataDir); err != nil {
		return err
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if _, err := apiCall(dataDir, "POST", "/api/recordings/start", map[string]string{"name": name, "url": u}, &out); err != nil {
		return err
	}
	fmt.Printf("● 开始录制 #%d「%s」\n  已打开专用浏览器窗口，请在里面正常登录和操作。\n  结束录制: 点击页面右下角「结束录制」，或执行 a2m stop，或直接关闭浏览器窗口。\n", out.ID, name)
	return nil
}

func cmdStop(dataDir string) error {
	if !serverAlive(dataDir) {
		return errors.New("Action2MCP 服务没有运行")
	}
	var info StopInfo
	if _, err := apiCall(dataDir, "POST", "/api/recordings/stop", map[string]string{"reason": "command"}, &info); err != nil {
		return err
	}
	fmt.Printf("■ 已结束录制 #%d「%s」：共捕获 %d 个请求，其中 %d 个可能是业务请求。\n  打开控制台查看并保存为工具: http://localhost:%d/#/recordings/%d\n", info.RecordingID, info.Name, info.Count, info.Useful, config.LoadConfig(dataDir).Port, info.RecordingID)
	return nil
}

func cmdLogin(dataDir, u string) error {
	if err := ensureServer(dataDir); err != nil {
		return err
	}
	if _, err := apiCall(dataDir, "POST", "/api/browser/open", map[string]string{"url": u}, nil); err != nil {
		return err
	}
	fmt.Println("已打开专用浏览器。登录完成后可以直接关闭窗口，登录态会保存在本机 data 目录里。")
	return nil
}

func cmdStatus(dataDir string) error {
	if !serverAlive(dataDir) {
		fmt.Println("服务未运行。执行 a2m 启动。")
		return nil
	}
	var st Status
	apiCall(dataDir, "GET", "/api/status", nil, &st)
	fmt.Printf("服务运行中 (pid %d)  MCP: %s\n", st.PID, st.MCPURL)
	if st.Recording {
		fmt.Printf("正在录制 #%d「%s」：已捕获 %d 个请求（%d 个可能有用），已录 %d 秒\n", st.RecordingID, st.RecordingName, st.Captured, st.Useful, st.RecordingSecs)
	} else {
		fmt.Println("当前没有录制")
	}
	if st.MCPMode == mcp.ModeFlat {
		fmt.Printf("工具 %d 个，已开启流程包 %d 个，MCP 平铺模式：对 AI 暴露 %d 个工具\n", st.TotalTools, st.EnabledPacks, st.ExposedTools)
	} else {
		fmt.Printf("工具 %d 个，已开启流程包 %d 个（共 %d 个工具），MCP 阶梯模式：AI 先看到 4 个入口工具，按需加载流程包\n", st.TotalTools, st.EnabledPacks, st.ExposedTools)
	}
	return nil
}

func cmdExport(dataDir, file string) error {
	app, err := NewApp(dataDir)
	if err != nil {
		return err
	}
	b, err := app.transfer().Export()
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, b, 0o644); err != nil {
		return err
	}
	fmt.Println("已导出到", file, "（不含登录态）")
	return nil
}

func cmdImport(dataDir, file string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	app, err := NewApp(dataDir)
	if err != nil {
		return err
	}
	r, err := app.transfer().Import(b)
	if err != nil {
		return err
	}
	fmt.Printf("导入完成：新增工具 %d 个、更新 %d 个；新增流程包 %d 个、更新 %d 个\n", r.ToolsAdded, r.ToolsUpdated, r.PacksAdded, r.PacksUpdated)
	return nil
}

func cmdQuit(dataDir string) error {
	if !serverAlive(dataDir) {
		fmt.Println("服务未运行")
		return nil
	}
	apiCall(dataDir, "POST", "/api/quit", nil, nil)
	for i := 0; i < 50; i++ { // wait until the port is really free
		if alive, _ := probeServer(dataDir); !alive {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("已关闭服务")
	return nil
}

// cmdStdio bridges MCP stdio <-> the local HTTP endpoint. Responses may come back as JSON or as an
// SSE stream; server-initiated notifications (tools/list_changed) are read from the GET /mcp stream
// and written to stdout as well.
func cmdStdio(dataDir string) error {
	log.SetOutput(os.Stderr)
	if err := ensureServer(dataDir); err != nil {
		return err
	}
	endpoint := baseURL(dataDir) + "/mcp"
	client := &http.Client{}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	out := bufio.NewWriter(os.Stdout)
	var outMu sync.Mutex
	write := func(b []byte) {
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			return
		}
		outMu.Lock()
		out.Write(b)
		out.WriteByte('\n')
		out.Flush()
		outMu.Unlock()
	}
	var sessMu sync.Mutex
	session := ""
	getSession := func() string { sessMu.Lock(); defer sessMu.Unlock(); return session }
	streamStarted := false
	startStream := func() {
		go func() {
			for {
				sid := getSession()
				req, _ := http.NewRequest("GET", endpoint, nil)
				req.Header.Set("Accept", "text/event-stream")
				req.Header.Set("Mcp-Session-Id", sid)
				resp, err := (&http.Client{}).Do(req)
				if err == nil && resp.StatusCode == 200 {
					readSSE(resp.Body, write)
					resp.Body.Close()
				} else if resp != nil {
					resp.Body.Close()
				}
				time.Sleep(2 * time.Second) // server restarted or stream dropped: reconnect
			}
		}()
	}
	var wg sync.WaitGroup
	handleLine := func(line []byte) {
		var resp *http.Response
		var err error
		timeout, attempts := stdioCallPolicy(line)
		reqClient := &http.Client{Timeout: timeout, Transport: client.Transport}
		for attempt := 0; attempt < attempts; attempt++ {
			req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(line))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			if s := getSession(); s != "" {
				req.Header.Set("Mcp-Session-Id", s)
			}
			resp, err = reqClient.Do(req)
			if err == nil {
				break
			}
			if attempt+1 < attempts {
				ensureServer(dataDir)
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "a2m mcp:", err)
			return
		}
		if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
			sessMu.Lock()
			session = s
			started := streamStarted
			if !streamStarted {
				streamStarted = true
			}
			sessMu.Unlock()
			if !started {
				startStream()
			}
		}
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			readSSE(resp.Body, write)
			resp.Body.Close()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusAccepted {
			return
		}
		write(b)
	}
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		line := append([]byte(nil), raw...)
		if stdioAsyncCall(line) && getSession() != "" {
			wg.Add(1)
			go func(b []byte) {
				defer wg.Done()
				handleLine(b)
			}(line)
			continue
		}
		handleLine(line)
	}
	wg.Wait()
	return nil
}

func stdioAsyncCall(line []byte) bool {
	var q struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(line, &q) != nil || q.Method != "tools/call" {
		return false
	}
	switch q.Params.Name {
	case "list_packs", "load_pack", "unload_pack":
		return false
	}
	return true
}

func stdioCallPolicy(line []byte) (time.Duration, int) {
	var q struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(line, &q) == nil && q.Method == "tools/call" {
		return 35 * time.Minute, 1
	}
	return 240 * time.Second, 2
}

// readSSE calls fn with the data of every SSE event in r.
func readSSE(r io.Reader, fn func([]byte)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	var data []string
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			if len(data) > 0 {
				fn([]byte(strings.Join(data, "\n")))
				data = nil
			}
			continue
		}
		if strings.HasPrefix(l, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(l, "data:"), " "))
		}
	}
	if len(data) > 0 {
		fn([]byte(strings.Join(data, "\n")))
	}
}
