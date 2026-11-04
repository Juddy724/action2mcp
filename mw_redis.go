package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/redis/go-redis/v9"
)

// key positions: "1" first arg, "all" every arg, "pairs" k v k v…, "2" first two args, "none" no key,
// "numkeys" EVAL-style (numkeys then keys).
type redisSpec struct {
	Perm string
	Keys string
}

var redisCmds = map[string]redisSpec{}

var redisBlocked = map[string]string{
	"FLUSHALL": "会清空整个 Redis", "FLUSHDB": "会清空整个库", "CONFIG": "会修改服务器配置", "SHUTDOWN": "会关闭 Redis",
	"DEBUG": "调试命令", "KEYS": "会阻塞 Redis，请改用 redis_scan", "MONITOR": "会持续输出所有命令", "SUBSCRIBE": "订阅会一直阻塞",
	"PSUBSCRIBE": "订阅会一直阻塞", "SSUBSCRIBE": "订阅会一直阻塞", "SELECT": "不允许切换库", "MOVE": "不允许跨库移动", "SWAPDB": "不允许交换库",
	"MULTI": "不支持事务", "EXEC": "不支持事务", "WATCH": "不支持事务", "SCRIPT": "不允许管理脚本", "FUNCTION": "不允许管理函数",
	"ACL": "不允许管理账号", "CLIENT": "不允许管理连接", "CLUSTER": "不允许管理集群", "SAVE": "会阻塞 Redis", "BGSAVE": "持久化管理",
	"BGREWRITEAOF": "持久化管理", "LASTSAVE": "持久化管理", "MIGRATE": "不允许迁移数据", "MODULE": "不允许加载模块",
	"RESTORE": "不允许恢复序列化数据", "DUMP": "不允许导出序列化数据", "REPLICAOF": "复制管理", "SLAVEOF": "复制管理", "SYNC": "复制管理",
	"PSYNC": "复制管理", "FAILOVER": "复制管理", "SLOWLOG": "服务器管理", "LATENCY": "服务器管理", "MEMORY": "服务器管理",
	"OBJECT": "服务器管理", "COMMAND": "服务器管理", "AUTH": "不允许切换账号", "HELLO": "不允许切换协议或账号", "RESET": "不允许重置连接",
	"QUIT": "不允许断开连接", "BLPOP": "阻塞命令", "BRPOP": "阻塞命令", "BLMOVE": "阻塞命令", "BRPOPLPUSH": "阻塞命令",
	"BZPOPMIN": "阻塞命令", "BZPOPMAX": "阻塞命令", "BLMPOP": "阻塞命令", "BZMPOP": "阻塞命令", "XREAD": "可能阻塞，请用 XRANGE",
	"XREADGROUP": "会改变消费组状态", "WAIT": "阻塞命令", "WAITAOF": "阻塞命令", "PUBLISH": "不支持发布消息", "SPUBLISH": "不支持发布消息",
	"SORT": "可能写入其它 key", "RANDOMKEY": "不允许随机读取任意 key", "SCAN": "请使用 redis_scan 工具", "EVAL_RO": "", "EVALSHA_RO": "",
}

func init() {
	add := func(perm, keys string, names ...string) {
		for _, n := range names {
			redisCmds[n] = redisSpec{perm, keys}
		}
	}
	add("read", "1", "GET", "STRLEN", "GETRANGE", "SUBSTR", "TYPE", "TTL", "PTTL", "EXPIRETIME", "PEXPIRETIME",
		"HGET", "HMGET", "HGETALL", "HKEYS", "HVALS", "HLEN", "HEXISTS", "HSTRLEN", "HRANDFIELD", "HSCAN",
		"LRANGE", "LLEN", "LINDEX", "LPOS", "SMEMBERS", "SISMEMBER", "SMISMEMBER", "SCARD", "SRANDMEMBER", "SSCAN",
		"ZRANGE", "ZRANGEBYSCORE", "ZREVRANGE", "ZREVRANGEBYSCORE", "ZRANGEBYLEX", "ZREVRANGEBYLEX", "ZSCORE", "ZMSCORE",
		"ZCARD", "ZCOUNT", "ZRANK", "ZREVRANK", "ZSCAN", "ZLEXCOUNT", "ZRANDMEMBER", "XRANGE", "XREVRANGE", "XLEN",
		"GETBIT", "BITCOUNT", "BITPOS", "GEOPOS", "GEODIST", "GEOHASH", "GEOSEARCH", "GEORADIUS_RO", "GEORADIUSBYMEMBER_RO")
	add("read", "all", "MGET", "EXISTS", "SINTER", "SUNION", "SDIFF", "PFCOUNT", "TOUCH")
	add("read", "none", "PING", "DBSIZE", "ECHO", "TIME", "INFO")
	add("write", "1", "SET", "SETNX", "SETEX", "PSETEX", "APPEND", "INCR", "INCRBY", "INCRBYFLOAT", "DECR", "DECRBY",
		"GETSET", "GETEX", "SETRANGE", "SETBIT", "HSET", "HSETNX", "HMSET", "HINCRBY", "HINCRBYFLOAT", "LPUSH", "RPUSH",
		"LPUSHX", "RPUSHX", "LSET", "LINSERT", "SADD", "ZADD", "ZINCRBY", "XADD", "PFADD", "EXPIRE", "PEXPIRE",
		"EXPIREAT", "PEXPIREAT", "PERSIST", "GEOADD")
	add("write", "pairs", "MSET", "MSETNX")
	add("write", "2", "RENAME", "RENAMENX", "LMOVE", "RPOPLPUSH", "SMOVE")
	add("delete", "all", "DEL", "UNLINK")
	add("delete", "1", "HDEL", "LREM", "LTRIM", "SREM", "ZREM", "ZREMRANGEBYSCORE", "ZREMRANGEBYRANK", "ZREMRANGEBYLEX",
		"XDEL", "XTRIM", "GETDEL", "LPOP", "RPOP", "SPOP", "ZPOPMIN", "ZPOPMAX")
	add("script", "numkeys", "EVAL", "EVALSHA", "FCALL", "FCALL_RO")
	delete(redisBlocked, "EVAL_RO")
	delete(redisBlocked, "EVALSHA_RO")
	add("script", "numkeys", "EVAL_RO", "EVALSHA_RO")
}

// splitCommand splits "SET a 'b c'" into args, honoring single/double quotes.
func splitCommand(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQ := rune(0)
	has := false
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\' && inQ == '"':
			esc = true
		case inQ != 0:
			if r == inQ {
				inQ = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			inQ, has = r, true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if has || cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if inQ != 0 {
		return nil, errors.New("命令里的引号没有闭合")
	}
	if has || cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out, nil
}

// classifyRedis returns the permission needed and the keys touched, or an error for blocked commands.
func classifyRedis(args []string, c *MWConfig) (string, []string, error) {
	if len(args) == 0 {
		return "", nil, errors.New("请提供 Redis 命令")
	}
	name := strings.ToUpper(strings.TrimSpace(args[0]))
	if why, ok := redisBlocked[name]; ok {
		return "", nil, fmt.Errorf("已拦截：不允许执行 %s（%s）", name, why)
	}
	spec, ok := redisCmds[name]
	if !ok {
		return "", nil, fmt.Errorf("已拦截：不支持的 Redis 命令 %s（只允许常用的读写命令）", name)
	}
	rest := args[1:]
	var keys []string
	switch spec.Keys {
	case "1":
		if len(rest) < 1 {
			return "", nil, fmt.Errorf("%s 缺少 key 参数", name)
		}
		keys = rest[:1]
	case "2":
		if len(rest) < 2 {
			return "", nil, fmt.Errorf("%s 需要两个 key", name)
		}
		keys = rest[:2]
	case "all":
		if len(rest) < 1 {
			return "", nil, fmt.Errorf("%s 缺少 key 参数", name)
		}
		keys = rest
	case "pairs":
		if len(rest) < 2 || len(rest)%2 != 0 {
			return "", nil, fmt.Errorf("%s 的参数必须是 key value 成对出现", name)
		}
		for i := 0; i < len(rest); i += 2 {
			keys = append(keys, rest[i])
		}
	case "numkeys":
		if len(rest) < 2 {
			return "", nil, fmt.Errorf("%s 参数不完整", name)
		}
		n, err := strconv.Atoi(rest[1])
		if err != nil || n < 0 || n > len(rest)-2 {
			return "", nil, fmt.Errorf("%s 的 numkeys 参数无效", name)
		}
		keys = rest[2 : 2+n]
		if len(c.KeyPrefixes) > 0 {
			return "", nil, errors.New("已拦截：中间件限定了 key 前缀，脚本可以访问任意 key，因此不允许执行脚本")
		}
	}
	if len(c.KeyPrefixes) > 0 {
		if spec.Keys == "none" && name == "DBSIZE" {
			return "", nil, errors.New("已拦截：中间件限定了 key 前缀，不能统计整个库")
		}
		for _, k := range keys {
			if !hasAnyPrefix(k, c.KeyPrefixes) {
				return "", nil, fmt.Errorf("无权限：key %q 不在允许的前缀范围内（%s）", k, strings.Join(c.KeyPrefixes, "、"))
			}
		}
	}
	return spec.Perm, keys, nil
}

func hasAnyPrefix(s string, ps []string) bool {
	for _, p := range ps {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (a *App) redisClient(m *Middleware) (redis.UniversalClient, error) {
	pw, err := a.mwPassword(m)
	if err != nil {
		return nil, err
	}
	key := m.cacheKey(pw)
	if v, ok := a.mwPool.Load(key); ok {
		return v.(redis.UniversalClient), nil
	}
	c := m.Config
	opt := &redis.UniversalOptions{
		Username:     c.User,
		Password:     pw,
		DialTimeout:  8 * time.Second,
		ReadTimeout:  time.Duration(c.timeoutSec()) * time.Second,
		WriteTimeout: time.Duration(c.timeoutSec()) * time.Second,
		PoolSize:     4,
		MaxRetries:   1,
	}
	if c.Database != "" {
		opt.DB, _ = strconv.Atoi(c.Database)
	}
	if c.TLS {
		opt.TLSConfig = &tls.Config{InsecureSkipVerify: c.TLSSkipVerify, MinVersion: tls.VersionTLS12}
	}
	var cl redis.UniversalClient
	switch c.RedisMode {
	case "cluster":
		opt.Addrs = strings.Split(c.Addrs, ",")
		cl = redis.NewClusterClient(opt.Cluster())
	case "sentinel":
		opt.Addrs = strings.Split(c.Addrs, ",")
		opt.MasterName = c.MasterName
		cl = redis.NewFailoverClient(opt.Failover())
	default:
		opt.Addrs = []string{joinHostPort(c.Host, c.Port)}
		cl = redis.NewClient(opt.Simple())
	}
	a.mwPoolPut(m.ID, key, cl)
	return cl, nil
}

func (a *App) testRedis(ctx context.Context, m *Middleware) (string, error) {
	cl, err := a.redisClient(m)
	if err != nil {
		return "", err
	}
	if err := cl.Ping(ctx).Err(); err != nil {
		a.mwPoolDrop(m.ID)
		return "", err
	}
	ver := ""
	if info, err := cl.Info(ctx, "server").Result(); err == nil {
		for _, l := range strings.Split(info, "\n") {
			if strings.HasPrefix(l, "redis_version:") {
				ver = "，版本 " + strings.TrimSpace(strings.TrimPrefix(l, "redis_version:"))
			}
		}
	}
	return "连接成功" + ver, nil
}

func redisValue(v any, budget *int) any {
	switch x := v.(type) {
	case string:
		if *budget <= 0 {
			*budget -= len(x)
			return "…（已截断）"
		}
		if len(x) > *budget {
			cut := *budget
			for cut > 0 && !utf8.RuneStart(x[cut]) {
				cut--
			}
			*budget = -1
			return x[:cut] + fmt.Sprintf("…（已截断，共 %d 字节）", len(x))
		}
		*budget -= len(x)
		return x
	case []any:
		out := []any{}
		for _, e := range x {
			if *budget < 0 {
				out = append(out, "…（已截断）")
				break
			}
			out = append(out, redisValue(e, budget))
		}
		return out
	case map[any]any:
		out := map[string]any{}
		for k, e := range x {
			if *budget < 0 {
				out["…"] = "（已截断）"
				break
			}
			out[fmt.Sprint(k)] = redisValue(e, budget)
		}
		return out
	case nil:
		return nil
	}
	return v
}

func (a *App) callRedis(ctx context.Context, c *mwCall, args map[string]any) (string, bool) {
	cfg := &c.m.Config
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.timeoutSec())*time.Second)
	defer cancel()
	if c.tool == "redis_scan" {
		match := argStr(args, "match")
		c.action = "SCAN MATCH " + match
		if msg, ok := c.need("read"); !ok {
			return msg, true
		}
		max := argInt(args, "max", 100)
		if max <= 0 || max > cfg.maxRows()*5 {
			max = cfg.maxRows() * 5
		}
		patterns := []string{match}
		if match == "" {
			patterns = []string{"*"}
		}
		if len(cfg.KeyPrefixes) > 0 {
			if match == "" {
				patterns = nil
				for _, p := range cfg.KeyPrefixes {
					patterns = append(patterns, escapeGlob(p)+"*")
				}
			} else if !globWithinPrefixes(match, cfg.KeyPrefixes) {
				return c.blocked(fmt.Sprintf("无权限：中间件「%s」只允许 key 前缀 %s，匹配模式 %q 超出范围", c.m.Name, strings.Join(cfg.KeyPrefixes, "、"), match)), true
			}
		}
		cl, err := a.redisClient(c.m)
		if err != nil {
			return c.done("", err)
		}
		keys, err := redisScan(ctx, cl, patterns, max)
		if err != nil {
			return c.done("", err)
		}
		if len(cfg.KeyPrefixes) > 0 {
			kept := []string{}
			for _, k := range keys {
				if hasAnyPrefix(k, cfg.KeyPrefixes) {
					kept = append(kept, k)
				}
			}
			keys = kept
		}
		sort.Strings(keys)
		res := map[string]any{"keys": keys, "count": len(keys)}
		if len(keys) >= max {
			res["truncated"] = true
			res["note"] = fmt.Sprintf("最多返回 %d 个 key，请用更精确的 match 缩小范围", max)
		}
		return c.done(jsonText(res), nil)
	}
	var cmd []string
	if raw, ok := args["args"].([]any); ok && len(raw) > 0 {
		for _, x := range raw {
			cmd = append(cmd, fmt.Sprint(x))
		}
	} else {
		var err error
		cmd, err = splitCommand(argStr(args, "command"))
		if err != nil {
			return err.Error(), true
		}
	}
	perm, keys, err := classifyRedis(cmd, cfg)
	if len(cmd) > 0 {
		c.action = strings.ToUpper(cmd[0])
		if len(keys) > 0 {
			c.action += " " + strings.Join(keys, " ")
		}
	}
	if err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "无权限：") {
			msg = fmt.Sprintf("无权限：中间件「%s」%s", c.m.Name, strings.TrimPrefix(msg, "无权限："))
		}
		return c.blocked(msg), true
	}
	if msg, ok := c.need(perm); !ok {
		return msg, true
	}
	cl, err := a.redisClient(c.m)
	if err != nil {
		return c.done("", err)
	}
	iargs := make([]any, len(cmd))
	for i, s := range cmd {
		iargs[i] = s
	}
	v, err := cl.Do(ctx, iargs...).Result()
	if err == redis.Nil {
		return c.done(`{"result":null}`, nil)
	}
	if err != nil {
		return c.done("", err)
	}
	budget := cfg.maxResultBytes()
	out := map[string]any{"result": redisValue(v, &budget)}
	if budget < 0 {
		out["truncated"] = true
		out["note"] = "结果太大，已截断"
	}
	return c.done(jsonText(out), nil)
}

func escapeGlob(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`, `]`, `\]`)
	return r.Replace(s)
}

// globWithinPrefixes: the literal part of the pattern before the first glob char must start with an allowed prefix.
func globWithinPrefixes(pat string, ps []string) bool {
	lit := strings.Builder{}
	for i := 0; i < len(pat); i++ {
		ch := pat[i]
		if ch == '\\' && i+1 < len(pat) {
			lit.WriteByte(pat[i+1])
			i++
			continue
		}
		if ch == '*' || ch == '?' || ch == '[' {
			break
		}
		lit.WriteByte(ch)
	}
	return hasAnyPrefix(lit.String(), ps)
}

func redisScan(ctx context.Context, cl redis.UniversalClient, patterns []string, max int) ([]string, error) {
	var mu sync.Mutex
	seen := map[string]bool{}
	keys := []string{}
	scanOne := func(ctx context.Context, c redis.Cmdable) error {
		for _, p := range patterns {
			var cursor uint64
			for i := 0; i < 1000; i++ {
				ks, next, err := c.Scan(ctx, cursor, p, 500).Result()
				if err != nil {
					return err
				}
				mu.Lock()
				for _, k := range ks {
					if !seen[k] && len(keys) < max {
						seen[k] = true
						keys = append(keys, k)
					}
				}
				full := len(keys) >= max
				mu.Unlock()
				if full || next == 0 {
					break
				}
				cursor = next
			}
		}
		return nil
	}
	if cc, ok := cl.(*redis.ClusterClient); ok {
		err := cc.ForEachMaster(ctx, func(ctx context.Context, c *redis.Client) error { return scanOne(ctx, c) })
		return keys, err
	}
	return keys, scanOne(ctx, cl)
}
