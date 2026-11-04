package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/twmb/franz-go/pkg/kerr"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	rocketmq "github.com/apache/rocketmq-client-go/v2"
	rmqadmin "github.com/apache/rocketmq-client-go/v2/admin"
	rmqconsumer "github.com/apache/rocketmq-client-go/v2/consumer"
	"github.com/apache/rocketmq-client-go/v2/primitive"
	rmqproducer "github.com/apache/rocketmq-client-go/v2/producer"
	"github.com/apache/rocketmq-client-go/v2/rlog"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

func init() { rlog.SetLogLevel("error") }

type mqMessage struct {
	Topic     string            `json:"topic,omitempty"`
	Partition *int32            `json:"partition,omitempty"`
	Queue     *int              `json:"queue,omitempty"`
	Offset    *int64            `json:"offset,omitempty"`
	Key       string            `json:"key,omitempty"`
	Tag       string            `json:"tag,omitempty"`
	MsgID     string            `json:"msg_id,omitempty"`
	Time      string            `json:"time,omitempty"`
	Body      string            `json:"body"`
	Headers   map[string]string `json:"headers,omitempty"`
	ts        time.Time
}

func bodyText(b []byte, limit int) string {
	if len(b) > limit {
		cut := limit
		for cut > 0 && cut > limit-4 && !utf8.RuneStart(b[cut]) {
			cut--
		}
		b = b[:cut]
		if utf8.Valid(b) {
			return string(b) + "…（已截断）"
		}
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return fmt.Sprintf("（二进制消息，%d 字节）", len(b))
}

func (c *MWConfig) checkTopic(t string) error {
	if strings.TrimSpace(t) == "" {
		return errors.New("请提供 topic / 队列名")
	}
	if len(c.Topics) == 0 {
		return nil
	}
	for _, p := range c.Topics {
		if p == t || (strings.HasSuffix(p, "*") && strings.HasPrefix(t, strings.TrimSuffix(p, "*"))) {
			return nil
		}
	}
	return fmt.Errorf("无权限：%s 不在允许的范围内（允许：%s）", t, strings.Join(c.Topics, "、"))
}

func (a *App) testMQ(ctx context.Context, m *Middleware) (string, error) {
	switch m.Config.MQKind {
	case "kafka":
		cl, err := a.kafkaClient(m)
		if err != nil {
			return "", err
		}
		md, err := kadm.NewClient(cl).BrokerMetadata(ctx)
		if err != nil {
			a.mwPoolDrop(m.ID)
			return "", err
		}
		return fmt.Sprintf("连接成功，集群有 %d 个 Broker", len(md.Brokers)), nil
	case "rabbitmq":
		conn, err := a.rabbitDial(m)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		ver := ""
		if v, ok := conn.Properties["version"].(string); ok {
			ver = "，版本 " + v
		}
		return "连接成功" + ver, nil
	case "rocketmq":
		topics, err := a.rmqTopics(ctx, m)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("连接成功，NameServer 返回 %d 个业务 Topic", len(topics)), nil
	}
	return "", errors.New("未知的消息队列类型")
}

func (a *App) callMQ(ctx context.Context, c *mwCall, args map[string]any) (string, bool) {
	cfg := &c.m.Config
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.timeoutSec())*time.Second)
	defer cancel()
	topic := strings.TrimSpace(argStr(args, "topic"))
	perm := map[string]string{"mq_send": "send", "mq_peek": "consume", "mq_list_topics": "consume", "mq_create_topic": "admin"}[c.tool]
	c.action = strings.TrimPrefix(c.tool, "mq_") + " " + topic
	if c.tool == "mq_send" && cfg.MQKind == "rabbitmq" && argStr(args, "key") != "" {
		c.action += " routing_key=" + argStr(args, "key")
	}
	if msg, ok := c.need(perm); !ok {
		return msg, true
	}
	if c.tool != "mq_list_topics" {
		if err := cfg.checkTopic(topic); err != nil {
			msg := err.Error()
			if strings.HasPrefix(msg, "无权限：") {
				msg = fmt.Sprintf("无权限：中间件「%s」%s", c.m.Name, strings.TrimPrefix(msg, "无权限："))
			}
			return c.blocked(msg), true
		}
	}
	max := argInt(args, "max", 10)
	if max <= 0 {
		max = 10
	}
	if max > 100 {
		max = 100
	}
	bodyLimit := cfg.maxResultBytes() / max
	if bodyLimit > 64*1024 {
		bodyLimit = 64 * 1024
	}
	var res any
	var err error
	switch cfg.MQKind {
	case "kafka":
		res, err = a.kafkaOp(ctx, c, topic, args, max, bodyLimit)
	case "rabbitmq":
		res, err = a.rabbitOp(ctx, c, topic, args, max, bodyLimit)
	case "rocketmq":
		res, err = a.rmqOp(ctx, c, topic, args, max, bodyLimit)
	default:
		err = errors.New("未知的消息队列类型")
	}
	if err != nil {
		return c.done("", err)
	}
	if ts, ok := res.([]string); ok && len(cfg.Topics) > 0 {
		kept := []string{}
		for _, t := range ts {
			if cfg.checkTopic(t) == nil {
				kept = append(kept, t)
			}
		}
		res = kept
	}
	if ts, ok := res.([]string); ok {
		res = map[string]any{"topics": ts, "count": len(ts)}
	}
	if ms, ok := res.([]mqMessage); ok {
		res = map[string]any{"messages": ms, "count": len(ms)}
	}
	return c.done(jsonText(res), nil)
}

// ---------- Kafka (franz-go) ----------

func (a *App) kafkaOpts(m *Middleware) ([]kgo.Opt, error) {
	pw, err := a.mwPassword(m)
	if err != nil {
		return nil, err
	}
	c := m.Config
	opts := []kgo.Opt{kgo.SeedBrokers(strings.Split(c.Addrs, ",")...), kgo.DialTimeout(8 * time.Second),
		kgo.RequestTimeoutOverhead(5 * time.Second), kgo.ProduceRequestTimeout(10 * time.Second),
		kgo.RecordDeliveryTimeout(time.Duration(c.timeoutSec()) * time.Second), kgo.RequestRetries(2),
		kgo.ClientID("action2mcp")}
	if c.TLS {
		opts = append(opts, kgo.DialTLSConfig(&tls.Config{InsecureSkipVerify: c.TLSSkipVerify, MinVersion: tls.VersionTLS12}))
	}
	switch strings.ToUpper(c.SASL) {
	case "", "NONE":
	case "PLAIN":
		opts = append(opts, kgo.SASL(plain.Auth{User: c.User, Pass: pw}.AsMechanism()))
	case "SCRAM-SHA-256":
		opts = append(opts, kgo.SASL(scram.Auth{User: c.User, Pass: pw}.AsSha256Mechanism()))
	case "SCRAM-SHA-512":
		opts = append(opts, kgo.SASL(scram.Auth{User: c.User, Pass: pw}.AsSha512Mechanism()))
	default:
		return nil, errors.New("不支持的 SASL 机制：" + c.SASL)
	}
	return opts, nil
}

func (a *App) kafkaClient(m *Middleware) (*kgo.Client, error) {
	pw, err := a.mwPassword(m)
	if err != nil {
		return nil, err
	}
	key := m.cacheKey(pw)
	if v, ok := a.mwPool.Load(key); ok {
		return v.(*kgo.Client), nil
	}
	opts, err := a.kafkaOpts(m)
	if err != nil {
		return nil, err
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	a.mwPoolPut(m.ID, key, cl)
	return cl, nil
}

func (a *App) kafkaOp(ctx context.Context, c *mwCall, topic string, args map[string]any, max, bodyLimit int) (any, error) {
	cl, err := a.kafkaClient(c.m)
	if err != nil {
		return nil, err
	}
	adm := kadm.NewClient(cl)
	topicExists := func() error {
		td, err := adm.ListTopics(ctx, topic)
		if err != nil {
			return err
		}
		if d, ok := td[topic]; !ok || d.Err != nil {
			return fmt.Errorf("Topic %s 不存在（创建 Topic 需要「管理」权限，可用 mq_create_topic）", topic)
		}
		return nil
	}
	switch c.tool {
	case "mq_list_topics":
		td, err := adm.ListTopics(ctx)
		if err != nil {
			return nil, err
		}
		out := []string{}
		for _, d := range td.Sorted() {
			if !d.IsInternal && !strings.HasPrefix(d.Topic, "__") {
				out = append(out, d.Topic)
			}
		}
		return out, nil
	case "mq_create_topic":
		p := int32(argInt(args, "partitions", 1))
		if p <= 0 || p > 1000 {
			p = 1
		}
		r, err := adm.CreateTopic(ctx, p, -1, nil, topic)
		if err == nil {
			err = r.Err
		}
		if errors.Is(err, kerr.TopicAlreadyExists) {
			return map[string]any{"created": topic, "note": "topic 已存在，未做改动"}, nil
		}
		if err != nil {
			return nil, err
		}
		if r.Err != nil {
			if errors.Is(r.Err, kerr.TopicAlreadyExists) {
				return map[string]any{"created": topic, "note": "topic 已存在，未做改动"}, nil
			}
			return nil, r.Err
		}
		return map[string]any{"created": topic, "partitions": p}, nil
	case "mq_send":
		if err := topicExists(); err != nil {
			return nil, err
		}
		rec := &kgo.Record{Topic: topic, Value: []byte(argStr(args, "body"))}
		if k := argStr(args, "key"); k != "" {
			rec.Key = []byte(k)
		}
		r, err := cl.ProduceSync(ctx, rec).First()
		if err != nil {
			return nil, err
		}
		return map[string]any{"sent": true, "topic": topic, "partition": r.Partition, "offset": r.Offset}, nil
	case "mq_peek":
		if err := topicExists(); err != nil {
			return nil, err
		}
		starts, err := adm.ListStartOffsets(ctx, topic)
		if err != nil {
			return nil, err
		}
		ends, err := adm.ListEndOffsets(ctx, topic)
		if err != nil {
			return nil, err
		}
		want := map[int32]kgo.Offset{}
		total := int64(0)
		ends.Each(func(o kadm.ListedOffset) {
			if o.Topic != topic || o.Err != nil {
				return
			}
			st := int64(0)
			if s, ok := starts.Lookup(topic, o.Partition); ok && s.Err == nil {
				st = s.Offset
			}
			from := o.Offset - int64(max)
			if from < st {
				from = st
			}
			if o.Offset > from {
				want[o.Partition] = kgo.NewOffset().At(from)
				total += o.Offset - from
			}
		})
		msgs := []mqMessage{}
		if total == 0 {
			return msgs, nil
		}
		opts, _ := a.kafkaOpts(c.m)
		opts = append(opts, kgo.ConsumePartitions(map[string]map[int32]kgo.Offset{topic: want}))
		cc, err := kgo.NewClient(opts...)
		if err != nil {
			return nil, err
		}
		defer cc.Close()
		pctx, pcancel := context.WithTimeout(ctx, 6*time.Second)
		defer pcancel()
		got := int64(0)
		for got < total && pctx.Err() == nil {
			fs := cc.PollFetches(pctx)
			fs.EachRecord(func(r *kgo.Record) {
				got++
				p, off := r.Partition, r.Offset
				mm := mqMessage{Partition: &p, Offset: &off, Key: string(r.Key), Time: r.Timestamp.Format("2006-01-02 15:04:05"), Body: bodyText(r.Value, bodyLimit), ts: r.Timestamp}
				if len(r.Headers) > 0 {
					mm.Headers = map[string]string{}
					for _, h := range r.Headers {
						mm.Headers[h.Key] = bodyText(h.Value, 256)
					}
				}
				msgs = append(msgs, mm)
			})
			if errs := fs.Errors(); len(errs) > 0 && pctx.Err() == nil {
				return nil, errs[0].Err
			}
		}
		sort.SliceStable(msgs, func(i, j int) bool { return msgs[i].ts.Before(msgs[j].ts) })
		if len(msgs) > max {
			msgs = msgs[len(msgs)-max:]
		}
		return msgs, nil
	}
	return nil, errors.New("未知操作")
}

// ---------- RabbitMQ (amqp091) ----------

func (a *App) rabbitDial(m *Middleware) (*amqp.Connection, error) {
	pw, err := a.mwPassword(m)
	if err != nil {
		return nil, err
	}
	c := m.Config
	scheme := "amqp"
	cfg := amqp.Config{
		SASL:       []amqp.Authentication{&amqp.PlainAuth{Username: c.User, Password: pw}},
		Vhost:      c.Database,
		Dial:       amqp.DefaultDial(8 * time.Second),
		Properties: amqp.Table{"connection_name": "action2mcp"},
	}
	if cfg.Vhost == "" {
		cfg.Vhost = "/"
	}
	if c.TLS {
		scheme = "amqps"
		cfg.TLSClientConfig = &tls.Config{InsecureSkipVerify: c.TLSSkipVerify, MinVersion: tls.VersionTLS12}
	}
	// credentials are passed via SASL, never inside the URL
	return amqp.DialConfig(scheme+"://"+net.JoinHostPort(c.Host, fmt.Sprint(c.Port))+"/", cfg)
}

func (a *App) rabbitOp(ctx context.Context, c *mwCall, topic string, args map[string]any, max, bodyLimit int) (any, error) {
	if c.tool == "mq_list_topics" {
		return nil, errors.New("RabbitMQ 的 AMQP 协议不支持列出队列，请直接指定队列名（或在中间件里配置允许的队列，AI 会在工具说明里看到）")
	}
	conn, err := a.rabbitDial(c.m)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	defer ch.Close()
	switch c.tool {
	case "mq_create_topic":
		q, err := ch.QueueDeclare(topic, true, false, false, false, nil)
		if err != nil {
			return nil, err
		}
		return map[string]any{"created": q.Name, "durable": true}, nil
	case "mq_send":
		key := argStr(args, "key")
		exchange, rk := "", topic
		if key != "" {
			exchange, rk = topic, key
			if _, err := ch.QueueDeclarePassive(topic, false, false, false, false, nil); err == nil {
				// topic is a queue: publish directly to it, ignore key
				exchange, rk = "", topic
			} else {
				ch, err = conn.Channel()
				if err != nil {
					return nil, err
				}
				defer ch.Close()
				if err := ch.ExchangeDeclarePassive(topic, "direct", false, false, false, false, nil); err != nil {
					return nil, fmt.Errorf("队列或 exchange %s 不存在", topic)
				}
			}
		} else if _, err := ch.QueueDeclarePassive(topic, false, false, false, false, nil); err != nil {
			return nil, fmt.Errorf("队列 %s 不存在（创建队列需要「管理」权限，可用 mq_create_topic）", topic)
		}
		if err := ch.Confirm(false); err != nil {
			return nil, err
		}
		dc, err := ch.PublishWithDeferredConfirmWithContext(ctx, exchange, rk, false, false, amqp.Publishing{
			ContentType: "text/plain", DeliveryMode: amqp.Persistent, Body: []byte(argStr(args, "body")), Timestamp: time.Now(),
		})
		if err != nil {
			return nil, err
		}
		ok, err := dc.WaitContext(ctx)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("RabbitMQ 拒绝了这条消息（nack）")
		}
		out := map[string]any{"sent": true}
		if exchange == "" {
			out["queue"] = topic
		} else {
			out["exchange"], out["routing_key"] = exchange, rk
		}
		return out, nil
	case "mq_peek":
		q, err := ch.QueueDeclarePassive(topic, false, false, false, false, nil)
		if err != nil {
			return nil, fmt.Errorf("队列 %s 不存在", topic)
		}
		msgs := []mqMessage{}
		var last uint64
		for i := 0; i < max && i < q.Messages; i++ {
			d, ok, err := ch.Get(topic, false)
			if err != nil {
				return nil, err
			}
			if !ok {
				break
			}
			last = d.DeliveryTag
			mm := mqMessage{Key: d.RoutingKey, MsgID: d.MessageId, Body: bodyText(d.Body, bodyLimit)}
			if !d.Timestamp.IsZero() {
				mm.Time = d.Timestamp.Format("2006-01-02 15:04:05")
			}
			msgs = append(msgs, mm)
		}
		if last > 0 {
			if err := ch.Nack(last, true, true); err != nil {
				return nil, err
			}
		}
		return map[string]any{"messages": msgs, "count": len(msgs), "queue_depth": q.Messages, "note": "只查看队列头部的消息，已全部放回队列"}, nil
	}
	return nil, errors.New("未知操作")
}

// ---------- RocketMQ (rocketmq-client-go v2, remoting protocol via NameServer) ----------

var rmqAdminMu sync.Mutex

type rmqClients struct {
	mu   sync.Mutex
	prod rocketmq.Producer
	pull rocketmq.PullConsumer
}

func (r *rmqClients) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prod != nil {
		r.prod.Shutdown()
	}
	if r.pull != nil {
		p := r.pull
		// pending long-poll pulls finish within ~30s
		time.AfterFunc(35*time.Second, func() { p.Shutdown() })
	}
	return nil
}

func (a *App) rmqCreds(m *Middleware) (primitive.Credentials, error) {
	pw, err := a.mwPassword(m)
	if err != nil {
		return primitive.Credentials{}, err
	}
	return primitive.Credentials{AccessKey: m.Config.User, SecretKey: pw}, nil
}

func (a *App) rmqGet(m *Middleware) (*rmqClients, error) {
	pw, err := a.mwPassword(m)
	if err != nil {
		return nil, err
	}
	key := m.cacheKey(pw)
	if v, ok := a.mwPool.Load(key); ok {
		return v.(*rmqClients), nil
	}
	r := &rmqClients{}
	a.mwPoolPut(m.ID, key, r)
	return r, nil
}

func (a *App) withRmqAdmin(m *Middleware, f func(rmqadmin.Admin) error) error {
	cred, err := a.rmqCreds(m)
	if err != nil {
		return err
	}
	rmqAdminMu.Lock()
	defer rmqAdminMu.Unlock()
	opts := []rmqadmin.AdminOption{rmqadmin.WithResolver(primitive.NewPassthroughResolver(strings.Split(m.Config.Addrs, ",")))}
	if cred.AccessKey != "" {
		opts = append(opts, rmqadmin.WithCredentials(cred))
	}
	ad, err := rmqadmin.NewAdmin(opts...)
	if err != nil {
		return err
	}
	defer ad.Close()
	return f(ad)
}

func rmqSystemTopic(t string) bool {
	if strings.HasPrefix(t, "%RETRY%") || strings.HasPrefix(t, "%DLQ%") || strings.HasPrefix(t, "RMQ_SYS_") || strings.HasPrefix(t, "rmq_sys_") {
		return true
	}
	switch t {
	case "TBW102", "SCHEDULE_TOPIC_XXXX", "BenchmarkTest", "OFFSET_MOVED_EVENT", "SELF_TEST_TOPIC", "TRANS_CHECK_MAX_TIME_TOPIC":
		return true
	}
	return strings.HasSuffix(t, "_REPLY_TOPIC")
}

func (a *App) rmqTopics(ctx context.Context, m *Middleware) ([]string, error) {
	out := []string{}
	err := a.withRmqAdmin(m, func(ad rmqadmin.Admin) error {
		tl, err := ad.FetchAllTopicList(ctx)
		if err != nil {
			return err
		}
		sys := map[string]bool{}
		for _, t := range tl.TopicList {
			if rmqSystemTopic(t) || sys[t] {
				continue
			}
			out = append(out, t)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// cluster and broker names are also returned as topics; drop names that have no route
	sort.Strings(out)
	return out, nil
}

func (a *App) rmqQueues(ctx context.Context, m *Middleware, topic string) ([]*primitive.MessageQueue, error) {
	var qs []*primitive.MessageQueue
	err := a.withRmqAdmin(m, func(ad rmqadmin.Admin) error {
		var err error
		qs, err = ad.FetchPublishMessageQueues(ctx, topic)
		return err
	})
	if err != nil || len(qs) == 0 {
		return nil, fmt.Errorf("Topic %s 不存在（创建 Topic 需要「管理」权限，可用 mq_create_topic）", topic)
	}
	return qs, nil
}

func (a *App) rmqOp(ctx context.Context, c *mwCall, topic string, args map[string]any, max, bodyLimit int) (any, error) {
	m := c.m
	switch c.tool {
	case "mq_list_topics":
		return a.rmqTopics(ctx, m)
	case "mq_create_topic":
		broker := m.Config.BrokerAddr
		if broker == "" {
			host, _, _ := net.SplitHostPort(strings.Split(m.Config.Addrs, ",")[0])
			broker = net.JoinHostPort(host, "10911")
		}
		n := argInt(args, "partitions", 4)
		if n <= 0 || n > 64 {
			n = 4
		}
		err := a.withRmqAdmin(m, func(ad rmqadmin.Admin) error {
			return ad.CreateTopic(ctx, rmqadmin.WithTopicCreate(topic), rmqadmin.WithBrokerAddrCreate(broker), rmqadmin.WithReadQueueNums(n), rmqadmin.WithWriteQueueNums(n))
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{"created": topic, "queues": n, "broker": broker}, nil
	case "mq_send":
		if _, err := a.rmqQueues(ctx, m, topic); err != nil {
			return nil, err
		}
		r, err := a.rmqGet(m)
		if err != nil {
			return nil, err
		}
		cred, _ := a.rmqCreds(m)
		r.mu.Lock()
		if r.prod == nil {
			opts := []rmqproducer.Option{rmqproducer.WithNsResolver(primitive.NewPassthroughResolver(strings.Split(m.Config.Addrs, ","))),
				rmqproducer.WithRetry(1), rmqproducer.WithGroupName("action2mcp_producer"), rmqproducer.WithInstanceName(fmt.Sprintf("a2m_p_%d_%d", m.ID, time.Now().UnixNano())),
				rmqproducer.WithSendMsgTimeout(time.Duration(m.Config.timeoutSec()) * time.Second)}
			if cred.AccessKey != "" {
				opts = append(opts, rmqproducer.WithCredentials(cred))
			}
			p, err := rocketmq.NewProducer(opts...)
			if err == nil {
				err = p.Start()
			}
			if err != nil {
				r.mu.Unlock()
				return nil, err
			}
			r.prod = p
		}
		prod := r.prod
		r.mu.Unlock()
		msg := primitive.NewMessage(topic, []byte(argStr(args, "body")))
		if t := argStr(args, "tag"); t != "" {
			msg.WithTag(t)
		}
		if k := argStr(args, "key"); k != "" {
			msg.WithKeys([]string{k})
		}
		res, err := prod.SendSync(ctx, msg)
		if err != nil {
			return nil, err
		}
		if res.Status != primitive.SendOK {
			return nil, fmt.Errorf("发送状态异常：%d", res.Status)
		}
		return map[string]any{"sent": true, "topic": topic, "msg_id": res.MsgID, "queue": res.MessageQueue.QueueId, "offset": res.QueueOffset}, nil
	case "mq_peek":
		qs, err := a.rmqQueues(ctx, m, topic)
		if err != nil {
			return nil, err
		}
		r, err := a.rmqGet(m)
		if err != nil {
			return nil, err
		}
		cred, _ := a.rmqCreds(m)
		r.mu.Lock()
		if r.pull == nil {
			opts := []rmqconsumer.Option{rmqconsumer.WithNsResolver(primitive.NewPassthroughResolver(strings.Split(m.Config.Addrs, ","))),
				rmqconsumer.WithGroupName("action2mcp_peek"), rmqconsumer.WithInstance(fmt.Sprintf("a2m_c_%d_%d", m.ID, time.Now().UnixNano())),
				rmqconsumer.WithAutoCommit(false)}
			if cred.AccessKey != "" {
				opts = append(opts, rmqconsumer.WithCredentials(cred))
			}
			pc, err := rocketmq.NewPullConsumer(opts...)
			if err == nil {
				pc.Subscribe(topic, rmqconsumer.MessageSelector{})
				err = pc.Start()
			}
			if err != nil {
				r.mu.Unlock()
				return nil, err
			}
			r.pull = pc
		}
		pc := r.pull
		r.mu.Unlock()
		// Pull every queue in parallel. Empty queues are long-polled by the broker and simply time out here.
		var mu sync.Mutex
		msgs := []mqMessage{}
		var wg sync.WaitGroup
		for _, q := range qs {
			wg.Add(1)
			go func(q *primitive.MessageQueue) {
				defer wg.Done()
				res, err := pc.PullFrom(context.Background(), q, 0, 1)
				if err != nil || res == nil {
					return
				}
				from := res.MaxOffset - int64(max)
				if from < res.MinOffset {
					from = res.MinOffset
				}
				if res.MaxOffset <= from {
					return
				}
				res, err = pc.PullFrom(context.Background(), q, from, max)
				if err != nil || res == nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				for _, me := range res.GetMessageExts() {
					qid, off := q.QueueId, me.QueueOffset
					ts := time.UnixMilli(me.StoreTimestamp)
					msgs = append(msgs, mqMessage{Queue: &qid, Offset: &off, Key: me.GetKeys(), Tag: me.GetTags(), MsgID: me.MsgId,
						Time: ts.Format("2006-01-02 15:04:05"), Body: bodyText(me.Body, bodyLimit), ts: ts})
				}
			}(q)
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		case <-ctx.Done():
		}
		mu.Lock()
		out := append([]mqMessage{}, msgs...)
		mu.Unlock()
		sort.SliceStable(out, func(i, j int) bool { return out[i].ts.Before(out[j].ts) })
		if len(out) > max {
			out = out[len(out)-max:]
		}
		return out, nil
	}
	return nil, errors.New("未知操作")
}
