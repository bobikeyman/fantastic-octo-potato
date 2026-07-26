package probe

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/bobivpn/checker/internal/engine"
	"github.com/bobivpn/checker/internal/model"
)

// Stage — стадия, на которой проверка остановилась.
type Stage string

const (
	StageL4           Stage = "l4"
	StageOpen         Stage = "open"
	StageConnectivity Stage = "connectivity"
	StageTrace        Stage = "trace"
	StageExitIP       Stage = "exit_ip"
	StageLatency      Stage = "latency"
	StageSpeed        Stage = "speed"
	StageDone         Stage = "done"
)

// Config — пороги одной проверки.
type Config struct {
	SkipL4       bool
	L4Timeout    time.Duration
	ProbeTimeout time.Duration

	ConnectivityURLs []string
	TraceURL         string

	LatencySamples int
	MaxLatency     time.Duration
	MaxJitter      time.Duration

	SpeedURL     string
	SpeedWarmup  time.Duration
	SpeedLimit   int64
	SpeedTimeout time.Duration
	MinSpeedKBps float64

	// OwnIP — адрес проверяющего. Нужен, чтобы поймать ключи, у которых
	// трафик идёт мимо прокси.
	OwnIP string
}

// DefaultConfig — пороги по умолчанию, согласованные с configs/checker.yaml.
func DefaultConfig() Config {
	return Config{
		L4Timeout:    3 * time.Second,
		ProbeTimeout: 8 * time.Second,
		ConnectivityURLs: []string{
			"https://cp.cloudflare.com/generate_204",
			"https://www.gstatic.com/generate_204",
		},
		TraceURL:       "https://cloudflare.com/cdn-cgi/trace",
		LatencySamples: 3,
		MaxLatency:     2 * time.Second,
		MaxJitter:      500 * time.Millisecond,
		SpeedURL:       "https://speed.cloudflare.com/__down?bytes=3000000",
		SpeedWarmup:    200 * time.Millisecond,
		SpeedLimit:     3 << 20,
		SpeedTimeout:   20 * time.Second,
		MinSpeedKBps:   200,
	}
}

// Result — итог проверки одной ноды.
type Result struct {
	Fingerprint string      `json:"fp"`
	Raw         string      `json:"raw"`
	Node        *model.Node `json:"-"`

	OK    bool       `json:"ok"`
	Tier  model.Tier `json:"tier,omitempty"`
	Stage Stage      `json:"stage"`
	Error string     `json:"error,omitempty"`

	L4LatencyMs int `json:"l4_latency_ms,omitempty"`

	ExitIP      string `json:"exit_ip,omitempty"`
	ExitColo    string `json:"exit_colo,omitempty"`
	ExitCountry string `json:"exit_country,omitempty"`
	WARP        bool   `json:"warp,omitempty"`

	LatencyMs int     `json:"latency_ms,omitempty"`
	JitterMs  int     `json:"jitter_ms,omitempty"`
	SpeedKBps float64 `json:"speed_kbps,omitempty"`
	SpeedByte int64   `json:"speed_bytes,omitempty"`

	CheckedAt time.Time `json:"checked_at"`
}

// Check прогоняет ноду через все стадии.
//
// Основной проход идёт со строгой проверкой сертификата. Если нода на нём
// отвалилась, но сама просит allowInsecure, делается второй проход с
// ослабленной проверкой — результат уходит в корзину tier=insecure,
// а не в общую выдачу.
func Check(ctx context.Context, eng engine.Engine, n *model.Node, cfg Config) Result {
	res := attempt(ctx, eng, n, cfg, false)
	if res.OK {
		res.Tier = model.TierMain
		return res
	}
	// Пересдача имеет смысл только если ключ действительно просит
	// ослабленную проверку и провалился уже после L4.
	if !n.AllowInsecure || res.Stage == StageL4 {
		return res
	}
	relaxed := attempt(ctx, eng, n, cfg, true)
	if relaxed.OK {
		relaxed.Tier = model.TierInsecure
		return relaxed
	}
	return res
}

func attempt(ctx context.Context, eng engine.Engine, n *model.Node, cfg Config, allowInsecure bool) Result {
	res := Result{
		Fingerprint: n.Fingerprint(),
		Raw:         n.Raw,
		Node:        n,
		CheckedAt:   time.Now().UTC(),
	}
	fail := func(stage Stage, err error) Result {
		res.Stage = stage
		res.Error = err.Error()
		res.OK = false
		return res
	}

	// --- Стадия 1: L4 ---
	if !cfg.SkipL4 {
		d, err := L4(ctx, n.Endpoint(), cfg.L4Timeout)
		if err != nil {
			return fail(StageL4, err)
		}
		res.L4LatencyMs = int(d.Milliseconds())
	}

	// --- Поднятие ядра ---
	sess, err := eng.Open(n, engine.Options{AllowInsecure: allowInsecure})
	if err != nil {
		return fail(StageOpen, err)
	}
	defer sess.Close()

	client := sess.HTTPClient(cfg.ProbeTimeout)

	// --- Стадия 2: связность ---
	if err := ConnectivityAll(ctx, client, cfg.ConnectivityURLs); err != nil {
		return fail(StageConnectivity, err)
	}

	// --- Стадия 2b: выходной адрес ---
	info, err := Trace(ctx, client, cfg.TraceURL)
	if err != nil {
		return fail(StageTrace, err)
	}
	res.ExitIP, res.ExitColo, res.ExitCountry, res.WARP = info.IP, info.Colo, info.Country, info.WARP

	if err := ValidateExitIP(info.IP, cfg.OwnIP); err != nil {
		return fail(StageExitIP, err)
	}

	// --- Стадия 3a: задержка ---
	median, jitter, err := Latency(ctx, client, cfg.ConnectivityURLs[0], cfg.LatencySamples)
	if err != nil {
		return fail(StageLatency, err)
	}
	res.LatencyMs = int(median.Milliseconds())
	res.JitterMs = int(jitter.Milliseconds())

	if cfg.MaxLatency > 0 && median > cfg.MaxLatency {
		return fail(StageLatency, fmt.Errorf("задержка %v выше порога %v", median, cfg.MaxLatency))
	}
	if cfg.MaxJitter > 0 && jitter > cfg.MaxJitter {
		return fail(StageLatency, fmt.Errorf("джиттер %v выше порога %v", jitter, cfg.MaxJitter))
	}

	// --- Стадия 3b: скорость ---
	speedCtx, cancel := context.WithTimeout(ctx, cfg.SpeedTimeout)
	defer cancel()

	speedClient := sess.HTTPClient(cfg.SpeedTimeout)
	sp, err := Speed(speedCtx, speedClient, cfg.SpeedURL, cfg.SpeedWarmup, cfg.SpeedLimit)
	res.SpeedKBps, res.SpeedByte = sp.KBps, sp.Bytes
	if err != nil {
		return fail(StageSpeed, err)
	}
	if cfg.MinSpeedKBps > 0 && sp.KBps < cfg.MinSpeedKBps {
		return fail(StageSpeed, fmt.Errorf("скорость %.1f KB/s ниже порога %.0f KB/s",
			sp.KBps, cfg.MinSpeedKBps))
	}

	res.Stage = StageDone
	res.OK = true
	return res
}

// OwnIP узнаёт собственный выходной адрес — напрямую, без прокси.
//
// Без него нельзя отличить рабочий туннель от ключа, у которого трафик
// уходит мимо прокси и возвращает адрес самого проверяющего.
func OwnIP(ctx context.Context, traceURL string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	info, err := Trace(ctx, client, traceURL)
	if err != nil {
		return "", err
	}
	return info.IP, nil
}
