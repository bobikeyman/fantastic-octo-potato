// Package subs загружает подписки и приводит их тело к списку строк.
package subs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bobivpn/checker/internal/parse"
)

// MaxBodySize ограничивает размер одной подписки. Крупнейшие публичные
// источники укладываются в единицы мегабайт; всё сверх — либо ошибка,
// либо попытка забить память.
const MaxBodySize = 32 << 20

// Fetcher загружает подписки.
type Fetcher struct {
	Client *http.Client
	// UserAgent: часть источников отдаёт содержимое только клиентам VPN
	// и возвращает заглушку всем остальным.
	UserAgent string
	Retries   int
	Timeout   time.Duration
}

// NewFetcher создаёт загрузчик с разумными значениями по умолчанию.
func NewFetcher() *Fetcher {
	return &Fetcher{
		Client:    &http.Client{Timeout: 30 * time.Second},
		UserAgent: "v2rayNG/1.8.5",
		Retries:   3,
		Timeout:   30 * time.Second,
	}
}

// Result — итог загрузки одной подписки.
type Result struct {
	URL     string
	Body    string
	Lines   int
	Err     error
	Elapsed time.Duration
	// Base64 отмечает, что тело было завёрнуто в base64 целиком.
	Base64 bool
	// LooksLikeYAML отмечает Clash-подписку: ключей из неё сейчас не достать,
	// но молча возвращать ноль строк — хуже, чем сказать об этом.
	LooksLikeYAML bool
}

// Fetch загружает одну подписку с повторами.
func (f *Fetcher) Fetch(ctx context.Context, url string) Result {
	res := Result{URL: url}
	start := time.Now()
	defer func() { res.Elapsed = time.Since(start) }()

	retries := f.Retries
	if retries < 1 {
		retries = 1
	}

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		if attempt > 0 {
			// Линейная пауза: источники нередко отвечают 429 при частых обращениях.
			delay := time.Duration(attempt) * 2 * time.Second
			select {
			case <-ctx.Done():
				res.Err = ctx.Err()
				return res
			case <-time.After(delay):
			}
		}

		body, err := f.once(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}

		normalized, wasB64 := Normalize(body)
		res.Body = normalized
		res.Base64 = wasB64
		res.Lines = countKeyLines(normalized)
		res.LooksLikeYAML = res.Lines == 0 && looksLikeClashYAML(normalized)
		return res
	}

	res.Err = fmt.Errorf("после %d попыток: %w", retries, lastErr)
	return res
}

func (f *Fetcher) once(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := f.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("статус %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// FetchAll загружает подписки параллельно, сохраняя порядок.
func (f *Fetcher) FetchAll(ctx context.Context, urls []string, concurrency int) []Result {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]Result, len(urls))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, url := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, url string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = f.Fetch(ctx, url)
		}(i, url)
	}
	wg.Wait()
	return results
}

// Normalize приводит тело подписки к тексту со ссылками.
//
// Значительная часть источников отдаёт весь список одной base64-строкой.
func Normalize(body string) (text string, wasBase64 bool) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return "", false
	}
	// Уже обычный текст со ссылками — трогать нечего.
	if strings.Contains(trimmed, "://") {
		return trimmed, false
	}
	decoded, err := parse.DecodeBase64(trimmed)
	if err == nil && strings.Contains(string(decoded), "://") {
		return strings.TrimSpace(string(decoded)), true
	}
	return trimmed, false
}

func countKeyLines(text string) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "://") {
			n++
		}
	}
	return n
}

func looksLikeClashYAML(text string) bool {
	return strings.Contains(text, "proxies:") || strings.Contains(text, "proxy-groups:")
}

// LoadURLs собирает список подписок из файла и переменной окружения.
//
// Переменная нужна для приватных источников: класть их в публичный
// репозиторий нельзя.
func LoadURLs(file, envVar string) ([]string, error) {
	var raw []string

	if envVar != "" {
		if v := os.Getenv(envVar); strings.TrimSpace(v) != "" {
			raw = append(raw, strings.Split(v, "\n")...)
		}
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			if len(raw) == 0 {
				return nil, err
			}
		} else {
			raw = append(raw, strings.Split(string(data), "\n")...)
		}
	}

	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out, nil
}
