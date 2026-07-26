package subs

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testFetcher(t *testing.T) *Fetcher {
	t.Helper()
	f := NewFetcher()
	f.Retries = 2
	f.Timeout = 3 * time.Second
	f.Client = &http.Client{Timeout: 3 * time.Second}
	return f
}

func TestNormalizePlainText(t *testing.T) {
	body := "vless://uuid@host:443#a\nvmess://abc\n"
	got, wasB64 := Normalize(body)
	if wasB64 {
		t.Error("обычный текст помечен как base64")
	}
	if !strings.Contains(got, "vless://") {
		t.Errorf("тело потеряно: %q", got)
	}
}

// Значительная часть источников отдаёт весь список одной base64-строкой.
func TestNormalizeBase64Body(t *testing.T) {
	inner := "vless://uuid@host:443#a\ntrojan://pw@host:443#b"
	for name, enc := range map[string]string{
		"Std":    base64.StdEncoding.EncodeToString([]byte(inner)),
		"RawStd": base64.RawStdEncoding.EncodeToString([]byte(inner)),
		"URL":    base64.URLEncoding.EncodeToString([]byte(inner)),
	} {
		t.Run(name, func(t *testing.T) {
			got, wasB64 := Normalize(enc)
			if !wasB64 {
				t.Error("base64-тело не распознано")
			}
			if got != inner {
				t.Errorf("раскодировано неверно: %q", got)
			}
		})
	}
}

func TestNormalizeGarbageStaysAsIs(t *testing.T) {
	got, wasB64 := Normalize("совершенно не подписка")
	if wasB64 {
		t.Error("мусор помечен как base64")
	}
	if got == "" {
		t.Error("тело затёрто")
	}
}

func TestFetchPlain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://a@h:443#1\nvless://b@h:443#2\n# комментарий\n"))
	}))
	defer srv.Close()

	res := testFetcher(t).Fetch(context.Background(), srv.URL)
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if res.Lines != 2 {
		t.Errorf("строк с ключами = %d, ожидалось 2", res.Lines)
	}
}

// User-Agent значим: часть источников отдаёт список только клиентам VPN.
func TestFetchSendsUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.UserAgent()
		_, _ = w.Write([]byte("vless://a@h:443#1"))
	}))
	defer srv.Close()

	f := testFetcher(t)
	f.UserAgent = "v2rayNG/1.8.5"
	if res := f.Fetch(context.Background(), srv.URL); res.Err != nil {
		t.Fatal(res.Err)
	}
	if got != "v2rayNG/1.8.5" {
		t.Errorf("User-Agent = %q", got)
	}
}

func TestFetchRetriesThenSucceeds(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt64(&hits, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("vless://a@h:443#1"))
	}))
	defer srv.Close()

	f := testFetcher(t)
	f.Retries = 3
	res := f.Fetch(context.Background(), srv.URL)
	if res.Err != nil {
		t.Fatalf("повтор не спас: %v", res.Err)
	}
	if atomic.LoadInt64(&hits) < 2 {
		t.Error("повтор не выполнялся")
	}
}

func TestFetchFailsOnPersistentError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res := testFetcher(t).Fetch(context.Background(), srv.URL)
	if res.Err == nil {
		t.Fatal("404 засчитан за успех")
	}
}

// Clash-подписку сейчас не разобрать, но молча вернуть ноль строк хуже,
// чем отметить это в результате.
func TestFetchDetectsClashYAML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("proxies:\n  - name: node1\n    type: vmess\n"))
	}))
	defer srv.Close()

	res := testFetcher(t).Fetch(context.Background(), srv.URL)
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if !res.LooksLikeYAML {
		t.Error("Clash-подписка не распознана")
	}
}

func TestFetchAllPreservesOrder(t *testing.T) {
	mk := func(payload string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(payload))
		}))
	}
	a, b, c := mk("vless://a@h:443#a"), mk("vless://b@h:443#b"), mk("vless://c@h:443#c")
	defer a.Close()
	defer b.Close()
	defer c.Close()

	urls := []string{a.URL, b.URL, c.URL}
	results := testFetcher(t).FetchAll(context.Background(), urls, 3)

	if len(results) != 3 {
		t.Fatalf("результатов %d", len(results))
	}
	for i, want := range []string{"#a", "#b", "#c"} {
		if results[i].Err != nil {
			t.Fatalf("%d: %v", i, results[i].Err)
		}
		if !strings.Contains(results[i].Body, want) {
			t.Errorf("порядок нарушен на позиции %d: %q", i, results[i].Body)
		}
		if results[i].URL != urls[i] {
			t.Errorf("URL на позиции %d = %q", i, results[i].URL)
		}
	}
}

func TestLoadURLs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "subscriptions.txt")
	content := strings.Join([]string{
		"# комментарий",
		"",
		"https://example.com/a.txt",
		"https://example.com/b.txt",
		"https://example.com/a.txt", // дубль
		"не-ссылка",
		"  https://example.com/c.txt  ",
	}, "\n")
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	urls, err := LoadURLs(file, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://example.com/a.txt",
		"https://example.com/b.txt",
		"https://example.com/c.txt",
	}
	if len(urls) != len(want) {
		t.Fatalf("получено %d ссылок: %v", len(urls), urls)
	}
	for i := range want {
		if urls[i] != want[i] {
			t.Errorf("%d: %q, ожидалось %q", i, urls[i], want[i])
		}
	}
}

// Приватные подписки приходят переменной окружения: класть их
// в публичный репозиторий нельзя.
func TestLoadURLsMergesEnv(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "subscriptions.txt")
	if err := os.WriteFile(file, []byte("https://example.com/public.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_SUBS", "https://example.com/private.txt\nhttps://example.com/public.txt\n")

	urls, err := LoadURLs(file, "TEST_SUBS")
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 2 {
		t.Fatalf("ожидалось 2 уникальных ссылки, получено %d: %v", len(urls), urls)
	}
}

func TestLoadURLsMissingFileWithEnv(t *testing.T) {
	t.Setenv("TEST_SUBS", "https://example.com/private.txt")
	urls, err := LoadURLs(filepath.Join(t.TempDir(), "нет-такого.txt"), "TEST_SUBS")
	if err != nil {
		t.Fatalf("переменная окружения должна спасать: %v", err)
	}
	if len(urls) != 1 {
		t.Fatalf("получено %v", urls)
	}
}
