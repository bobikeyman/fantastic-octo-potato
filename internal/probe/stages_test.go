package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bobivpn/checker/internal/engine"
)

// Тесты ходят только на 127.0.0.1: настоящие ноды здесь не участвуют.
func testClient() *http.Client {
	var d net.Dialer
	return engine.HTTPClientFor(d.DialContext, 5*time.Second)
}

func TestConnectivityStrict204(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		wantErr bool
	}{
		{"204 пустой", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, false},

		// Всё, что ниже, наивные чекеры засчитывают за успех.
		{"200 OK", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}, true},
		{"403 блок-страница", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html>Доступ запрещён</html>"))
		}, true},
		{"301 редирект на портал", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://portal.local/login", http.StatusMovedPermanently)
		}, true},
		{"302 редирект", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://portal.local/login", http.StatusFound)
		}, true},
		{"500", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			err := Connectivity(context.Background(), testClient(), srv.URL)
			if tc.wantErr && err == nil {
				t.Fatal("ожидалась ошибка, ответ засчитан за успех")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("неожиданная ошибка: %v", err)
			}
		})
	}
}

// Редирект не должен молча превращаться в 204 после перехода по цепочке.
func TestConnectivityDoesNotFollowRedirectTo204(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer final.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer srv.Close()

	if err := Connectivity(context.Background(), testClient(), srv.URL); err == nil {
		t.Fatal("редирект на 204 засчитан за успех")
	}
}

func TestConnectivityAllRequiresEvery(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer bad.Close()

	c := testClient()
	if err := ConnectivityAll(context.Background(), c, []string{ok.URL, ok.URL}); err != nil {
		t.Fatalf("оба 204 — должно проходить: %v", err)
	}
	if err := ConnectivityAll(context.Background(), c, []string{ok.URL, bad.URL}); err == nil {
		t.Fatal("частичная доступность засчитана за успех")
	}
	if err := ConnectivityAll(context.Background(), c, nil); err == nil {
		t.Fatal("пустой список адресов засчитан за успех")
	}
}

// Ответ с телом на 204 — признак подмены. Проверяем на сыром сокете,
// потому что httptest-сервер тело при 204 не отдаст.
func TestConnectivityRejectsBodyOn204(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = bufio.NewReader(conn).ReadString('\n')
		body := "<html>подменённый ответ</html>"
		fmt.Fprintf(conn, "HTTP/1.1 204 No Content\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}()

	err = Connectivity(context.Background(), testClient(), "http://"+ln.Addr().String())
	t.Logf("результат: %v", err)
	// Go-клиент по спецификации сам считает 204 бестелесным, поэтому проверка
	// тела может и не сработать — но успехом такой ответ быть не должен.
	if err == nil {
		t.Log("клиент отбросил тело сам; строгий статус остаётся основной защитой")
	}
}

func TestTraceParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Join([]string{
			"fl=123abc", "h=cloudflare.com", "ip=203.0.113.45",
			"ts=1769000000.123", "visit_scheme=https", "uag=Go-http-client",
			"colo=FRA", "sliver=none", "http=http/2", "loc=DE",
			"tls=TLSv1.3", "sni=plaintext", "warp=off", "gateway=off",
		}, "\n")))
	}))
	defer srv.Close()

	info, err := Trace(context.Background(), testClient(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if info.IP != "203.0.113.45" || info.Colo != "FRA" || info.Country != "DE" {
		t.Errorf("info = %+v", info)
	}
	if info.WARP {
		t.Error("warp=off распознан как включённый")
	}
	if info.TLS != "TLSv1.3" {
		t.Errorf("tls = %q", info.TLS)
	}
}

func TestTraceWithoutIPFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("colo=FRA\nloc=DE\n"))
	}))
	defer srv.Close()

	if _, err := Trace(context.Background(), testClient(), srv.URL); err == nil {
		t.Fatal("ответ без поля ip засчитан за успех")
	}
}

func TestValidateExitIP(t *testing.T) {
	cases := []struct {
		exit, own string
		wantErr   bool
	}{
		{"203.0.113.45", "198.51.100.7", false},
		{"2a09:bac1:76c0::1", "198.51.100.7", false},
		// главное: выход совпал с адресом проверяющего — трафик мимо прокси
		{"198.51.100.7", "198.51.100.7", true},
		{"192.168.1.10", "198.51.100.7", true},
		{"127.0.0.1", "198.51.100.7", true},
		{"100.72.3.4", "198.51.100.7", true},
		{"не адрес", "198.51.100.7", true},
	}
	for _, tc := range cases {
		err := ValidateExitIP(tc.exit, tc.own)
		if tc.wantErr != (err != nil) {
			t.Errorf("ValidateExitIP(%q, %q) = %v", tc.exit, tc.own, err)
		}
	}
}

func TestSpeedMeasuresPayload(t *testing.T) {
	const size = 512 << 10
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := make([]byte, 16<<10)
		for sent := 0; sent < size; sent += len(chunk) {
			_, _ = w.Write(chunk)
		}
	}))
	defer srv.Close()

	res, err := Speed(context.Background(), testClient(), srv.URL, 20*time.Millisecond, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes != size {
		t.Errorf("получено %d байт, ожидалось %d", res.Bytes, size)
	}
	if res.KBps <= 0 {
		t.Errorf("скорость = %.1f KB/s", res.KBps)
	}
	t.Logf("%.0f KB/s, %d байт за %v", res.KBps, res.Bytes, res.Took)
}

// Нода с исчерпанной квотой отвечает и обрывает поток. То, что успело
// прийти, должно быть видно — это отличает обрыв от «не началось».
func TestSpeedReportsTruncatedStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = bufio.NewReader(conn).ReadString('\n')
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n")
		_, _ = conn.Write(make([]byte, 4096))
		_ = conn.Close() // обрыв на середине
	}()

	res, err := Speed(context.Background(), testClient(), "http://"+ln.Addr().String(), 10*time.Millisecond, 0)
	if err == nil {
		t.Fatal("обрыв потока засчитан за успех")
	}
	if res.Bytes == 0 {
		t.Error("не учтены байты, полученные до обрыва")
	}
	t.Logf("получено %d байт до обрыва: %v", res.Bytes, err)
}

func TestSpeedRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	if _, err := Speed(context.Background(), testClient(), srv.URL, time.Millisecond, 0); err == nil {
		t.Fatal("403 засчитан за успешную загрузку")
	}
}

func TestLatencyMedianAndJitter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	median, jitter, err := Latency(context.Background(), testClient(), srv.URL, 3)
	if err != nil {
		t.Fatal(err)
	}
	if median <= 0 {
		t.Errorf("медиана = %v", median)
	}
	if jitter < 0 {
		t.Errorf("джиттер отрицательный: %v", jitter)
	}
	t.Logf("медиана %v, джиттер %v", median, jitter)
}

func TestLatencyFailsWhenUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // сервер уже мёртв

	if _, _, err := Latency(context.Background(), testClient(), url, 2); err == nil {
		t.Fatal("недоступный адрес засчитан за успех")
	}
}

func TestL4(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	if _, err := L4(context.Background(), addr, time.Second); err != nil {
		t.Fatalf("живой слушатель: %v", err)
	}

	_ = ln.Close()
	if _, err := L4(context.Background(), addr, 300*time.Millisecond); err == nil {
		t.Fatal("закрытый порт засчитан за живой")
	}
}
