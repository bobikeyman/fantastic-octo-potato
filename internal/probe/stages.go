// Package probe содержит отдельные стадии проверки ноды.
//
// Каждая стадия принимает готовый *http.Client, а не сессию движка, — так их
// можно покрыть тестами на локальном httptest-сервере, не поднимая ядро
// и не трогая настоящие ноды.
package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// L4 — TCP-дозвон до сервера ноды напрямую, без прокси.
//
// Дешёвый предварительный фильтр: отсекает мёртвые эндпоинты до того, как
// на них будет потрачено поднятие ядра и TLS-хендшейк.
func L4(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	_ = conn.Close()
	return elapsed, nil
}

// Connectivity требует от эндпоинта строго 204 с пустым телом.
//
// Именно эта строгость отсекает основную массу ложных срабатываний:
// наивные чекеры засчитывают за успех любой ответ, включая 403 от блок-страницы
// и редирект на портал провайдера.
func Connectivity(ctx context.Context, c *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("статус %d, ожидался 204", resp.StatusCode)
	}
	// Подстраховка. Сработать она почти не может: Go-клиент по спецификации
	// сам считает 204 бестелесным. Настоящая защита от подменённого ответа —
	// это строгий статус выше и проверка TLS-сертификата на уровне клиента:
	// нода не предъявит валидный сертификат для чужого домена.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return fmt.Errorf("чтение тела: %w", err)
	}
	if len(body) > 0 {
		return fmt.Errorf("204 с непустым телом (%d байт) — ответ подменён", len(body))
	}
	return nil
}

// ConnectivityAll требует успеха от ВСЕХ адресов.
//
// Адреса намеренно берутся из разных ASN: нода, у которой доступен только
// один из них, режет трафик выборочно и полноценной не является.
func ConnectivityAll(ctx context.Context, c *http.Client, urls []string) error {
	if len(urls) == 0 {
		return errors.New("не задано ни одного адреса проверки")
	}
	for _, u := range urls {
		if err := Connectivity(ctx, c, u); err != nil {
			return fmt.Errorf("%s: %w", u, err)
		}
	}
	return nil
}

// TraceInfo — разбор ответа cdn-cgi/trace.
type TraceInfo struct {
	IP      string // выходной адрес ноды
	Colo    string // дата-центр Cloudflare, принявший запрос
	Country string // страна выходного адреса по версии Cloudflare
	WARP    bool
	TLS     string
}

// Trace получает выходной адрес одним TLS-верифицированным запросом.
//
// Против ip-api.com у этого способа два преимущества: ответ отдаётся по
// проверяемому TLS (подменить его нода не может) и в нём сразу приезжают
// colo и страна, то есть на ключ уходит один запрос вместо двух.
func Trace(ctx context.Context, c *http.Client, url string) (TraceInfo, error) {
	var info TraceInfo

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return info, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("статус %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return info, err
	}

	for _, line := range strings.Split(string(body), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "ip":
			info.IP = val
		case "colo":
			info.Colo = val
		case "loc":
			info.Country = val
		case "warp":
			info.WARP = val == "on" || val == "plus"
		case "tls":
			info.TLS = val
		}
	}
	if info.IP == "" {
		return info, errors.New("в ответе нет поля ip")
	}
	return info, nil
}

// ValidateExitIP проверяет, что выходной адрес осмысленный.
//
// Совпадение с адресом раннера означает, что трафик пошёл мимо прокси —
// а такой ключ бесполезен, даже если всё остальное ответило.
func ValidateExitIP(exit, own string) error {
	addr, err := netip.ParseAddr(strings.TrimSpace(exit))
	if err != nil {
		return fmt.Errorf("выходной адрес %q не разобран", exit)
	}
	if own != "" && addr.String() == strings.TrimSpace(own) {
		return errors.New("выходной адрес совпадает с адресом проверяющего: трафик идёт мимо прокси")
	}
	switch {
	case addr.IsLoopback():
		return errors.New("выходной адрес — loopback")
	case addr.IsPrivate():
		return errors.New("выходной адрес приватный")
	case addr.IsUnspecified():
		return errors.New("выходной адрес нулевой")
	}
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return errors.New("выходной адрес из диапазона CGNAT")
		}
	}
	return nil
}

// Latency измеряет время до первого байта ответа ЧЕРЕЗ прокси.
//
// Наивные чекеры меряют TCP-хендшейк с раннера до сервера напрямую и потом
// сортируют по нему выдачу — это число не имеет отношения к тому, что
// почувствует пользователь.
func Latency(ctx context.Context, c *http.Client, url string, samples int) (median, jitter time.Duration, err error) {
	if samples < 1 {
		samples = 1
	}
	got := make([]time.Duration, 0, samples)

	for i := 0; i < samples; i++ {
		d, err := ttfb(ctx, c, url)
		if err != nil {
			// Одна неудачная проба из нескольких — не приговор,
			// но хотя бы одна обязана пройти.
			continue
		}
		got = append(got, d)
	}
	if len(got) == 0 {
		return 0, 0, errors.New("ни одна проба задержки не прошла")
	}

	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	median = got[len(got)/2]
	jitter = got[len(got)-1] - got[0]
	return median, jitter, nil
}

func ttfb(ctx context.Context, c *http.Client, url string) (time.Duration, error) {
	var first time.Time
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { first = time.Now() },
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64))

	if first.IsZero() {
		return time.Since(start), nil
	}
	return first.Sub(start), nil
}

// SpeedResult — итог замера пропускной способности.
type SpeedResult struct {
	KBps  float64
	Bytes int64
	Took  time.Duration
}

// Speed качает файл и считает установившуюся скорость.
//
// Начальный участок отбрасывается: на нём идёт TLS-хендшейк и разгон
// TCP-окна, и по нему скорость выходит заниженной в разы. Именно поэтому
// замер на файле в килобайт, как делают наивные чекеры, не измеряет ничего.
//
// Длинная загрузка попутно ловит ноды с исчерпанной квотой: хендшейк у них
// проходит, а поток обрывается через пару сотен килобайт.
func Speed(ctx context.Context, c *http.Client, url string, warmup time.Duration, limit int64) (SpeedResult, error) {
	var res SpeedResult

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return res, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("статус %d", resp.StatusCode)
	}

	var (
		start      = time.Now()
		buf        = make([]byte, 32<<10)
		total      int64
		markTime   time.Time
		markBytes  int64
		markedDone bool
		reader     io.Reader = resp.Body
	)
	if limit > 0 {
		reader = io.LimitReader(resp.Body, limit)
	}

	for {
		n, readErr := reader.Read(buf)
		total += int64(n)

		if !markedDone && time.Since(start) >= warmup {
			markTime, markBytes, markedDone = time.Now(), total, true
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			// Обрыв на середине — сам по себе диагноз, но то, что успело
			// прийти, всё равно возвращаем: это отличает «оборвалось на 200 КБ»
			// от «не началось вовсе».
			res.Bytes, res.Took = total, time.Since(start)
			return res, fmt.Errorf("поток оборван после %d байт: %w", total, readErr)
		}
		if ctx.Err() != nil {
			res.Bytes, res.Took = total, time.Since(start)
			return res, ctx.Err()
		}
	}

	res.Bytes = total
	res.Took = time.Since(start)

	// Если загрузка целиком уложилась в разгонный участок, считаем по всей
	// длине: занижение лучше, чем деление на ноль.
	measuredBytes, measuredTime := total, res.Took
	if markedDone {
		if d := time.Since(markTime); d > 0 && total > markBytes {
			measuredBytes, measuredTime = total-markBytes, d
		}
	}
	if measuredTime <= 0 || measuredBytes <= 0 {
		return res, errors.New("нечего измерять: пустой ответ")
	}
	res.KBps = float64(measuredBytes) / 1024 / measuredTime.Seconds()
	return res, nil
}
