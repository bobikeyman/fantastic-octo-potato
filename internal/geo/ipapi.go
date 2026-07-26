// Package geo определяет провайдера и организацию по выходному адресу.
//
// Страна берётся не отсюда, а из ответа cdn-cgi/trace: он приходит по
// проверенному TLS в ходе самой проверки, то есть бесплатен и не подделывается
// нодой. Здесь нужен только провайдер — для человекочитаемых имён ключей.
package geo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Значения подобраны под бесплатный лимит ip-api.com: 100 адресов за запрос,
// не чаще 15 запросов в минуту.
const (
	batchSize     = 100
	batchEndpoint = "http://ip-api.com/batch?fields=status,query,country,countryCode,isp,org,as,asname"
	batchInterval = 4500 * time.Millisecond
)

// Info — сведения о выходном адресе.
type Info struct {
	IP          string `json:"query"`
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	AS          string `json:"as"`
	ASName      string `json:"asname"`
}

// Provider возвращает короткое имя провайдера для подписи ключа.
func (i Info) Provider() string {
	for _, candidate := range []string{i.ISP, i.Org, i.ASName} {
		if name := cleanProvider(candidate); name != "" {
			return name
		}
	}
	return "Server"
}

// Lookup — клиент пакетного определения провайдера.
type Lookup struct {
	Client   *http.Client
	Endpoint string
	// Interval — пауза между пакетами, чтобы не упереться в лимит частоты.
	Interval time.Duration
}

// NewLookup создаёт клиент с настройками под бесплатный лимит.
func NewLookup() *Lookup {
	return &Lookup{
		Client:   &http.Client{Timeout: 20 * time.Second},
		Endpoint: batchEndpoint,
		Interval: batchInterval,
	}
}

// Resolve определяет провайдеров для набора адресов.
//
// Запросы идут пакетами по сотне. Старый чекер спрашивал по одному адресу на
// ключ — на пяти тысячах ключей это гарантированно упиралось в лимит частоты,
// отчего сотни ключей оставались без страны.
//
// Ошибка сети не считается фатальной: без провайдера ключ просто получит
// подпись «Server», а публикация не должна срываться из-за косметики.
func (l *Lookup) Resolve(ctx context.Context, ips []string) map[string]Info {
	out := make(map[string]Info, len(ips))
	unique := dedupe(ips)

	for start := 0; start < len(unique); start += batchSize {
		end := min(start+batchSize, len(unique))
		chunk := unique[start:end]

		if start > 0 && l.Interval > 0 {
			select {
			case <-ctx.Done():
				return out
			case <-time.After(l.Interval):
			}
		}

		infos, err := l.batch(ctx, chunk)
		if err != nil {
			// Продолжаем: неопределившиеся адреса получат имя по умолчанию.
			continue
		}
		for _, info := range infos {
			if info.Status == "success" && info.IP != "" {
				out[info.IP] = info
			}
		}
	}
	return out
}

func (l *Lookup) batch(ctx context.Context, ips []string) ([]Info, error) {
	body, err := json.Marshal(ips)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := l.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("статус %d", resp.StatusCode)
	}
	var infos []Info
	if err := json.NewDecoder(resp.Body).Decode(&infos); err != nil {
		return nil, err
	}
	return infos, nil
}

func dedupe(ips []string) []string {
	seen := make(map[string]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

// Юридические суффиксы и служебные слова только занимают место в подписи ключа.
var providerNoise = []string{
	" LLC", " Ltd.", " Ltd", " Limited", " Inc.", " Inc", " GmbH", " B.V.",
	" S.A.", " SAS", " SARL", " AB", " AS", " Oy", " Corporation", " Corp.",
	" Corp", " Co.", " Company", " Networks", " Network", " Hosting",
	" Technologies", " Technology", " Solutions", " Services", " Group",
}

func cleanProvider(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// В поле as приезжает вида "AS13335 Cloudflare, Inc." — номер отбрасываем.
	if strings.HasPrefix(s, "AS") {
		if _, rest, ok := strings.Cut(s, " "); ok {
			s = rest
		}
	}
	for _, noise := range providerNoise {
		s = strings.TrimSuffix(s, noise)
		s = strings.TrimSuffix(s, strings.ToUpper(noise))
	}
	s = strings.Trim(s, " ,.-")

	// Длинные имена ломают вёрстку списка в клиентах.
	const maxLen = 24
	if len([]rune(s)) > maxLen {
		s = string([]rune(s)[:maxLen-1]) + "…"
	}
	return s
}
