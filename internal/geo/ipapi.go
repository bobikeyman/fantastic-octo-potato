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

// Организационно-правовые формы. Идут и в начале имени, и в конце —
// зависит от страны регистрации.
var legalForms = []string{
	"llc", "ltd", "limited", "inc", "gmbh", "bv", "b.v", "sa", "s.a", "sas",
	"sarl", "srl", "ab", "oy", "as", "a.s", "plc", "pte", "pvt", "corp",
	"corporation", "co", "company", "jsc", "pjsc", "ojsc", "cjsc", "zao",
	"ooo", "oao", "ao", "ip", "spa", "sp", "kg", "ug", "nv", "n.v", "aps",
	"doo", "d.o.o", "sh.p.k", "eood", "ead", "sro", "s.r.o",
}

var legalFormSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(legalForms))
	for _, f := range legalForms {
		m[f] = struct{}{}
	}
	return m
}()

// Слова, которые есть почти у каждого хостера и ничего не различают.
var genericWords = map[string]struct{}{
	"networks": {}, "network": {}, "hosting": {}, "technologies": {},
	"technology": {}, "solutions": {}, "solution": {}, "services": {},
	"service": {}, "group": {}, "holding": {}, "international": {},
	"communications": {}, "communication": {}, "telecom": {},
	"telecommunications": {}, "systems": {}, "system": {}, "internet": {},
	"datacenter": {}, "data": {}, "center": {}, "cloud": {}, "host": {},
	"provider": {}, "global": {}, "digital": {}, "online": {}, "web": {},
	"computer": {}, "computing": {}, "infrastructure": {}, "enterprise": {},
	"company": {}, "corp": {},
	// Предлоги и артикли: без них имя не теряет смысла, но занимает
	// заметно меньше места.
	"of": {}, "the": {}, "and": {}, "for": {}, "de": {}, "du": {},
}

// cleanProvider приводит сырое имя из ip-api к короткой подписи.
//
// Сырые значения приходят в самом разном виде: «JSC "TIMEWEB"», «Selectel»,
// «AS13335 Cloudflare, Inc.», иногда — вообще URL геофида. Без нормализации
// один и тот же провайдер попадает в список под разными именами и получает
// независимую нумерацию.
func cleanProvider(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || looksLikeURL(s) {
		return ""
	}

	// В поле as приезжает «AS13335 Cloudflare, Inc.» — номер отбрасываем.
	if rest, ok := strings.CutPrefix(s, "AS"); ok {
		if head, tail, found := strings.Cut(rest, " "); found && isDigits(head) {
			s = tail
		}
	}

	// Кавычки вокруг названия ставят в основном в СНГ: «JSC "TIMEWEB"».
	s = strings.Map(func(r rune) rune {
		switch r {
		case '"', '«', '»', '\'', '`', '“', '”':
			return -1
		}
		return r
	}, s)

	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	})

	kept := make([]string, 0, len(words))
	for _, w := range words {
		bare := strings.ToLower(strings.Trim(w, ".,-()"))
		if bare == "" {
			continue
		}
		if _, isLegal := legalFormSet[bare]; isLegal {
			continue
		}
		kept = append(kept, strings.Trim(w, ",.()"))
	}

	// Если после чистки ничего не осталось — имя состояло из одних
	// служебных слов; лучше вернуть исходное, чем пустоту.
	if len(kept) == 0 {
		kept = words
	}

	// Слишком длинное имя обрезаем по словам, а не по символам: обрывок
	// вида «Cloud Technologies LL…» выглядит как ошибка.
	const maxLen = 22
	result := strings.Join(kept, " ")
	if len([]rune(result)) > maxLen {
		result = shortenByWords(kept, maxLen)
	}
	return strings.Trim(result, " ,.-")
}

// shortenByWords собирает имя из слов, пока помещается в лимит,
// отбрасывая общие для всех хостеров слова.
//
// Надёжно выделить бренд из произвольного названия нельзя: он бывает и в
// начале («Hetzner Online GmbH»), и в конце («OOO Network of data-centers
// Selectel»). Поэтому цель скромнее — получить узнаваемую подпись, а не
// каноническое имя компании. Как следствие, два написания одного
// провайдера иногда всё же дают разные подписи.
func shortenByWords(words []string, maxLen int) string {
	meaningful := make([]string, 0, len(words))
	for _, w := range words {
		if _, generic := genericWords[strings.ToLower(strings.Trim(w, ".,-()"))]; generic {
			continue
		}
		meaningful = append(meaningful, w)
	}
	if len(meaningful) == 0 {
		meaningful = words
	}

	var b strings.Builder
	for _, w := range meaningful {
		next := len([]rune(b.String())) + len([]rune(w))
		if b.Len() > 0 {
			next++
		}
		if next > maxLen {
			break
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(w)
	}
	if b.Len() == 0 {
		// Первое слово само длиннее лимита — режем его.
		r := []rune(meaningful[0])
		return string(r[:min(maxLen, len(r))])
	}
	return b.String()
}

func looksLikeURL(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") ||
		strings.HasPrefix(l, "www.")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
