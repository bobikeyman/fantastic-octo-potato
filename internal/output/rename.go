// Package output формирует файлы подписок из результатов проверки.
package output

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/bobivpn/checker/internal/probe"
)

// Key — ключ, готовый к публикации.
type Key struct {
	Raw         string
	Fingerprint string

	CountryCode string
	Country     string
	Provider    string
	ExitIP      string

	LatencyMs int
	SpeedKBps float64
	JitterMs  int

	// Uptime и Runs приходят из истории репутации.
	Uptime float64
	Runs   int

	Insecure bool
}

// Sort упорядочивает ключи для выдачи: страна по приоритету, затем провайдер
// по алфавиту, затем задержка.
//
// Порядок обязан быть полным и детерминированным: файлы коммитятся, и
// перестановка равных элементов давала бы шумный дифф на каждом прогоне.
func Sort(keys []Key) {
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if pa, pb := PriorityOf(a.CountryCode), PriorityOf(b.CountryCode); pa != pb {
			return pa < pb
		}
		if a.CountryCode != b.CountryCode {
			return a.CountryCode < b.CountryCode
		}
		if pa, pb := strings.ToLower(a.Provider), strings.ToLower(b.Provider); pa != pb {
			return pa < pb
		}
		if a.LatencyMs != b.LatencyMs {
			return a.LatencyMs < b.LatencyMs
		}
		if a.SpeedKBps != b.SpeedKBps {
			return a.SpeedKBps > b.SpeedKBps
		}
		// Последний разделитель — отпечаток: без него равные ключи
		// переставлялись бы произвольно.
		return a.Fingerprint < b.Fingerprint
	})
}

// SortByQuality упорядочивает по надёжности — для топовой подписки.
func SortByQuality(keys []Key) {
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Uptime != b.Uptime {
			return a.Uptime > b.Uptime
		}
		if a.LatencyMs != b.LatencyMs {
			return a.LatencyMs < b.LatencyMs
		}
		if a.SpeedKBps != b.SpeedKBps {
			return a.SpeedKBps > b.SpeedKBps
		}
		return a.Fingerprint < b.Fingerprint
	})
}

// Rename подставляет человекочитаемые имена вида «🇩🇪 Germany | Hetzner 2».
//
// Нумерация идёт внутри пары «страна + провайдер» и зависит от порядка,
// поэтому вызывать Rename нужно после сортировки.
func Rename(keys []Key) []string {
	counters := make(map[string]int, len(keys))
	out := make([]string, 0, len(keys))

	for _, k := range keys {
		provider := k.Provider
		if provider == "" {
			provider = "Server"
		}
		bucket := k.CountryCode + "|" + provider
		counters[bucket]++

		name := fmt.Sprintf("%s %s | %s %d", Flag(k.CountryCode), k.Country, provider, counters[bucket])
		if k.Insecure {
			name += " ⚠"
		}
		out = append(out, replaceFragment(k.Raw, name))
	}
	return out
}

// replaceFragment заменяет #имя в ссылке.
//
// Решётка режется по ПЕРВОМУ вхождению: имена нередко содержат «#» сами,
// и разрез по последнему (как в старом чекере) оставлял бы в ссылке хвост
// старого названия.
func replaceFragment(raw, name string) string {
	base, _, _ := strings.Cut(raw, "#")
	return base + "#" + url.PathEscape(name)
}

// FromResults превращает результаты проверки в ключи для публикации.
//
// providers сопоставляет выходной адрес с именем провайдера; отсутствие
// записи не ошибка — ключ получит подпись «Server».
func FromResults(results []probe.Result, providers map[string]string) []Key {
	keys := make([]Key, 0, len(results))
	for _, r := range results {
		if !r.OK {
			continue
		}
		code := strings.ToUpper(r.ExitCountry)
		keys = append(keys, Key{
			Raw:         r.Raw,
			Fingerprint: r.Fingerprint,
			CountryCode: code,
			Country:     CountryName(code),
			Provider:    providers[r.ExitIP],
			ExitIP:      r.ExitIP,
			LatencyMs:   r.LatencyMs,
			JitterMs:    r.JitterMs,
			SpeedKBps:   r.SpeedKBps,
			Insecure:    r.Tier == "insecure",
		})
	}
	return keys
}

// LimitPerExitIP оставляет не больше n лучших ключей на один выходной адрес.
// При n <= 0 не делает ничего — это режим по умолчанию.
//
// # Почему по умолчанию выключено
//
// Изначально ограничение вводилось из предположения, что несколько ключей с
// одним выходным адресом — это один сервер, показанный много раз. Замер на
// боевых данных предположение опроверг: совпадение выходного адреса не
// означает ни одного сервера, ни одной учётной записи.
//
// Ключи различаются по двум независимым осям, и обе дают реальную живучесть:
//
//   - Разные учётки на одном сервере. Подписки покупаются по отдельности,
//     и бан одной не касается остальных: в замере 48 серверов отдали
//     несколько рабочих учёток каждый.
//   - Разные входные серверы с общим выходом. Провайдер держит ферму входов
//     за одним шлюзом: в замере один выходной адрес обслуживал 35 входных
//     серверов из целой подсети. Блокировка входного адреса у провайдера
//     пользователя убивает один вход, но не остальные 34.
//
// Отсечение по выходному адресу било по второй оси вслепую и выбрасывало
// уже проверенные рабочие ключи — то есть именно те запасные маршруты, ради
// которых список и нужен.
//
// Флаг оставлен для случая, когда список хочется укоротить осознанно.
// Вызывать нужно после сортировки — «лучшие» определяются порядком.
func LimitPerExitIP(keys []Key, n int) []Key {
	if n <= 0 {
		return keys
	}
	seen := make(map[string]int, len(keys))
	out := make([]Key, 0, len(keys))
	for _, k := range keys {
		if k.ExitIP == "" {
			out = append(out, k)
			continue
		}
		if seen[k.ExitIP] >= n {
			continue
		}
		seen[k.ExitIP]++
		out = append(out, k)
	}
	return out
}

// FilterCountries оставляет ключи только из указанных стран.
func FilterCountries(keys []Key, codes []string) []Key {
	if len(codes) == 0 {
		return keys
	}
	allowed := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		allowed[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
	}
	out := make([]Key, 0, len(keys))
	for _, k := range keys {
		if _, ok := allowed[k.CountryCode]; ok {
			out = append(out, k)
		}
	}
	return out
}

// GroupByCountry разбивает ключи по странам, сохраняя порядок внутри группы.
func GroupByCountry(keys []Key) map[string][]Key {
	out := make(map[string][]Key)
	for _, k := range keys {
		code := k.CountryCode
		if code == "" {
			code = "XX"
		}
		out[code] = append(out[code], k)
	}
	return out
}
