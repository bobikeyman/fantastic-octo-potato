// Package score хранит репутацию ключей между прогонами и решает,
// какие из них попадают в публикацию.
//
// Без истории проверка остаётся снимком удачи: ключ, случайно ответивший
// один раз, попадает в подписку наравне с тем, что стабильно работает
// вторую неделю. Именно это отличает рейтинг от разового замера.
package score

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Alpha — вес свежего прогона в экспоненциальном среднем.
//
// 0.3 даёт «память» примерно на десяток прогонов: одна неудача не
// выбрасывает давно работающий ключ, но три подряд — выбрасывают.
const Alpha = 0.3

// Entry — репутация одного ключа.
type Entry struct {
	Fingerprint string `json:"fp"`

	Runs int `json:"runs"`
	OK   int `json:"ok"`
	Fail int `json:"fail"`
	// Streak — подряд идущих успехов; отрицательное значение считает неудачи.
	Streak int `json:"streak"`

	EWMA float64 `json:"ewma"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	LastOK    time.Time `json:"last_ok,omitzero"`

	// Source различает, откуда пришёл замер: из дата-центра или из целевой
	// сети. Проверка из Azure и проверка с домашнего ПК — разные факты,
	// и смешивать их в одно число нельзя.
	Source string `json:"source,omitempty"`

	// Последние известные характеристики — для сортировки выдачи,
	// когда ключ в текущем прогоне не проверялся.
	LastCountry string  `json:"country,omitempty"`
	LastExitIP  string  `json:"exit_ip,omitempty"`
	LastLatency int     `json:"latency_ms,omitempty"`
	LastSpeed   float64 `json:"speed_kbps,omitempty"`
}

// Uptime — доля успешных прогонов за всё время наблюдения.
func (e *Entry) Uptime() float64 {
	if e.Runs == 0 {
		return 0
	}
	return float64(e.OK) / float64(e.Runs)
}

// History — репутация всех известных ключей.
type History struct {
	entries map[string]*Entry
}

// New создаёт пустую историю.
func New() *History {
	return &History{entries: make(map[string]*Entry)}
}

// Len возвращает число записей.
func (h *History) Len() int { return len(h.entries) }

// Get возвращает запись по отпечатку.
func (h *History) Get(fp string) (*Entry, bool) {
	e, ok := h.entries[fp]
	return e, ok
}

// Observation — результат одной проверки, попадающий в историю.
type Observation struct {
	Fingerprint string
	OK          bool
	Country     string
	ExitIP      string
	LatencyMs   int
	SpeedKBps   float64
	Source      string
	At          time.Time
}

// Observe учитывает результат проверки.
func (h *History) Observe(o Observation) *Entry {
	at := o.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	at = at.UTC()

	e, ok := h.entries[o.Fingerprint]
	if !ok {
		e = &Entry{
			Fingerprint: o.Fingerprint,
			FirstSeen:   at,
			// Первый замер задаёт начальное значение целиком: сглаживать
			// его нечем, а старт с нуля занизил бы оценку на несколько
			// прогонов вперёд.
			EWMA: boolToFloat(o.OK),
		}
		h.entries[o.Fingerprint] = e
	} else {
		e.EWMA = Alpha*boolToFloat(o.OK) + (1-Alpha)*e.EWMA
	}

	e.Runs++
	e.LastSeen = at
	e.Source = o.Source

	if o.OK {
		e.OK++
		e.LastOK = at
		if e.Streak < 0 {
			e.Streak = 1
		} else {
			e.Streak++
		}
		// Характеристики обновляем только по удачному замеру: цифры
		// неудачного прогона бессмысленны.
		if o.Country != "" {
			e.LastCountry = o.Country
		}
		if o.ExitIP != "" {
			e.LastExitIP = o.ExitIP
		}
		if o.LatencyMs > 0 {
			e.LastLatency = o.LatencyMs
		}
		if o.SpeedKBps > 0 {
			e.LastSpeed = o.SpeedKBps
		}
	} else {
		e.Fail++
		if e.Streak > 0 {
			e.Streak = -1
		} else {
			e.Streak--
		}
	}
	return e
}

// Policy — правила допуска ключа в публикацию.
type Policy struct {
	// MinEWMA — нижняя граница репутации.
	MinEWMA float64
	// MinRuns — сколько прогонов ключ должен быть виден, прежде чем
	// попадёт в выдачу. Отсекает «повезло один раз».
	MinRuns int
	// RequireCurrentOK требует успеха именно в текущем прогоне: ключ мог
	// иметь прекрасную историю и умереть час назад.
	RequireCurrentOK bool
}

// DefaultPolicy соответствует configs/checker.yaml.
func DefaultPolicy() Policy {
	return Policy{MinEWMA: 0.6, MinRuns: 2, RequireCurrentOK: true}
}

// Admits решает, публиковать ли ключ.
func (p Policy) Admits(e *Entry, okNow bool) bool {
	if e == nil {
		return false
	}
	if p.RequireCurrentOK && !okNow {
		return false
	}
	if e.Runs < p.MinRuns {
		return false
	}
	return e.EWMA >= p.MinEWMA
}

// Prune удаляет записи, которых давно не видно.
//
// Ключи исчезают из подписок навсегда, и хранить их вечно незачем:
// файл истории коммитится в репозиторий и не должен пухнуть.
func (h *History) Prune(now time.Time, ttl time.Duration) int {
	if ttl <= 0 {
		return 0
	}
	cutoff := now.UTC().Add(-ttl)
	removed := 0
	for fp, e := range h.entries {
		if e.LastSeen.Before(cutoff) {
			delete(h.entries, fp)
			removed++
		}
	}
	return removed
}

// Entries возвращает записи, упорядоченные по отпечатку.
//
// Порядок фиксирован намеренно: файл истории коммитится, и его диффы
// должны читаться, а не переставляться целиком при каждом прогоне.
func (h *History) Entries() []*Entry {
	out := make([]*Entry, 0, len(h.entries))
	for _, e := range h.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

// Save записывает историю в gzip-JSONL.
//
// Построчный формат выбран ради диффов: одна запись — одна строка,
// изменение репутации ключа видно как изменение одной строки.
func (h *History) Save(path string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// Пишем через временный файл: прерывание прогона не должно оставить
	// историю обрезанной.
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}

	gz := gzip.NewWriter(f)
	enc := json.NewEncoder(gz)
	enc.SetEscapeHTML(false)
	for _, e := range h.Entries() {
		if err := enc.Encode(e); err != nil {
			gz.Close()
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := gz.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Load читает историю. Отсутствие файла — не ошибка: это первый прогон.
func Load(path string) (*History, error) {
	h := New()

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return h, nil
		}
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("история повреждена: %w", err)
	}
	defer gz.Close()

	sc := bufio.NewScanner(gz)
	// Записи короткие, но буфер по умолчанию (64 КБ) оставляем с запасом.
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("строка %d: %w", line, err)
		}
		if e.Fingerprint == "" {
			continue
		}
		h.entries[e.Fingerprint] = &e
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return nil, err
	}
	return h, nil
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
