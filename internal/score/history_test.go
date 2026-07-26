package score

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func observe(h *History, fp string, oks ...bool) *Entry {
	var e *Entry
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	for i, ok := range oks {
		e = h.Observe(Observation{
			Fingerprint: fp,
			OK:          ok,
			Country:     "DE",
			ExitIP:      "203.0.113.1",
			LatencyMs:   120,
			SpeedKBps:   2000,
			At:          base.Add(time.Duration(i) * 3 * time.Hour),
		})
	}
	return e
}

func TestObserveCountsAndStreak(t *testing.T) {
	h := New()
	e := observe(h, "aaa", true, true, false, true)

	if e.Runs != 4 || e.OK != 3 || e.Fail != 1 {
		t.Errorf("runs=%d ok=%d fail=%d", e.Runs, e.OK, e.Fail)
	}
	if e.Streak != 1 {
		t.Errorf("streak = %d, ожидалась 1 после успеха вслед за неудачей", e.Streak)
	}
	if math.Abs(e.Uptime()-0.75) > 1e-9 {
		t.Errorf("uptime = %.3f", e.Uptime())
	}
}

func TestStreakGoesNegativeOnFailures(t *testing.T) {
	h := New()
	e := observe(h, "aaa", true, false, false, false)
	if e.Streak != -3 {
		t.Errorf("streak = %d, ожидалась -3", e.Streak)
	}
}

// Первый замер задаёт EWMA целиком: старт с нуля занизил бы оценку
// на несколько прогонов вперёд.
func TestFirstObservationSetsEWMADirectly(t *testing.T) {
	h := New()
	if e := observe(h, "ok", true); e.EWMA != 1 {
		t.Errorf("EWMA после первого успеха = %.3f, ожидалась 1", e.EWMA)
	}
	if e := observe(h, "bad", false); e.EWMA != 0 {
		t.Errorf("EWMA после первой неудачи = %.3f, ожидалась 0", e.EWMA)
	}
}

// Одна неудача не должна выбрасывать давно работающий ключ,
// а три подряд — должны.
func TestEWMADecayRate(t *testing.T) {
	h := New()
	stable := observe(h, "stable", true, true, true, true, true, true)
	if stable.EWMA < 0.99 {
		t.Errorf("стабильный ключ: EWMA = %.3f", stable.EWMA)
	}

	one := observe(h, "one-fail", true, true, true, true, true, false)
	if one.EWMA < 0.6 {
		t.Errorf("одна неудача уронила EWMA до %.3f — слишком резко", one.EWMA)
	}

	three := observe(h, "three-fails", true, true, true, true, false, false, false)
	if three.EWMA >= 0.6 {
		t.Errorf("три неудачи подряд оставили EWMA %.3f — слишком мягко", three.EWMA)
	}
}

func TestPolicyRejectsNewKeys(t *testing.T) {
	h := New()
	p := DefaultPolicy()

	// Повезло один раз — в подписку не попадает.
	first := observe(h, "newbie", true)
	if p.Admits(first, true) {
		t.Error("ключ допущен после единственного успешного прогона")
	}

	second := observe(h, "newbie", true)
	if !p.Admits(second, true) {
		t.Error("ключ не допущен после двух успешных прогонов подряд")
	}
}

// Ключ мог иметь прекрасную историю и умереть час назад.
func TestPolicyRequiresCurrentSuccess(t *testing.T) {
	h := New()
	e := observe(h, "was-good", true, true, true, true)
	p := DefaultPolicy()

	if !p.Admits(e, true) {
		t.Fatal("здоровый ключ не допущен")
	}
	if p.Admits(e, false) {
		t.Error("ключ допущен, хотя в текущем прогоне не ответил")
	}
}

func TestPolicyRejectsLowReputation(t *testing.T) {
	h := New()
	e := observe(h, "flaky", true, false, false, true, false, false)
	if DefaultPolicy().Admits(e, true) {
		t.Errorf("нестабильный ключ допущен: EWMA = %.3f", e.EWMA)
	}
}

func TestPruneRemovesStale(t *testing.T) {
	h := New()
	now := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)

	h.Observe(Observation{Fingerprint: "fresh", OK: true, At: now.Add(-2 * time.Hour)})
	h.Observe(Observation{Fingerprint: "stale", OK: true, At: now.Add(-10 * 24 * time.Hour)})

	if removed := h.Prune(now, 7*24*time.Hour); removed != 1 {
		t.Errorf("удалено %d записей, ожидалась 1", removed)
	}
	if _, ok := h.Get("fresh"); !ok {
		t.Error("свежая запись удалена")
	}
	if _, ok := h.Get("stale"); ok {
		t.Error("устаревшая запись осталась")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "history.jsonl.gz")

	h := New()
	observe(h, "aaa", true, true, false)
	observe(h, "bbb", true)

	if err := h.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("загружено %d записей", loaded.Len())
	}

	orig, _ := h.Get("aaa")
	got, ok := loaded.Get("aaa")
	if !ok {
		t.Fatal("запись aaa потеряна")
	}
	if got.Runs != orig.Runs || got.OK != orig.OK || got.Streak != orig.Streak {
		t.Errorf("счётчики не пережили сохранение: %+v", got)
	}
	if math.Abs(got.EWMA-orig.EWMA) > 1e-9 {
		t.Errorf("EWMA = %.6f, ожидалась %.6f", got.EWMA, orig.EWMA)
	}
	if got.LastCountry != "DE" || got.LastExitIP != "203.0.113.1" {
		t.Errorf("характеристики потеряны: %+v", got)
	}
}

// Отсутствие файла — это первый прогон, а не ошибка.
func TestLoadMissingFileIsEmpty(t *testing.T) {
	h, err := Load(filepath.Join(t.TempDir(), "нет-такого.jsonl.gz"))
	if err != nil {
		t.Fatalf("отсутствие файла воспринято как ошибка: %v", err)
	}
	if h.Len() != 0 {
		t.Errorf("история не пуста: %d", h.Len())
	}
}

func TestLoadCorruptedFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.jsonl.gz")
	if err := os.WriteFile(path, []byte("это не gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("повреждённый файл загружен без ошибки")
	}
}

// Файл истории коммитится: порядок записей обязан быть стабильным,
// иначе каждый прогон переставляет файл целиком.
func TestEntriesOrderStable(t *testing.T) {
	h := New()
	for _, fp := range []string{"ccc", "aaa", "bbb"} {
		observe(h, fp, true)
	}
	got := h.Entries()
	for i, want := range []string{"aaa", "bbb", "ccc"} {
		if got[i].Fingerprint != want {
			t.Fatalf("позиция %d: %q, ожидалось %q", i, got[i].Fingerprint, want)
		}
	}
}

// Неудачный прогон не должен затирать последние известные характеристики.
func TestFailureKeepsLastKnownMetrics(t *testing.T) {
	h := New()
	h.Observe(Observation{Fingerprint: "aaa", OK: true, Country: "NL", ExitIP: "203.0.113.9", LatencyMs: 90, SpeedKBps: 3000})
	e := h.Observe(Observation{Fingerprint: "aaa", OK: false})

	if e.LastCountry != "NL" || e.LastExitIP != "203.0.113.9" || e.LastLatency != 90 {
		t.Errorf("характеристики затёрты неудачным прогоном: %+v", e)
	}
}
