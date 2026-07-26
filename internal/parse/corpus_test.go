package parse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bobivpn/checker/internal/model"
)

// TestCorpus гоняет парсер по срезу реальных подписок (testdata/corpus.txt).
//
// Сеть не используется — это офлайн-фикстура. Тест защищает от регрессий:
// если доля разобранных ключей просядет, значит парсер что-то потерял.
func TestCorpus(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "corpus.txt"))
	if err != nil {
		t.Skipf("корпус недоступен: %v", err)
	}
	lines := strings.Split(string(data), "\n")

	nodes, stats := Batch(lines)

	t.Logf("строк: %d | разобрано: %d | уникальных: %d | дублей: %d | отбраковано: %d",
		stats.Lines, stats.Parsed, stats.Unique, stats.Duplicate, stats.RejectedTotal())
	for _, r := range stats.TopReasons() {
		t.Logf("  отбраковка %-24s %d", r.Reason, r.Count)
	}

	byProto := map[model.Protocol]int{}
	bySecurity := map[model.Security]int{}
	byTransport := map[model.Transport]int{}
	vision, insecure := 0, 0
	for _, n := range nodes {
		byProto[n.Protocol]++
		bySecurity[n.Security]++
		byTransport[n.Transport]++
		if n.Flow != "" {
			vision++
		}
		if n.AllowInsecure {
			insecure++
		}
	}
	t.Logf("протоколы: %v", byProto)
	t.Logf("security:  %v", bySecurity)
	t.Logf("transport: %v", byTransport)
	t.Logf("xtls-vision: %d | allowInsecure: %d", vision, insecure)

	if stats.Lines == 0 {
		t.Fatal("корпус пуст")
	}

	// Порог регрессии. Отбраковка hysteria2/tuic и битых ключей — норма,
	// но 90% реальных ссылок парсер обязан принимать.
	rate := float64(stats.Parsed) / float64(stats.Lines)
	if rate < 0.90 {
		t.Errorf("разобрано %.1f%% строк, ожидалось >= 90%%", rate*100)
	}

	// Каждая принятая нода должна давать непустой адрес и отпечаток.
	for _, n := range nodes {
		if n.Server == "" || n.Port == 0 {
			t.Fatalf("нода без адреса: %+v", n)
		}
		if len(n.Fingerprint()) != 32 {
			t.Fatalf("плохой отпечаток у %s", n.Endpoint())
		}
	}
}

// TestCorpusRoundTripStability — отпечаток обязан быть детерминированным
// между запусками, иначе история репутации развалится.
func TestCorpusRoundTripStability(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "corpus.txt"))
	if err != nil {
		t.Skipf("корпус недоступен: %v", err)
	}
	lines := strings.Split(string(data), "\n")

	first, _ := Batch(lines)
	second, _ := Batch(lines)

	if len(first) != len(second) {
		t.Fatalf("нестабильный дедуп: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Fingerprint() != second[i].Fingerprint() {
			t.Fatalf("отпечаток нестабилен на позиции %d", i)
		}
	}
}
