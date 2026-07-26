package output

import (
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func urlUnescape(s string) (string, error) { return url.PathUnescape(s) }

func TestFlagFromCode(t *testing.T) {
	cases := map[string]string{
		"RU": "🇷🇺", "DE": "🇩🇪", "US": "🇺🇸", "NL": "🇳🇱",
		// Алгоритм покрывает и страны, которых нет ни в одной таблице:
		// старый чекер на них выдавал глобус.
		"MG": "🇲🇬", "BT": "🇧🇹", "FJ": "🇫🇯",
		"XX": "🌍", "": "🌍", "мусор": "🌍", "Z": "🌍",
	}
	for code, want := range cases {
		if got := Flag(code); got != want {
			t.Errorf("Flag(%q) = %q, ожидалось %q", code, got, want)
		}
	}
}

func TestSortOrder(t *testing.T) {
	keys := []Key{
		{Fingerprint: "a", CountryCode: "US", Provider: "AWS", LatencyMs: 50},
		{Fingerprint: "b", CountryCode: "RU", Provider: "Yandex", LatencyMs: 200},
		{Fingerprint: "c", CountryCode: "DE", Provider: "Hetzner", LatencyMs: 30},
		{Fingerprint: "d", CountryCode: "RU", Provider: "Aeza", LatencyMs: 100},
		{Fingerprint: "e", CountryCode: "DE", Provider: "Hetzner", LatencyMs: 10},
	}
	Sort(keys)

	// Россия выше Германии, Германия выше США; внутри страны — провайдер
	// по алфавиту, затем задержка.
	want := []string{"d", "b", "e", "c", "a"}
	for i, fp := range want {
		if keys[i].Fingerprint != fp {
			t.Fatalf("позиция %d: %q, ожидалось %q (порядок %v)", i, keys[i].Fingerprint, fp, fps(keys))
		}
	}
}

// Файлы коммитятся: равные ключи не должны переставляться между прогонами.
func TestSortDeterministicForEqualKeys(t *testing.T) {
	mk := func() []Key {
		return []Key{
			{Fingerprint: "ccc", CountryCode: "DE", Provider: "X", LatencyMs: 100},
			{Fingerprint: "aaa", CountryCode: "DE", Provider: "X", LatencyMs: 100},
			{Fingerprint: "bbb", CountryCode: "DE", Provider: "X", LatencyMs: 100},
		}
	}
	a, b := mk(), mk()
	Sort(a)
	Sort(b)
	for i := range a {
		if a[i].Fingerprint != b[i].Fingerprint {
			t.Fatalf("порядок нестабилен на позиции %d", i)
		}
	}
	if a[0].Fingerprint != "aaa" {
		t.Errorf("равные ключи не упорядочены по отпечатку: %v", fps(a))
	}
}

func TestRenameNumbersWithinProvider(t *testing.T) {
	keys := []Key{
		{CountryCode: "DE", Country: "Germany", Provider: "Hetzner", Raw: "vless://a@h:443#старое"},
		{CountryCode: "DE", Country: "Germany", Provider: "Hetzner", Raw: "vless://b@h:443"},
		{CountryCode: "DE", Country: "Germany", Provider: "Aeza", Raw: "vless://c@h:443"},
		{CountryCode: "RU", Country: "Russia", Provider: "Hetzner", Raw: "vless://d@h:443"},
	}
	got := Rename(keys)

	wantNames := []string{
		"🇩🇪 Germany | Hetzner 1",
		"🇩🇪 Germany | Hetzner 2",
		"🇩🇪 Germany | Aeza 1",
		"🇷🇺 Russia | Hetzner 1", // нумерация своя в каждой стране
	}
	for i, want := range wantNames {
		name := fragmentOf(t, got[i])
		if name != want {
			t.Errorf("%d: имя %q, ожидалось %q", i, name, want)
		}
	}
	// Старое имя должно быть заменено, а не дописано.
	if strings.Contains(got[0], "старое") {
		t.Errorf("старое имя осталось: %s", got[0])
	}
}

// Имена нередко содержат «#»: резать нужно по первому вхождению,
// иначе в ссылке остаётся хвост старого названия.
func TestRenameHandlesHashInOldName(t *testing.T) {
	keys := []Key{{CountryCode: "NL", Country: "Netherlands", Provider: "X", Raw: "vless://a@h:443?type=ws#имя # с решёткой"}}
	got := Rename(keys)
	if strings.Count(got[0], "#") != 1 {
		t.Errorf("в ссылке %d решёток: %s", strings.Count(got[0], "#"), got[0])
	}
	if !strings.HasPrefix(got[0], "vless://a@h:443?type=ws#") {
		t.Errorf("тело ссылки повреждено: %s", got[0])
	}
}

func TestRenameMarksInsecure(t *testing.T) {
	keys := []Key{{CountryCode: "DE", Country: "Germany", Provider: "X", Raw: "vless://a@h:443", Insecure: true}}
	if name := fragmentOf(t, Rename(keys)[0]); !strings.Contains(name, "⚠") {
		t.Errorf("корзина insecure не отмечена: %q", name)
	}
}

// В выхлопе старого чекера 527 ключей вели на один адрес — для пользователя
// это один сервер, показанный полутысячей строк.
func TestLimitPerExitIP(t *testing.T) {
	var keys []Key
	for i := 0; i < 12; i++ {
		keys = append(keys, Key{Fingerprint: string(rune('a' + i)), ExitIP: "1.2.3.4"})
	}
	keys = append(keys, Key{Fingerprint: "z", ExitIP: "5.6.7.8"})

	got := LimitPerExitIP(keys, 5)
	if len(got) != 6 {
		t.Fatalf("осталось %d ключей, ожидалось 6", len(got))
	}
	counts := map[string]int{}
	for _, k := range got {
		counts[k.ExitIP]++
	}
	if counts["1.2.3.4"] != 5 {
		t.Errorf("на дублирующемся адресе %d ключей", counts["1.2.3.4"])
	}
	// Ключи без известного адреса не выбрасываются.
	if got := LimitPerExitIP([]Key{{ExitIP: ""}, {ExitIP: ""}}, 1); len(got) != 2 {
		t.Errorf("ключи без exit IP отброшены: %d", len(got))
	}
}

func TestFilterCountries(t *testing.T) {
	keys := []Key{
		{CountryCode: "RU"}, {CountryCode: "DE"}, {CountryCode: "US"}, {CountryCode: "FI"},
	}
	got := FilterCountries(keys, []string{"RU", "DE", "FI"})
	if len(got) != 3 {
		t.Fatalf("осталось %d", len(got))
	}
	if len(FilterCountries(keys, nil)) != 4 {
		t.Error("пустой фильтр отбросил ключи")
	}
}

func TestHappHeader(t *testing.T) {
	p := DefaultProfile()
	p.Announce = "первая строка\nвторая"
	h := p.Header()

	for _, want := range []string{
		"#profile-update-interval: 1",
		"#profile-title: 🐶BobiVPN🐶",
		"#subscription-userinfo:",
		"#support-url: https://bobivpn.netlify.app/",
		"#announce: base64:",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("в заголовке нет %q:\n%s", want, h)
		}
	}

	_, enc, _ := strings.Cut(h, "#announce: base64:")
	enc, _, _ = strings.Cut(enc, "\n")
	decoded, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("announce не раскодировался: %v", err)
	}
	if string(decoded) != p.Announce {
		t.Errorf("announce = %q", decoded)
	}
}

// Случайная строка давала бы дифф на каждом прогоне даже без изменения ключей.
func TestAnnounceLineStableWithinDay(t *testing.T) {
	day := time.Date(2026, 7, 26, 3, 0, 0, 0, time.UTC)
	same := time.Date(2026, 7, 26, 21, 0, 0, 0, time.UTC)
	next := time.Date(2026, 7, 27, 3, 0, 0, 0, time.UTC)

	if AnnounceLine(day) != AnnounceLine(same) {
		t.Error("строка меняется в течение суток")
	}
	// Разные дни обязаны давать выбор из общего набора.
	if got := AnnounceLine(next); got == "" {
		t.Error("пустая строка")
	}
}

func TestWriteFiles(t *testing.T) {
	dir := t.TempDir()
	links := []string{"vless://a@h:443#1", "vless://b@h:443#2"}

	plain := filepath.Join(dir, "vpn.txt")
	if err := WritePlain(plain, links); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(plain)
	if strings.Count(string(data), "vless://") != 2 {
		t.Errorf("plain: %q", data)
	}

	b64 := filepath.Join(dir, "vpn_base64.txt")
	if err := WriteBase64(b64, links); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(b64)
	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		t.Fatalf("base64 не раскодировался: %v", err)
	}
	if !strings.Contains(string(decoded), "vless://a") {
		t.Errorf("base64 содержит не то: %q", decoded)
	}

	happ := filepath.Join(dir, "bobi_vpn.txt")
	if err := WriteHapp(happ, DefaultProfile(), links); err != nil {
		t.Fatal(err)
	}
	h, _ := os.ReadFile(happ)
	if !strings.HasPrefix(string(h), "#profile-update-interval:") {
		t.Errorf("нет заголовка Happ: %.60s", h)
	}
	if !strings.Contains(string(h), "vless://b") {
		t.Error("ключи не записаны")
	}
}

// Страна, из которой не осталось рабочих ключей, не должна сохранять
// устаревший файл навсегда.
func TestWriteCountriesClearsStale(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "atlantis.txt")
	if err := os.WriteFile(stale, []byte("старое"), 0o644); err != nil {
		t.Fatal(err)
	}

	keys := []Key{
		{CountryCode: "DE", Country: "Germany", Provider: "Hetzner", Raw: "vless://a@h:443"},
		{CountryCode: "DE", Country: "Germany", Provider: "Aeza", Raw: "vless://b@h:443"},
		{CountryCode: "RU", Country: "Russia", Provider: "Yandex", Raw: "vless://c@h:443"},
	}
	files, err := WriteCountries(dir, keys, DefaultProfile())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("устаревший файл страны не удалён")
	}
	if len(files) != 2 {
		t.Fatalf("создано %d файлов: %+v", len(files), files)
	}
	// Россия идёт первой по приоритету.
	if files[0].Code != "RU" {
		t.Errorf("порядок стран: %s первым", files[0].Code)
	}
	if files[0].File != "russia.txt" {
		t.Errorf("имя файла = %q", files[0].File)
	}

	germany, err := os.ReadFile(filepath.Join(dir, "germany.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(germany), "#profile-title: 🇩🇪 BobiVPN Germany") {
		t.Errorf("заголовок страны неверен:\n%.200s", germany)
	}
}

func TestFileName(t *testing.T) {
	cases := map[string]string{
		"United States": "united_states",
		"Germany":       "germany",
		"Hong Kong":     "hong_kong",
		"":              "unknown",
		"!!!":           "unknown",
	}
	for in, want := range cases {
		if got := FileName(in); got != want {
			t.Errorf("FileName(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

func fps(keys []Key) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.Fingerprint
	}
	return out
}

func fragmentOf(t *testing.T, link string) string {
	t.Helper()
	_, frag, ok := strings.Cut(link, "#")
	if !ok {
		t.Fatalf("в ссылке нет имени: %s", link)
	}
	decoded, err := urlUnescape(frag)
	if err != nil {
		t.Fatalf("имя не раскодировалось: %v", err)
	}
	return decoded
}
