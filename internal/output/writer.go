package output

import (
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Profile — оформление подписки для клиента Happ.
type Profile struct {
	Title      string
	SupportURL string
	WebPageURL string
	// Announce — две строки, показываемые в клиенте.
	Announce string
	// UpdateInterval — периодичность обновления в часах.
	UpdateInterval int
}

// DefaultProfile соответствует configs/checker.yaml.
func DefaultProfile() Profile {
	return Profile{
		Title:          "🐶BobiVPN🐶",
		SupportURL:     "https://bobivpn.netlify.app/",
		WebPageURL:     "https://bobivpn.netlify.app/",
		UpdateInterval: 1,
	}
}

// Header собирает заголовок подписки в формате Happ.
func (p Profile) Header() string {
	var b strings.Builder
	fmt.Fprintf(&b, "#profile-update-interval: %d\n", max(p.UpdateInterval, 1))
	fmt.Fprintf(&b, "#profile-title: %s\n", p.Title)
	// Значения трафика и срока — заглушка: у сборной подписки из чужих
	// ключей нет ни квоты, ни даты окончания, но клиент ожидает поле.
	b.WriteString("#subscription-userinfo: upload=0; download=0; total=107374182400; expire=0\n")
	if p.SupportURL != "" {
		fmt.Fprintf(&b, "#support-url: %s\n", p.SupportURL)
	}
	if p.WebPageURL != "" {
		fmt.Fprintf(&b, "#profile-web-page-url: %s\n", p.WebPageURL)
	}
	if p.Announce != "" {
		enc := base64.StdEncoding.EncodeToString([]byte(p.Announce))
		fmt.Fprintf(&b, "#announce: base64:%s\n", enc)
	}
	return b.String()
}

// Announce — варианты второй строки объявления.
var announceLines = []string{
	"⚡ Только проверенные серверы",
	"🌍 Серверы по всему миру",
	"🔒 Безопасное соединение 24/7",
	"🚀 Максимальная скорость",
	"✨ Обновляется автоматически",
	"🛡️ Защита твоего трафика",
	"💎 Премиум качество бесплатно",
	"🔥 Работает когда другие нет",
	"⭐ Лучшие серверы для тебя",
	"🌐 Свобода без границ",
	"💪 Стабильное соединение",
	"🎯 Только рабочие ключи",
	"✅ Проверено и работает",
	"🏆 Топовые серверы",
	"🔓 Обходи любые блокировки",
}

// AnnounceLine выбирает строку по дате.
//
// Случайный выбор давал бы новый дифф при каждом прогоне даже без изменения
// ключей; привязка к дате оставляет строку стабильной в течение суток.
func AnnounceLine(day time.Time) string {
	h := fnv.New32a()
	fmt.Fprint(h, day.UTC().Format("2006-01-02"))
	return announceLines[int(h.Sum32())%len(announceLines)]
}

// WritePlain записывает ссылки по одной на строку.
func WritePlain(path string, links []string) error {
	content := strings.Join(links, "\n")
	if len(links) > 0 {
		content += "\n"
	}
	return writeFile(path, content)
}

// WriteBase64 записывает список, закодированный целиком.
func WriteBase64(path string, links []string) error {
	joined := strings.Join(links, "\n")
	return writeFile(path, base64.StdEncoding.EncodeToString([]byte(joined)))
}

// WriteHapp записывает подписку с заголовком профиля.
func WriteHapp(path string, profile Profile, links []string) error {
	var b strings.Builder
	b.WriteString(profile.Header())
	b.WriteString("\n")
	b.WriteString(strings.Join(links, "\n"))
	if len(links) > 0 {
		b.WriteString("\n")
	}
	return writeFile(path, b.String())
}

// WriteHappBase64 записывает подписку с заголовком, закодированную целиком.
func WriteHappBase64(path string, profile Profile, links []string) error {
	content := profile.Header() + "\n" + strings.Join(links, "\n")
	return writeFile(path, base64.StdEncoding.EncodeToString([]byte(content)))
}

// CountryFile — описание записанного файла страны.
type CountryFile struct {
	Code    string
	Country string
	File    string
	Count   int
}

// WriteCountries раскладывает ключи по файлам стран.
//
// Каталог очищается перед записью: страна, из которой не осталось рабочих
// ключей, иначе навсегда сохранила бы устаревший файл.
func WriteCountries(dir string, keys []Key, base Profile) ([]CountryFile, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := clearDir(dir, ".txt"); err != nil {
		return nil, err
	}

	groups := GroupByCountry(keys)
	files := make([]CountryFile, 0, len(groups))

	for code, group := range groups {
		country := CountryName(code)
		flag := Flag(code)

		profile := base
		profile.Title = fmt.Sprintf("%s BobiVPN %s", flag, country)
		profile.Announce = fmt.Sprintf("%s BobiVPN — %s\n⚡ %d проверенных серверов",
			flag, country, len(group))

		name := FileName(country) + ".txt"
		if err := WriteHapp(filepath.Join(dir, name), profile, Rename(group)); err != nil {
			return nil, err
		}
		files = append(files, CountryFile{Code: code, Country: country, File: name, Count: len(group)})
	}

	sortCountryFiles(files)
	return files, nil
}

func sortCountryFiles(files []CountryFile) {
	// Тот же порядок, что и в общей выдаче.
	for i := 1; i < len(files); i++ {
		for j := i; j > 0; j-- {
			a, b := files[j-1], files[j]
			pa, pb := PriorityOf(a.Code), PriorityOf(b.Code)
			if pa < pb || (pa == pb && a.Code <= b.Code) {
				break
			}
			files[j-1], files[j] = files[j], files[j-1]
		}
	}
}

func clearDir(dir, ext string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ext) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path, content string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(content), 0o644)
}
