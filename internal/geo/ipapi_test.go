package geo

import "testing"

func TestCleanProvider(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Кавычки и организационно-правовые формы — сырые значения
		// из первого реального прогона.
		{`JSC "TIMEWEB"`, "TIMEWEB"},
		{"JSC Selectel", "Selectel"},
		{"Selectel", "Selectel"},
		{`"Cloud Technologies" LLC`, "Cloud Technologies"},
		// Общие слова и предлоги выброшены, бренд сохранён. Каноническим
		// именем «Selectel» это не станет — см. комментарий к shortenByWords.
		{"OOO Network of data-centers Selectel", "data-centers Selectel"},

		// Номер AS отбрасывается, но «AS» в начале обычного имени — нет.
		{"AS13335 Cloudflare, Inc.", "Cloudflare"},
		{"ASTRA Networks", "ASTRA Networks"},

		// Форма в конце.
		{"Hetzner Online GmbH", "Hetzner Online"},
		{"OVH SAS", "OVH"},
		{"DigitalOcean, LLC", "DigitalOcean"},

		// URL геофида вместо имени провайдера.
		{"https://geofeeds.cyberzone.example/feed.csv", ""},
		{"www.example.com", ""},

		{"", ""},
		{"   ", ""},
	}

	for _, tc := range cases {
		if got := cleanProvider(tc.in); got != tc.want {
			t.Errorf("cleanProvider(%q) = %q, ожидалось %q", tc.in, got, tc.want)
		}
	}
}

// Обрывок вида «Cloud Technologies LL…» выглядит как ошибка вёрстки:
// длинные имена режутся по словам.
func TestCleanProviderShortensByWords(t *testing.T) {
	cases := []string{
		"Alibaba (US) Technology Co., Ltd.",
		"Shenzhen Tencent Computer Systems Company Limited",
		"South-East Branch of the National Telecom",
		"Ekiphost Bilisim Teknolojileri Sanayi Ticaret",
		"Oy Crea Nova Hosting Solution Ltd",
	}
	for _, in := range cases {
		got := cleanProvider(in)
		if got == "" {
			t.Errorf("cleanProvider(%q) вернул пустоту", in)
			continue
		}
		if len([]rune(got)) > 22 {
			t.Errorf("cleanProvider(%q) = %q — длиннее лимита", in, got)
		}
		// Слово не должно обрываться на середине.
		if r := []rune(got); r[len(r)-1] == '…' {
			t.Errorf("cleanProvider(%q) = %q — обрыв посреди слова", in, got)
		}
		t.Logf("%-50s -> %q", in, got)
	}
}

// Один провайдер под разными сырыми именами обязан давать одну подпись,
// иначе он попадёт в список дважды с независимой нумерацией.
func TestCleanProviderCollapsesVariants(t *testing.T) {
	groups := [][]string{
		{"JSC Selectel", "Selectel", `LLC "Selectel"`},
		{"Hetzner Online GmbH", "Hetzner Online"},
		{"OVH SAS", "OVH, SAS", "OVH"},
	}
	for _, group := range groups {
		first := cleanProvider(group[0])
		for _, variant := range group[1:] {
			if got := cleanProvider(variant); got != first {
				t.Errorf("варианты дают разные имена: %q -> %q, %q -> %q",
					group[0], first, variant, got)
			}
		}
	}
}

func TestProviderFallbackChain(t *testing.T) {
	// ISP пустой — берём Org, затем ASName.
	i := Info{ISP: "", Org: "Aeza International LTD", ASName: "AEZA"}
	if got := i.Provider(); got != "Aeza International" {
		t.Errorf("Provider() = %q", got)
	}
	// Всё пустое — подпись по умолчанию.
	if got := (Info{}).Provider(); got != "Server" {
		t.Errorf("пустой Info дал %q, ожидалось Server", got)
	}
	// URL в ISP не должен попасть в имя: переходим к следующему полю.
	i = Info{ISP: "https://geofeeds.example/x.csv", Org: "", ASName: "Contabo"}
	if got := i.Provider(); got != "Contabo" {
		t.Errorf("Provider() = %q, ожидалось Contabo", got)
	}
}

func TestDedupe(t *testing.T) {
	got := dedupe([]string{"1.1.1.1", "2.2.2.2", "1.1.1.1", "", "  ", " 3.3.3.3 "})
	if len(got) != 3 {
		t.Fatalf("осталось %d адресов: %v", len(got), got)
	}
	if got[2] != "3.3.3.3" {
		t.Errorf("пробелы не срезаны: %q", got[2])
	}
}
