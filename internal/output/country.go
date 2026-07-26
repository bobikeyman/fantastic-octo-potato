package output

import "strings"

// Flags — эмодзи-флаги по коду страны.
//
// Флаг собирается из кода алгоритмически (см. Flag), таблица нужна лишь для
// случаев, где алгоритм даёт не то, что ожидает пользователь.
var Flags = map[string]string{
	"XX": "🌍",
	"":   "🌍",
	"T1": "🧅", // выход через Tor
	"EU": "🇪🇺",
	"AP": "🌏",
}

// Flag возвращает эмодзи-флаг страны.
//
// Флаги — это пара Regional Indicator Symbol, то есть код страны, сдвинутый
// в другой диапазон Unicode. Перечислять две сотни стран руками, как это
// делает старый чекер (и промахивается на всех, кого забыл), незачем.
func Flag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if f, ok := Flags[code]; ok {
		return f
	}
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return "🌍"
	}
	const base = 0x1F1E6 // REGIONAL INDICATOR SYMBOL LETTER A
	return string([]rune{
		rune(base + int(code[0]-'A')),
		rune(base + int(code[1]-'A')),
	})
}

// Priority задаёт порядок стран в выдаче: меньше — выше.
//
// Порядок ориентирован на пользователя из России и СНГ: сначала местные
// и соседние, затем ближняя Европа, потом всё остальное.
var Priority = map[string]int{
	// СНГ и соседи
	"RU": 0, "KZ": 1, "BY": 2, "UA": 3, "AM": 4, "GE": 5, "MD": 6, "AZ": 7,
	"KG": 8, "UZ": 9, "TJ": 10,

	// Европа — ближняя и быстрая
	"FI": 20, "DE": 21, "NL": 22, "SE": 23, "NO": 24, "PL": 25, "LT": 26,
	"LV": 27, "EE": 28, "FR": 29, "GB": 30, "DK": 31, "CZ": 32, "AT": 33,
	"CH": 34, "BE": 35, "IE": 36, "LU": 37, "SK": 38, "HU": 39, "RO": 40,
	"BG": 41, "RS": 42, "HR": 43, "SI": 44, "GR": 45, "IT": 46, "ES": 47,
	"PT": 48, "IS": 49, "MT": 50, "CY": 51,

	// Ближний Восток и Кавказ
	"TR": 60, "IL": 61, "AE": 62, "SA": 63, "QA": 64, "KW": 65,

	// Азия
	"JP": 70, "KR": 71, "HK": 72, "TW": 73, "SG": 74, "IN": 75, "TH": 76,
	"VN": 77, "MY": 78, "ID": 79, "PH": 80, "CN": 81,

	// Америка
	"US": 90, "CA": 91, "MX": 92, "BR": 93, "AR": 94, "CL": 95,

	// Океания и Африка
	"AU": 100, "NZ": 101, "ZA": 110, "EG": 111, "NG": 112,
}

// PriorityOf возвращает приоритет страны; неизвестные уходят в конец.
func PriorityOf(code string) int {
	if p, ok := Priority[strings.ToUpper(strings.TrimSpace(code))]; ok {
		return p
	}
	return 999
}

// Names — человекочитаемые названия стран по коду.
//
// Cloudflare отдаёт в trace только двухбуквенный код, а имя страны нужно
// и для подписи ключа, и для имени файла в countries/.
var Names = map[string]string{
	"AE": "UAE", "AL": "Albania", "AM": "Armenia", "AR": "Argentina",
	"AT": "Austria", "AU": "Australia", "AZ": "Azerbaijan", "BA": "Bosnia",
	"BD": "Bangladesh", "BE": "Belgium", "BG": "Bulgaria", "BH": "Bahrain",
	"BR": "Brazil", "BY": "Belarus", "CA": "Canada", "CH": "Switzerland",
	"CL": "Chile", "CN": "China", "CO": "Colombia", "CR": "Costa Rica",
	"CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DK": "Denmark",
	"DO": "Dominicana", "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia",
	"EG": "Egypt", "ES": "Spain", "FI": "Finland", "FR": "France",
	"GB": "United Kingdom", "GE": "Georgia", "GR": "Greece", "HK": "Hong Kong",
	"HR": "Croatia", "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland",
	"IL": "Israel", "IN": "India", "IQ": "Iraq", "IR": "Iran", "IS": "Iceland",
	"IT": "Italy", "JO": "Jordan", "JP": "Japan", "KE": "Kenya",
	"KG": "Kyrgyzstan", "KH": "Cambodia", "KR": "South Korea", "KW": "Kuwait",
	"KZ": "Kazakhstan", "LB": "Lebanon", "LT": "Lithuania", "LU": "Luxembourg",
	"LV": "Latvia", "MA": "Morocco", "MD": "Moldova", "MK": "Macedonia",
	"MT": "Malta", "MX": "Mexico", "MY": "Malaysia", "NG": "Nigeria",
	"NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NZ": "New Zealand",
	"OM": "Oman", "PA": "Panama", "PE": "Peru", "PH": "Philippines",
	"PK": "Pakistan", "PL": "Poland", "PT": "Portugal", "PY": "Paraguay",
	"QA": "Qatar", "RO": "Romania", "RS": "Serbia", "RU": "Russia",
	"SA": "Saudi Arabia", "SE": "Sweden", "SG": "Singapore", "SI": "Slovenia",
	"SK": "Slovakia", "TH": "Thailand", "TJ": "Tajikistan", "TR": "Turkey",
	"TW": "Taiwan", "UA": "Ukraine", "US": "United States", "UY": "Uruguay",
	"UZ": "Uzbekistan", "VN": "Vietnam", "ZA": "South Africa",
}

// CountryName возвращает название страны; для неизвестного кода — сам код.
func CountryName(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return "Unknown"
	}
	if name, ok := Names[code]; ok {
		return name
	}
	return code
}

// FileName превращает название страны в имя файла: "United States" -> "united_states".
func FileName(country string) string {
	s := strings.ToLower(strings.TrimSpace(country))
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '_':
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), "_")
	if name == "" {
		return "unknown"
	}
	return name
}
