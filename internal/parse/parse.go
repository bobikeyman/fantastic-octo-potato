// Package parse превращает подписочные URI в канонические model.Node.
//
// Разбор намеренно отделён от валидации (см. validate.go): парсер вытаскивает то,
// что записано в ссылке, а валидатор решает, имеет ли это смысл для Xray.
package parse

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/bobivpn/checker/internal/model"
)

// Reason — машиночитаемая причина отбраковки. Идёт в счётчики отчёта.
type Reason string

const (
	ReasonUnsupportedProtocol  Reason = "unsupported_protocol"
	ReasonUnsupportedTransport Reason = "unsupported_transport"
	ReasonUnsupportedMethod    Reason = "unsupported_method"
	ReasonUnsupportedPlugin    Reason = "unsupported_plugin"
	ReasonMalformed            Reason = "malformed"
	ReasonBadBase64            Reason = "bad_base64"
	ReasonBadPort              Reason = "bad_port"
	ReasonBadHost              Reason = "bad_host"
	ReasonBadUUID              Reason = "bad_uuid"
	ReasonBadReality           Reason = "bad_reality"
	ReasonBadFlow              Reason = "bad_flow"
	ReasonBadEncryption        Reason = "bad_encryption"
	ReasonLegacyVMess          Reason = "legacy_vmess"
	ReasonEmptyCredentials     Reason = "empty_credentials"
)

// Error — ошибка разбора с машиночитаемой причиной.
type Error struct {
	Reason Reason
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Reason)
	}
	return string(e.Reason) + ": " + e.Detail
}

func errf(r Reason, format string, args ...any) *Error {
	return &Error{Reason: r, Detail: fmt.Sprintf(format, args...)}
}

// Protocols, которые встречаются в подписках, но Xray-core их не поддерживает.
// Отсеиваем явно, чтобы они попали в статистику, а не в общий мусор.
var unsupportedSchemes = map[string]bool{
	"hysteria":  true,
	"hysteria2": true,
	"hy2":       true,
	"hy":        true,
	"tuic":      true,
	"anytls":    true,
	"ssr":       true,
	"wireguard": true,
	"wg":        true,
	"juicity":   true,
	"snell":     true,
	"mieru":     true,
}

// URI разбирает одну подписочную ссылку.
func URI(raw string) (*model.Node, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errf(ReasonMalformed, "empty")
	}

	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, errf(ReasonMalformed, "no scheme separator")
	}
	scheme = strings.ToLower(scheme)

	if unsupportedSchemes[scheme] {
		return nil, errf(ReasonUnsupportedProtocol, "%s", scheme)
	}

	switch scheme {
	case "vless":
		return parseVLESS(raw)
	case "vmess":
		return parseVMess(raw)
	case "trojan":
		return parseTrojan(raw)
	case "ss":
		return parseShadowsocks(raw)
	default:
		return nil, errf(ReasonUnsupportedProtocol, "%s", scheme)
	}
}

// ---------- общие хелперы ----------

// splitFragment отрезает #имя по ПЕРВОМУ '#'.
//
// Старый Python-чекер резал по последнему ('rsplit'), что ломало имена,
// содержащие решётку.
func splitFragment(raw string) (body, name string) {
	body, frag, ok := strings.Cut(raw, "#")
	if !ok {
		return body, ""
	}
	if unescaped, err := url.PathUnescape(frag); err == nil {
		return body, strings.TrimSpace(unescaped)
	}
	return body, strings.TrimSpace(frag)
}

// decodeBase64 пробует все четыре варианта кодирования, встречающиеся в подписках.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' {
			return -1
		}
		return r
	}, s)
	if s == "" {
		return nil, errf(ReasonBadBase64, "empty")
	}

	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.StdEncoding,
	}
	stripped := strings.TrimRight(s, "=")
	for _, enc := range encodings {
		in := stripped
		if enc == base64.URLEncoding || enc == base64.StdEncoding {
			if pad := len(stripped) % 4; pad != 0 {
				in = stripped + strings.Repeat("=", 4-pad)
			}
		}
		if out, err := enc.DecodeString(in); err == nil {
			return out, nil
		}
	}
	return nil, errf(ReasonBadBase64, "%.32s", s)
}

// parsePort принимает порт строкой; пустой/невалидный — ошибка, а не молчаливый 443.
func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errf(ReasonBadPort, "empty")
	}
	// Некоторые подписки пишут диапазон "443,8443" или "2000-3000" (port hopping).
	// Xray такого не умеет — берём первый порт.
	if i := strings.IndexAny(s, ",-"); i > 0 {
		s = s[:i]
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, errf(ReasonBadPort, "%q", s)
	}
	if p < 1 || p > 65535 {
		return 0, errf(ReasonBadPort, "%d out of range", p)
	}
	return p, nil
}

// normalizeTransport приводит все встречающиеся написания к Xray-неймингу.
func normalizeTransport(s string) (model.Transport, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "tcp", "raw", "none":
		return model.TransportRaw, nil
	case "ws", "websocket":
		return model.TransportWS, nil
	case "grpc", "gun":
		return model.TransportGRPC, nil
	case "http", "h2", "h2c", "h3", "quic":
		// Xray-core удалил HTTP/2- и QUIC-транспорты (PrintRemovedFeatureError):
		// конфиг с ними не соберётся. Отбраковываем с внятной причиной,
		// чтобы такие ключи были видны в статистике, а не падали позже.
		return "", errf(ReasonUnsupportedTransport, "%s удалён в xray-core", s)
	case "httpupgrade":
		return model.TransportHTTPUpgrade, nil
	case "xhttp", "splithttp":
		return model.TransportXHTTP, nil
	case "kcp", "mkcp":
		return model.TransportKCP, nil
	default:
		return "", errf(ReasonUnsupportedTransport, "%s", s)
	}
}

// normalizeSecurity. Встречается мусор вида security=false — это none.
func normalizeSecurity(s string) model.Security {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tls", "xtls":
		return model.SecTLS
	case "reality":
		return model.SecReality
	default:
		return model.SecNone
	}
}

// truthy распознаёт 1/true/yes, которыми в подписках пишут allowInsecure.
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y":
		return true
	}
	return false
}

// splitALPN разбирает "h2,http/1.1" в срез.
func splitALPN(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// firstHost берёт первый хост из списка "a.com,b.com" — так пишут ws Host.
func firstHost(s string) string {
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// query разбирает строку параметров, не падая на битых кусках.
//
// url.ParseQuery возвращает уже раскодированные значения вместе с ошибкой на
// повреждённых парах — берём то, что удалось разобрать. Старый чекер делал
// split('=') без раскодирования, поэтому path=%2Fws доезжал до конфига как есть.
func query(rawQuery string) url.Values {
	v, _ := url.ParseQuery(rawQuery)
	return v
}

// cleanHost убирает квадратные скобки IPv6 и завершающую точку домена.
func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return strings.TrimSuffix(h, ".")
}
