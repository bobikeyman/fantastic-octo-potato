package parse

import (
	"net"
	"net/url"
	"strings"

	"github.com/bobivpn/checker/internal/model"
)

// Методы Shadowsocks, которые умеет Xray-core.
// Ключ — канонический вид, значение — он же; алиасы разворачиваются отдельно.
var ssMethods = map[string]string{
	"aes-128-gcm":                   "aes-128-gcm",
	"aes-256-gcm":                   "aes-256-gcm",
	"chacha20-poly1305":             "chacha20-poly1305",
	"chacha20-ietf-poly1305":        "chacha20-poly1305",
	"xchacha20-poly1305":            "xchacha20-poly1305",
	"xchacha20-ietf-poly1305":       "xchacha20-poly1305",
	"2022-blake3-aes-128-gcm":       "2022-blake3-aes-128-gcm",
	"2022-blake3-aes-256-gcm":       "2022-blake3-aes-256-gcm",
	"2022-blake3-chacha20-poly1305": "2022-blake3-chacha20-poly1305",
	"none":                          "none",
	"plain":                         "none",
}

// parseShadowsocks поддерживает три встречающихся формата:
//
//	SIP002 c base64-userinfo : ss://BASE64(method:pass)@host:port/?plugin=...#name
//	SIP002 c plain userinfo  : ss://method:pass@host:port#name
//	legacy, всё в base64     : ss://BASE64(method:pass@host:port)#name
func parseShadowsocks(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)
	rest := strings.TrimPrefix(body, "ss://")
	rest = strings.TrimPrefix(rest, "SS://")

	mainPart, rawQuery, _ := strings.Cut(rest, "?")
	q := query(rawQuery)

	// Часть подписок публикует VLESS-ключи со схемой ss:// — узнаём их по UUID
	// в userinfo вместе с параметрами, которых у Shadowsocks не бывает.
	// Без этого они уходили бы в malformed.
	//
	// Схему в Raw чиним: пользователю нужна ссылка, которая заведётся в клиенте.
	if mislabeledVLESS(mainPart, q) {
		corrected := "vless://" + raw[strings.Index(raw, "://")+3:]
		return parseVLESS(corrected)
	}

	// Xray-core не реализует SIP003-плагины (obfs-local, v2ray-plugin).
	// Отсеиваем явно и считаем отдельно, а не молча ломаем пароль,
	// как это делал старый чекер.
	if plugin := strings.TrimSpace(q.Get("plugin")); plugin != "" {
		pluginName, _, _ := strings.Cut(plugin, ";")
		return nil, errf(ReasonUnsupportedPlugin, "%s", pluginName)
	}

	var userInfo, hostPort string
	if i := strings.LastIndexByte(mainPart, '@'); i >= 0 {
		userInfo, hostPort = mainPart[:i], mainPart[i+1:]
	} else {
		decoded, err := decodeBase64(mainPart)
		if err != nil {
			return nil, err
		}
		s := string(decoded)
		i := strings.LastIndexByte(s, '@')
		if i < 0 {
			return nil, errf(ReasonMalformed, "legacy ss without @")
		}
		userInfo, hostPort = s[:i], s[i+1:]
	}

	method, password, err := splitSSUserInfo(userInfo)
	if err != nil {
		return nil, err
	}

	canon, ok := ssMethods[strings.ToLower(method)]
	if !ok {
		return nil, errf(ReasonUnsupportedMethod, "%s", method)
	}
	if password == "" && canon != "none" {
		return nil, errf(ReasonEmptyCredentials, "no password")
	}

	host, portStr, err := splitHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}

	n := &model.Node{
		Raw:       raw,
		Name:      name,
		Protocol:  model.ProtoShadowsocks,
		Server:    cleanHost(host),
		Port:      port,
		Method:    canon,
		Password:  password,
		Security:  normalizeSecurity(q.Get("security")),
		Transport: model.TransportRaw,
	}

	// Редко, но встречается ss поверх ws/tls (Xray это поддерживает).
	if t := q.Get("type"); strings.TrimSpace(t) != "" {
		n.Transport, err = normalizeTransport(t)
		if err != nil {
			return nil, err
		}
	}
	applyStreamParams(n, q)

	return n, nil
}

// mislabeledVLESS распознаёт VLESS-ключ, опубликованный под схемой ss://.
//
// Признак — UUID в userinfo плюс параметр, которого у Shadowsocks не бывает
// в принципе. Ложное срабатывание практически исключено: у настоящего ss
// userinfo это либо base64, либо method:password, и ни то ни другое не имеет
// формы UUID.
func mislabeledVLESS(mainPart string, q url.Values) bool {
	i := strings.LastIndexByte(mainPart, '@')
	if i < 0 {
		return false
	}
	if !uuidShaped(mainPart[:i]) {
		return false
	}
	return q.Has("encryption") || q.Has("type") || q.Has("flow") ||
		strings.EqualFold(q.Get("security"), "reality")
}

func uuidShaped(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHexDigit(r) {
				return false
			}
		}
	}
	return true
}

// splitSSUserInfo разбирает "method:password", учитывая base64 и percent-encoding.
func splitSSUserInfo(userInfo string) (method, password string, err error) {
	if unescaped, e := url.QueryUnescape(userInfo); e == nil {
		userInfo = unescaped
	}

	// Двоеточия нет в алфавите base64, поэтому его наличие однозначно означает
	// plain-форму method:password (типично для 2022-blake3-*).
	if m, p, ok := strings.Cut(userInfo, ":"); ok {
		return m, p, nil
	}

	// Иначе это канонический SIP002 с base64-userinfo.
	decoded, e := decodeBase64(userInfo)
	if e != nil {
		return "", "", errf(ReasonMalformed, "ss userinfo: не base64 и не method:password")
	}
	m, p, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", errf(ReasonMalformed, "ss userinfo without ':'")
	}
	return m, p, nil
}

// splitHostPort устойчив к завершающему слэшу и к IPv6 в скобках.
func splitHostPort(s string) (host, port string, err error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), "/")
	if s == "" {
		return "", "", errf(ReasonBadHost, "empty")
	}
	h, p, e := net.SplitHostPort(s)
	if e != nil {
		return "", "", errf(ReasonMalformed, "host:port %q: %v", s, e)
	}
	if h == "" {
		return "", "", errf(ReasonBadHost, "empty")
	}
	return h, p, nil
}
