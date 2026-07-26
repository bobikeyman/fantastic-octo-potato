package parse

import (
	"net/url"
	"strings"

	"github.com/bobivpn/checker/internal/model"
)

// parseVLESS: vless://uuid@host:port?params#name
func parseVLESS(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, errf(ReasonMalformed, "%v", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errf(ReasonEmptyCredentials, "no uuid")
	}
	host := cleanHost(u.Hostname())
	if host == "" {
		return nil, errf(ReasonBadHost, "empty")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}

	q := query(u.RawQuery)
	n := &model.Node{
		Raw:        raw,
		Name:       name,
		Protocol:   model.ProtoVLESS,
		Server:     host,
		Port:       port,
		UUID:       strings.TrimSpace(u.User.Username()),
		Encryption: firstNonEmpty(q.Get("encryption"), "none"),
		Security:   normalizeSecurity(q.Get("security")),
		Flow:       strings.TrimSpace(q.Get("flow")),
	}

	n.Transport, err = normalizeTransport(q.Get("type"))
	if err != nil {
		return nil, err
	}

	applyStreamParams(n, q)
	return n, nil
}

// applyStreamParams заполняет транспортные и TLS-поля из query-параметров.
// Общее для vless и trojan — формат ссылок у них одинаковый.
func applyStreamParams(n *model.Node, q url.Values) {
	// --- TLS / REALITY ---
	n.SNI = cleanHost(firstNonEmpty(q.Get("sni"), q.Get("peer")))
	n.TLSFingerprint = strings.TrimSpace(q.Get("fp"))
	n.ALPN = splitALPN(q.Get("alpn"))
	n.AllowInsecure = truthy(q.Get("allowInsecure")) ||
		truthy(q.Get("allow_insecure")) ||
		truthy(q.Get("insecure")) ||
		truthy(q.Get("skip-cert-verify"))

	if n.Security == model.SecReality {
		n.PublicKey = strings.TrimSpace(q.Get("pbk"))
		n.ShortID = strings.TrimSpace(q.Get("sid"))
		n.SpiderX = strings.TrimSpace(q.Get("spx"))
	}

	// --- транспорт ---
	switch n.Transport {
	case model.TransportWS, model.TransportHTTPUpgrade:
		n.Path = pathOrRoot(q.Get("path"))
		n.Host = firstHost(firstNonEmpty(q.Get("host"), q.Get("Host")))

	case model.TransportXHTTP:
		n.Path = pathOrRoot(q.Get("path"))
		n.Host = firstHost(q.Get("host"))
		n.Mode = strings.TrimSpace(q.Get("mode"))

	case model.TransportGRPC:
		// serviceName — канон; часть подписок кладёт его в path.
		n.ServiceName = strings.TrimSpace(firstNonEmpty(q.Get("serviceName"), q.Get("path")))
		n.ServiceName = strings.TrimPrefix(n.ServiceName, "/")
		n.Mode = strings.TrimSpace(q.Get("mode"))
		n.Host = firstHost(q.Get("authority"))

	case model.TransportHTTP:
		n.Path = pathOrRoot(q.Get("path"))
		n.Host = firstHost(q.Get("host"))

	case model.TransportKCP:
		n.Seed = strings.TrimSpace(q.Get("seed"))
		n.HeaderType = headerTypeOrNone(q.Get("headerType"))

	case model.TransportRaw:
		n.HeaderType = headerTypeOrNone(q.Get("headerType"))
		if n.HeaderType == "http" {
			// Обфускация под HTTP: host/path значимы.
			n.Path = pathOrRoot(q.Get("path"))
			n.Host = firstHost(q.Get("host"))
		}
	}

	// SNI по умолчанию: для TLS берём Host-заголовок, иначе адрес сервера.
	// Для REALITY подстановка запрещена — там serverName обязателен явно,
	// подставленный адрес сервера сломает рукопожатие.
	if n.SNI == "" && n.Security == model.SecTLS {
		n.SNI = cleanHost(firstNonEmpty(n.Host, n.Server))
	}
}

func pathOrRoot(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "/"
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return s
}

func headerTypeOrNone(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "none"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
