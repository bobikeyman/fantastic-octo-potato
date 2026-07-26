package parse

import (
	"net/url"
	"strings"

	"github.com/bobivpn/checker/internal/model"
)

// parseTrojan: trojan://password@host:port?params#name
func parseTrojan(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, errf(ReasonMalformed, "%v", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errf(ReasonEmptyCredentials, "no password")
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

	// Trojan по определению работает поверх TLS. Старый чекер жёстко ставил TLS
	// всегда, игнорируя security=none, — из-за этого ключи с plain-транспортом
	// или REALITY получали неверный конфиг.
	security := model.SecTLS
	if v := q.Get("security"); strings.TrimSpace(v) != "" {
		security = normalizeSecurity(v)
	}

	n := &model.Node{
		Raw:      raw,
		Name:     name,
		Protocol: model.ProtoTrojan,
		Server:   host,
		Port:     port,
		Password: u.User.Username(), // url.Parse уже раскодировал %XX
		Security: security,
		Flow:     strings.TrimSpace(q.Get("flow")),
	}

	n.Transport, err = normalizeTransport(q.Get("type"))
	if err != nil {
		return nil, err
	}

	applyStreamParams(n, q)
	return n, nil
}
