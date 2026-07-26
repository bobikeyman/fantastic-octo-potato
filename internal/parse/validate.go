package parse

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/bobivpn/checker/internal/model"
)

// Validate отбраковывает ноды, которые Xray заведомо не примет или которые
// не могут работать по смыслу.
//
// Это дешёвый фильтр перед дорогой сборкой конфига. Последнее слово всё равно
// за core.New() в internal/xraycfg — здесь ловится только то, что можно
// проверить без него, зато с внятной причиной для отчёта.
func Validate(n *model.Node) error {
	if err := validateHost(n.Server); err != nil {
		return err
	}
	if n.Port < 1 || n.Port > 65535 {
		return errf(ReasonBadPort, "%d", n.Port)
	}

	switch n.Protocol {
	case model.ProtoVLESS:
		if err := validateUUID(n.UUID); err != nil {
			return err
		}
		if err := validateEncryption(n.Encryption); err != nil {
			return err
		}
	case model.ProtoVMess:
		if err := validateUUID(n.UUID); err != nil {
			return err
		}
		// Xray работает только с VMessAEAD; alterId > 0 — это выпиленный
		// legacy-режим, такие ключи не поднимутся.
		if n.AlterID > 0 {
			return errf(ReasonLegacyVMess, "alterId=%d", n.AlterID)
		}
	case model.ProtoTrojan, model.ProtoShadowsocks:
		if n.Password == "" && n.Method != "none" {
			return errf(ReasonEmptyCredentials, "no password")
		}
	}

	if n.Security == model.SecReality {
		if err := validateReality(n); err != nil {
			return err
		}
	}
	return validateFlow(n)
}

func validateHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errf(ReasonBadHost, "empty")
	}
	if strings.EqualFold(host, "localhost") {
		return errf(ReasonBadHost, "localhost")
	}
	// Домены проверяем только на явный мусор — резолв будет позже.
	addr, err := netip.ParseAddr(host)
	if err != nil {
		if strings.ContainsAny(host, " \t/\\") || !strings.Contains(host, ".") {
			return errf(ReasonBadHost, "%q", host)
		}
		return nil
	}
	switch {
	case addr.IsLoopback():
		return errf(ReasonBadHost, "loopback %s", host)
	case addr.IsPrivate():
		return errf(ReasonBadHost, "private %s", host)
	case addr.IsUnspecified():
		return errf(ReasonBadHost, "unspecified %s", host)
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return errf(ReasonBadHost, "link-local %s", host)
	case addr.IsMulticast():
		return errf(ReasonBadHost, "multicast %s", host)
	}
	// 100.64.0.0/10 — CGNAT, снаружи недостижим.
	if addr.Is4() && addr.As4()[0] == 100 && addr.As4()[1] >= 64 && addr.As4()[1] <= 127 {
		return errf(ReasonBadHost, "cgnat %s", host)
	}
	return nil
}

// validateUUID проверяет строго только то, что выглядит как UUID.
//
// Xray допускает произвольную строку в качестве id, поэтому отбраковывать
// всё, что не 36 символов, нельзя — потеряем рабочие ключи.
func validateUUID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errf(ReasonEmptyCredentials, "empty uuid")
	}
	if len(id) != 36 || strings.Count(id, "-") != 4 {
		return nil // не UUID-подобная строка — решать будет core.New
	}
	for i, r := range id {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return errf(ReasonBadUUID, "%s", id)
			}
		default:
			if !isHexDigit(r) {
				return errf(ReasonBadUUID, "%s", id)
			}
		}
	}
	return nil
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// validateEncryption ловит мусор в параметре encryption.
//
// Встречается реально: авторы подписок вписывают туда рекламу своего канала
// («encryption=none=/@Telegram-|-@…»). Ядро такой ключ отвергает уже на
// сборке конфига — ловим раньше и с внятной причиной.
//
// Проверка намеренно мягкая: у VLESS кроме "none" бывают длинные строки
// пост-квантового шифрования, поэтому режем только по символам,
// которых в имени шифра быть не может.
func validateEncryption(enc string) error {
	enc = strings.TrimSpace(enc)
	if enc == "" {
		return nil
	}
	if len(enc) > 512 {
		return errf(ReasonBadEncryption, "слишком длинное (%d)", len(enc))
	}
	if i := strings.IndexAny(enc, "@|<>#\" \t\r\n"); i >= 0 {
		return errf(ReasonBadEncryption, "запрещённый символ %q", enc[i])
	}
	return nil
}

func validateReality(n *model.Node) error {
	// serverName для REALITY обязателен: подставить адрес сервера, как делают
	// наивные конвертеры, нельзя — рукопожатие сломается.
	if strings.TrimSpace(n.SNI) == "" {
		return errf(ReasonBadReality, "no sni")
	}
	pbk := strings.TrimSpace(n.PublicKey)
	if pbk == "" {
		return errf(ReasonBadReality, "no pbk")
	}
	// X25519-ключ: 32 байта в base64url без паддинга -> 43 символа.
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(pbk, "="))
	if err != nil || len(key) != 32 {
		return errf(ReasonBadReality, "bad pbk %.12s", pbk)
	}
	sid := strings.TrimSpace(n.ShortID)
	if sid == "" {
		return nil // пустой shortId допустим
	}
	if len(sid) > 16 || len(sid)%2 != 0 {
		return errf(ReasonBadReality, "bad sid %q", sid)
	}
	if _, err := hex.DecodeString(sid); err != nil {
		return errf(ReasonBadReality, "sid not hex %q", sid)
	}
	return nil
}

// validateFlow ловит комбинацию, которую старый чекер прокидывал в конфиг вслепую.
func validateFlow(n *model.Node) error {
	flow := strings.TrimSpace(n.Flow)
	if flow == "" {
		return nil
	}
	if n.Protocol != model.ProtoVLESS {
		return errf(ReasonBadFlow, "%s with %s", flow, n.Protocol)
	}
	if !strings.HasPrefix(flow, "xtls-rprx-vision") {
		return errf(ReasonBadFlow, "unknown flow %q", flow)
	}
	// XTLS Vision требует TLS или REALITY.
	if n.Security == model.SecNone {
		return errf(ReasonBadFlow, "vision without tls")
	}
	// ...и работает только поверх сырого TCP.
	if n.Transport != model.TransportRaw {
		return errf(ReasonBadFlow, "vision over %s", n.Transport)
	}
	return nil
}
