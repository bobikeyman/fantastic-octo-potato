// Package model содержит канонические структуры данных чекера.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Protocol — протокол прокси.
type Protocol string

const (
	ProtoVLESS       Protocol = "vless"
	ProtoVMess       Protocol = "vmess"
	ProtoTrojan      Protocol = "trojan"
	ProtoShadowsocks Protocol = "ss"
)

// Security — тип шифрования транспортного слоя.
type Security string

const (
	SecNone    Security = "none"
	SecTLS     Security = "tls"
	SecReality Security = "reality"
)

// Transport — тип транспорта. Используется Xray-нейминг: raw вместо tcp.
type Transport string

const (
	TransportRaw         Transport = "raw"
	TransportWS          Transport = "ws"
	TransportGRPC        Transport = "grpc"
	TransportHTTPUpgrade Transport = "httpupgrade"
	TransportXHTTP       Transport = "xhttp" // бывший splithttp
	TransportKCP         Transport = "kcp"
)

// Node — канонический разобранный ключ.
//
// Поля заполняются парсерами из internal/parse и потребляются internal/xraycfg.
// Raw сохраняется, чтобы выдавать пользователю исходную ссылку без потерь.
type Node struct {
	Raw  string `json:"raw"`
	Name string `json:"name,omitempty"` // из #fragment

	Protocol Protocol `json:"protocol"`
	Server   string   `json:"server"`
	Port     int      `json:"port"`

	// Аутентификация
	UUID       string `json:"uuid,omitempty"`       // vless, vmess
	Password   string `json:"password,omitempty"`   // trojan, ss
	Method     string `json:"method,omitempty"`     // ss
	AlterID    int    `json:"alter_id,omitempty"`   // vmess
	Encryption string `json:"encryption,omitempty"` // vless: none; vmess: scy

	// Транспортный слой
	Security       Security  `json:"security"`
	Transport      Transport `json:"transport"`
	SNI            string    `json:"sni,omitempty"`
	Host           string    `json:"host,omitempty"` // Host-заголовок ws/http
	Path           string    `json:"path,omitempty"`
	ServiceName    string    `json:"service_name,omitempty"` // grpc
	ALPN           []string  `json:"alpn,omitempty"`
	TLSFingerprint string    `json:"tls_fingerprint,omitempty"` // uTLS: chrome, firefox, …
	AllowInsecure  bool      `json:"allow_insecure,omitempty"`
	Flow           string    `json:"flow,omitempty"`

	// REALITY
	PublicKey string `json:"public_key,omitempty"` // pbk
	ShortID   string `json:"short_id,omitempty"`   // sid
	SpiderX   string `json:"spider_x,omitempty"`   // spx

	// Дополнительно
	Mode       string `json:"mode,omitempty"`        // xhttp/grpc
	HeaderType string `json:"header_type,omitempty"` // raw/kcp обфускация
	Seed       string `json:"seed,omitempty"`        // kcp

	fp string // кэш отпечатка
}

// Endpoint возвращает "host:port".
func (n *Node) Endpoint() string {
	return n.Server + ":" + strconv.Itoa(n.Port)
}

// Fingerprint — стабильный отпечаток ноды БЕЗ имени (#fragment).
//
// Ключ отличается от других только именем встречается в подписках десятками копий;
// дедуп по Raw (как в старом Python-чекере) их не склеивает и множит работу втрое.
func (n *Node) Fingerprint() string {
	if n.fp != "" {
		return n.fp
	}
	var b strings.Builder
	write := func(parts ...string) {
		for _, p := range parts {
			b.WriteString(p)
			b.WriteByte('|')
		}
	}
	write(
		string(n.Protocol),
		strings.ToLower(n.Server),
		strconv.Itoa(n.Port),
		n.UUID,
		n.Password,
		n.Method,
		string(n.Security),
		string(n.Transport),
		strings.ToLower(n.SNI),
		strings.ToLower(n.Host),
		n.Path,
		n.ServiceName,
		n.Flow,
		n.PublicKey,
		n.ShortID,
		n.Mode,
		n.HeaderType,
	)
	sum := sha256.Sum256([]byte(b.String()))
	n.fp = hex.EncodeToString(sum[:16])
	return n.fp
}

// Tier — корзина качества, в которую попадает ключ.
type Tier string

const (
	// TierMain — прошёл все проверки со строгой валидацией TLS.
	TierMain Tier = "main"
	// TierInsecure — рабочий, но требует отключения проверки сертификата.
	TierInsecure Tier = "insecure"
)
