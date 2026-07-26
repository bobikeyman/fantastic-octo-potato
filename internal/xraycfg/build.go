// Package xraycfg собирает конфигурацию Xray-core из model.Node.
//
// Схема полей выверена по infra/conf текущей версии ядра, а не по документации:
// Xray переименовывает и удаляет транспорты между релизами (tcpSettings ->
// rawSettings, splithttp -> xhttp, удалённые h2 и quic).
package xraycfg

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/bobivpn/checker/internal/model"
)

// Options управляет сборкой конфига.
type Options struct {
	// Tag аутбаунда. Пустой — "proxy".
	Tag string
	// AllowInsecure разрешает отключить проверку сертификата.
	//
	// По умолчанию false ДАЖЕ если ключ просит allowInsecure=1: основная
	// проверка идёт со строгой валидацией TLS, иначе нода-перехватчик
	// проходит её, подсунув собственный сертификат. Ключи, которым это
	// действительно нужно, перепроверяются отдельным проходом с true
	// и уходят в корзину tier=insecure.
	AllowInsecure bool
}

type outbound struct {
	Tag            string          `json:"tag,omitempty"`
	Protocol       string          `json:"protocol"`
	Settings       any             `json:"settings"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
}

type vnextSettings struct {
	Vnext []vnextServer `json:"vnext"`
}

type vnextServer struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Users   []any  `json:"users"`
}

type vlessUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}

type vmessUser struct {
	ID       string `json:"id"`
	Security string `json:"security,omitempty"`
	AlterID  int    `json:"alterId"`
}

type serversSettings struct {
	Servers []any `json:"servers"`
}

type trojanServer struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Password string `json:"password"`
}

type shadowsocksServer struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

type streamSettings struct {
	Network  string `json:"network"`
	Security string `json:"security,omitempty"`

	TLSSettings     *tlsSettings     `json:"tlsSettings,omitempty"`
	RealitySettings *realitySettings `json:"realitySettings,omitempty"`

	RAWSettings         *rawSettings         `json:"rawSettings,omitempty"`
	WSSettings          *wsSettings          `json:"wsSettings,omitempty"`
	GRPCSettings        *grpcSettings        `json:"grpcSettings,omitempty"`
	XHTTPSettings       *xhttpSettings       `json:"xhttpSettings,omitempty"`
	HTTPUpgradeSettings *httpUpgradeSettings `json:"httpupgradeSettings,omitempty"`
	KCPSettings         *kcpSettings         `json:"kcpSettings,omitempty"`
}

type tlsSettings struct {
	ServerName    string   `json:"serverName,omitempty"`
	AllowInsecure bool     `json:"allowInsecure"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
}

type realitySettings struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type rawSettings struct {
	Header json.RawMessage `json:"header,omitempty"`
}

type wsSettings struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type grpcSettings struct {
	ServiceName string `json:"serviceName"`
	MultiMode   bool   `json:"multiMode,omitempty"`
	Authority   string `json:"authority,omitempty"`
}

type xhttpSettings struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
	Mode string `json:"mode,omitempty"`
}

type httpUpgradeSettings struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type kcpSettings struct {
	Seed   string          `json:"seed,omitempty"`
	Header json.RawMessage `json:"header,omitempty"`
}

// Outbound собирает описание аутбаунда для ноды.
func Outbound(n *model.Node, opts Options) (any, error) {
	tag := opts.Tag
	if tag == "" {
		tag = "proxy"
	}

	stream, err := buildStream(n, opts)
	if err != nil {
		return nil, err
	}

	ob := &outbound{Tag: tag, StreamSettings: stream}

	switch n.Protocol {
	case model.ProtoVLESS:
		enc := n.Encryption
		if enc == "" {
			enc = "none"
		}
		ob.Protocol = "vless"
		ob.Settings = vnextSettings{Vnext: []vnextServer{{
			Address: n.Server,
			Port:    n.Port,
			Users:   []any{vlessUser{ID: n.UUID, Encryption: enc, Flow: n.Flow}},
		}}}

	case model.ProtoVMess:
		ob.Protocol = "vmess"
		ob.Settings = vnextSettings{Vnext: []vnextServer{{
			Address: n.Server,
			Port:    n.Port,
			Users:   []any{vmessUser{ID: n.UUID, Security: n.Encryption, AlterID: n.AlterID}},
		}}}

	case model.ProtoTrojan:
		ob.Protocol = "trojan"
		ob.Settings = serversSettings{Servers: []any{trojanServer{
			Address: n.Server, Port: n.Port, Password: n.Password,
		}}}

	case model.ProtoShadowsocks:
		ob.Protocol = "shadowsocks"
		ob.Settings = serversSettings{Servers: []any{shadowsocksServer{
			Address: n.Server, Port: n.Port, Method: n.Method, Password: n.Password,
		}}}

	default:
		return nil, fmt.Errorf("xraycfg: неизвестный протокол %q", n.Protocol)
	}

	return ob, nil
}

func buildStream(n *model.Node, opts Options) (*streamSettings, error) {
	s := &streamSettings{Network: string(n.Transport)}

	switch n.Security {
	case model.SecTLS:
		s.Security = "tls"
		s.TLSSettings = &tlsSettings{
			ServerName: n.SNI,
			// Ключ просит allowInsecure — уважаем только если это разрешено вызовом.
			AllowInsecure: opts.AllowInsecure && n.AllowInsecure,
			Fingerprint:   n.TLSFingerprint,
			ALPN:          n.ALPN,
		}

	case model.SecReality:
		fp := n.TLSFingerprint
		if fp == "" {
			// REALITY без отпечатка uTLS вырождается в обычный Go-хендшейк
			// и палится по JA3 — ядро ожидает здесь непустое значение.
			fp = "chrome"
		}
		s.Security = "reality"
		s.RealitySettings = &realitySettings{
			ServerName:  n.SNI,
			Fingerprint: fp,
			PublicKey:   n.PublicKey,
			ShortID:     n.ShortID,
			SpiderX:     n.SpiderX,
		}

	default:
		s.Security = "none"
	}

	switch n.Transport {
	case model.TransportRaw:
		if n.HeaderType == "http" {
			hdr, err := rawHTTPHeader(n)
			if err != nil {
				return nil, err
			}
			s.RAWSettings = &rawSettings{Header: hdr}
		}

	case model.TransportWS:
		s.WSSettings = &wsSettings{Path: n.Path, Host: n.Host}

	case model.TransportHTTPUpgrade:
		s.HTTPUpgradeSettings = &httpUpgradeSettings{Path: n.Path, Host: n.Host}

	case model.TransportXHTTP:
		s.XHTTPSettings = &xhttpSettings{Path: n.Path, Host: n.Host, Mode: n.Mode}

	case model.TransportGRPC:
		s.GRPCSettings = &grpcSettings{
			ServiceName: n.ServiceName,
			MultiMode:   n.Mode == "multi",
			Authority:   n.Host,
		}

	case model.TransportKCP:
		kcp := &kcpSettings{Seed: n.Seed}
		if n.HeaderType != "" && n.HeaderType != "none" {
			kcp.Header = json.RawMessage(`{"type":` + quote(n.HeaderType) + `}`)
		}
		s.KCPSettings = kcp

	default:
		return nil, fmt.Errorf("xraycfg: неизвестный транспорт %q", n.Transport)
	}

	return s, nil
}

// rawHTTPHeader собирает обфускацию сырого TCP под HTTP-запрос.
func rawHTTPHeader(n *model.Node) (json.RawMessage, error) {
	host := n.Host
	if host == "" {
		host = n.Server
	}
	path := n.Path
	if path == "" {
		path = "/"
	}
	hdr := map[string]any{
		"type": "http",
		"request": map[string]any{
			"path":    []string{path},
			"headers": map[string][]string{"Host": {host}},
		},
	}
	return json.Marshal(hdr)
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// FullConfig собирает минимальный самодостаточный конфиг Xray с одним
// аутбаундом и без инбаундов.
//
// Инбаунды не нужны: проверка ходит через core.Dial напрямую, поэтому
// SOCKS-портов и связанных с ними гонок в этой схеме не существует.
func FullConfig(n *model.Node, opts Options) ([]byte, error) {
	ob, err := Outbound(n, opts)
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"outbounds": []any{ob},
		// AsIs: домен уезжает на ноду как домен, а не резолвится локально.
		// Заодно проверяется DNS самой ноды.
		"routing": map[string]any{"domainStrategy": "AsIs"},
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
