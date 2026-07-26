package parse

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/bobivpn/checker/internal/model"
)

// flexString принимает и "443", и 443 — подписки пишут числа обоими способами.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	b = trimJSONSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	*f = flexString(strings.TrimSpace(string(b)))
	return nil
}

func (f flexString) String() string { return strings.TrimSpace(string(f)) }

func (f flexString) Int() int {
	v, err := strconv.Atoi(f.String())
	if err != nil {
		return 0
	}
	return v
}

func trimJSONSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 {
		c := b[len(b)-1]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			b = b[:len(b)-1]
			continue
		}
		break
	}
	return b
}

// vmessJSON — формат "vmess v2" из base64-тела ссылки.
type vmessJSON struct {
	PS   flexString `json:"ps"`
	Add  flexString `json:"add"`
	Port flexString `json:"port"`
	ID   flexString `json:"id"`
	Aid  flexString `json:"aid"`
	Scy  flexString `json:"scy"`
	Net  flexString `json:"net"`
	Type flexString `json:"type"`
	Host flexString `json:"host"`
	Path flexString `json:"path"`
	TLS  flexString `json:"tls"`
	SNI  flexString `json:"sni"`
	ALPN flexString `json:"alpn"`
	FP   flexString `json:"fp"`
	// Некоторые генераторы кладут allowInsecure сюда.
	Verify flexString `json:"verify_cert"`
	Skip   flexString `json:"skip-cert-verify"`
}

// parseVMess: vmess://<base64 json>#name
func parseVMess(raw string) (*model.Node, error) {
	body, fragName := splitFragment(raw)
	payload := strings.TrimPrefix(body, "vmess://")
	payload = strings.TrimPrefix(payload, "VMESS://")

	data, err := decodeBase64(payload)
	if err != nil {
		// Изредка тело кладут как plain JSON без base64.
		if s := strings.TrimSpace(payload); strings.HasPrefix(s, "{") {
			data = []byte(s)
		} else {
			return nil, err
		}
	}

	var v vmessJSON
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, errf(ReasonMalformed, "vmess json: %v", err)
	}

	host := cleanHost(v.Add.String())
	if host == "" {
		return nil, errf(ReasonBadHost, "empty add")
	}
	port, err := parsePort(v.Port.String())
	if err != nil {
		return nil, err
	}
	if v.ID.String() == "" {
		return nil, errf(ReasonEmptyCredentials, "no id")
	}

	name := fragName
	if name == "" {
		name = v.PS.String()
	}

	security := model.SecNone
	if s := strings.ToLower(v.TLS.String()); s == "tls" || s == "xtls" {
		security = model.SecTLS
	} else if s == "reality" {
		security = model.SecReality
	}

	scy := v.Scy.String()
	if scy == "" {
		scy = "auto"
	}

	n := &model.Node{
		Raw:            raw,
		Name:           name,
		Protocol:       model.ProtoVMess,
		Server:         host,
		Port:           port,
		UUID:           v.ID.String(),
		AlterID:        v.Aid.Int(),
		Encryption:     scy,
		Security:       security,
		SNI:            cleanHost(v.SNI.String()),
		TLSFingerprint: v.FP.String(),
		ALPN:           splitALPN(v.ALPN.String()),
		AllowInsecure:  truthy(v.Skip.String()) || v.Verify.String() == "false",
	}

	n.Transport, err = normalizeTransport(v.Net.String())
	if err != nil {
		return nil, err
	}

	// В vmess-JSON поля host/path/type перегружены: их смысл зависит от net.
	vHost := firstHost(v.Host.String())
	vPath := v.Path.String()
	vType := strings.ToLower(v.Type.String())

	switch n.Transport {
	case model.TransportWS, model.TransportHTTPUpgrade, model.TransportXHTTP:
		n.Path = pathOrRoot(vPath)
		n.Host = vHost
		if n.Transport == model.TransportXHTTP {
			n.Mode = vType
		}
	case model.TransportGRPC:
		// Для grpc в path лежит serviceName, а в type — режим (gun/multi).
		n.ServiceName = strings.TrimPrefix(strings.TrimSpace(vPath), "/")
		n.Mode = vType
		n.Host = vHost
	case model.TransportKCP:
		n.Seed = strings.TrimSpace(vPath)
		n.HeaderType = headerTypeOrNone(vType)
	case model.TransportRaw:
		n.HeaderType = headerTypeOrNone(vType)
		if n.HeaderType == "http" {
			n.Path = pathOrRoot(vPath)
			n.Host = vHost
		}
	}

	if n.SNI == "" && n.Security == model.SecTLS {
		n.SNI = cleanHost(firstNonEmpty(n.Host, n.Server))
	}

	return n, nil
}
