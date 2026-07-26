package parse

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/bobivpn/checker/internal/model"
)

func mustParse(t *testing.T, uri string) *model.Node {
	t.Helper()
	n, err := URI(uri)
	if err != nil {
		t.Fatalf("URI(%.60s…) = %v", uri, err)
	}
	if err := Validate(n); err != nil {
		t.Fatalf("Validate(%.60s…) = %v", uri, err)
	}
	return n
}

func mustReject(t *testing.T, uri string, want Reason) {
	t.Helper()
	n, err := URI(uri)
	if err == nil {
		err = Validate(n)
	}
	if err == nil {
		t.Fatalf("ожидалась отбраковка %q, ключ принят: %.80s", want, uri)
	}
	if got := reasonOf(err); got != want {
		t.Fatalf("причина = %q, ожидалась %q (%v)", got, want, err)
	}
}

// корректный 32-байтовый x25519 pbk в base64url
const testPBK = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"

func TestVLESSReality(t *testing.T) {
	uri := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443" +
		"?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome" +
		"&pbk=" + testPBK + "&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision" +
		"#%F0%9F%87%B7%F0%9F%87%BA%20Moscow"

	n := mustParse(t, uri)

	checks := []struct{ got, want string }{
		{string(n.Protocol), "vless"},
		{n.Server, "example.com"},
		{n.UUID, "b831381d-6324-4d53-ad4f-8cda48b30811"},
		{string(n.Security), "reality"},
		{string(n.Transport), "raw"}, // type=tcp нормализуется в Xray-нейминг
		{n.SNI, "www.microsoft.com"},
		{n.PublicKey, testPBK},
		{n.ShortID, "6ba85179e30d4fc2"},
		{n.Flow, "xtls-rprx-vision"},
		{n.Name, "🇷🇺 Moscow"},
	}
	for i, c := range checks {
		if c.got != c.want {
			t.Errorf("поле %d: got %q, want %q", i, c.got, c.want)
		}
	}
	if n.Port != 443 {
		t.Errorf("port = %d, want 443", n.Port)
	}
}

// type=raw — Xray-нейминг для сырого TCP. Старый чекер его не знал:
// 398 ключей в выхлопе разбирались неверно.
func TestVLESSTypeRaw(t *testing.T) {
	n := mustParse(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:8443"+
		"?security=tls&sni=a.example.org&type=raw#x")
	if n.Transport != model.TransportRaw {
		t.Errorf("transport = %q, want raw", n.Transport)
	}
}

func TestVLESSWebSocketPathDecoded(t *testing.T) {
	// path приезжает percent-encoded; старый чекер не раскодировал его
	// и клал в конфиг как %2Fws%2Flink, ломая соединение.
	n := mustParse(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443"+
		"?type=ws&security=tls&path=%2Fws%2Flink%3Fed%3D2048&host=front.example.com&sni=front.example.com#y")

	if n.Path != "/ws/link?ed=2048" {
		t.Errorf("path = %q, want %q", n.Path, "/ws/link?ed=2048")
	}
	if n.Host != "front.example.com" {
		t.Errorf("host = %q", n.Host)
	}
	if n.Transport != model.TransportWS {
		t.Errorf("transport = %q, want ws", n.Transport)
	}
}

func TestVLESSGRPCServiceNameFromPath(t *testing.T) {
	n := mustParse(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@g.example.com:443"+
		"?type=grpc&security=tls&sni=g.example.com&path=%2FTunService#g")
	if n.ServiceName != "TunService" {
		t.Errorf("serviceName = %q, want TunService", n.ServiceName)
	}
}

func TestVLESSXHTTPAliasSplithttp(t *testing.T) {
	n := mustParse(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@x.example.com:443"+
		"?type=splithttp&security=tls&sni=x.example.com&path=/sh&mode=packet-up#x")
	if n.Transport != model.TransportXHTTP {
		t.Errorf("transport = %q, want xhttp", n.Transport)
	}
	if n.Mode != "packet-up" {
		t.Errorf("mode = %q", n.Mode)
	}
}

// security=false встречается в подписках (9 ключей в текущем выхлопе) — это none.
func TestVLESSSecurityFalseIsNone(t *testing.T) {
	n := mustParse(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:80?security=false&type=tcp#z")
	if n.Security != model.SecNone {
		t.Errorf("security = %q, want none", n.Security)
	}
}

// SNI для REALITY подставлять нельзя — без него ключ нерабочий.
func TestVLESSRealityWithoutSNIRejected(t *testing.T) {
	mustReject(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"+
		"?security=reality&pbk="+testPBK+"&type=tcp#a", ReasonBadReality)
}

func TestVLESSRealityBadPBKRejected(t *testing.T) {
	mustReject(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"+
		"?security=reality&sni=a.com&pbk=notarealkey&type=tcp#a", ReasonBadReality)
}

// XTLS Vision без TLS и поверх ws — невалидные комбинации, Xray их не поднимет.
// Старый чекер прокидывал flow в конфиг вслепую.
func TestVisionInvalidCombinations(t *testing.T) {
	mustReject(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"+
		"?security=none&type=tcp&flow=xtls-rprx-vision#a", ReasonBadFlow)
	mustReject(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"+
		"?security=tls&sni=a.com&type=ws&flow=xtls-rprx-vision#a", ReasonBadFlow)
}

func TestVMessBase64(t *testing.T) {
	// port и aid числами, а не строками — оба варианта живут в подписках.
	raw := `{"v":"2","ps":"Tokyo 01","add":"jp.example.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,"scy":"auto","net":"ws","type":"none","host":"jp.example.com","path":"/vm","tls":"tls","sni":"jp.example.com"}`
	uri := "vmess://" + base64.StdEncoding.EncodeToString([]byte(raw))

	n := mustParse(t, uri)
	if n.Server != "jp.example.com" || n.Port != 443 {
		t.Errorf("endpoint = %s", n.Endpoint())
	}
	if n.Name != "Tokyo 01" {
		t.Errorf("name = %q", n.Name)
	}
	if n.Transport != model.TransportWS || n.Path != "/vm" {
		t.Errorf("transport = %q path = %q", n.Transport, n.Path)
	}
	if n.Security != model.SecTLS {
		t.Errorf("security = %q", n.Security)
	}
}

// Xray работает только с VMessAEAD; alterId > 0 не поднимется.
func TestVMessLegacyAlterIDRejected(t *testing.T) {
	raw := `{"v":"2","ps":"old","add":"a.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"64","net":"tcp","tls":""}`
	mustReject(t, "vmess://"+base64.RawStdEncoding.EncodeToString([]byte(raw)), ReasonLegacyVMess)
}

func TestVMessGRPCServiceNameFromPath(t *testing.T) {
	raw := `{"v":"2","ps":"g","add":"a.example.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,"net":"grpc","type":"multi","path":"GunService","tls":"tls","sni":"a.example.com"}`
	n := mustParse(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(raw)))
	if n.ServiceName != "GunService" || n.Mode != "multi" {
		t.Errorf("serviceName = %q mode = %q", n.ServiceName, n.Mode)
	}
}

func TestTrojanDefaultsToTLS(t *testing.T) {
	n := mustParse(t, "trojan://p%40ssw0rd@t.example.com:443?sni=t.example.com#T")
	if n.Security != model.SecTLS {
		t.Errorf("security = %q, want tls", n.Security)
	}
	if n.Password != "p@ssw0rd" {
		t.Errorf("password = %q, want p@ssw0rd", n.Password)
	}
}

// ...но security=none обязано уважаться. Старый чекер всегда ставил TLS.
func TestTrojanRespectsSecurityNone(t *testing.T) {
	n := mustParse(t, "trojan://pass@t.example.com:80?security=none&type=tcp#T")
	if n.Security != model.SecNone {
		t.Errorf("security = %q, want none", n.Security)
	}
}

func TestShadowsocksSIP002(t *testing.T) {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:s3cret"))
	n := mustParse(t, "ss://"+userInfo+"@ss.example.com:8388#SS%20Node")
	if n.Method != "aes-256-gcm" || n.Password != "s3cret" {
		t.Errorf("method = %q password = %q", n.Method, n.Password)
	}
	if n.Name != "SS Node" {
		t.Errorf("name = %q", n.Name)
	}
}

func TestShadowsocksPlainUserInfo2022(t *testing.T) {
	n := mustParse(t, "ss://2022-blake3-aes-256-gcm:Yjgz@ss.example.com:8388#s")
	if n.Method != "2022-blake3-aes-256-gcm" || n.Password != "Yjgz" {
		t.Errorf("method = %q password = %q", n.Method, n.Password)
	}
}

func TestShadowsocksLegacyFullBase64(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@ss.example.com:1080"))
	n := mustParse(t, "ss://"+body+"#legacy")
	// алиас разворачивается в канонический метод Xray
	if n.Method != "chacha20-poly1305" || n.Port != 1080 {
		t.Errorf("method = %q port = %d", n.Method, n.Port)
	}
}

// Xray не реализует SIP003-плагины. Старый чекер на таких ссылках
// молча ломал разбор пароля.
func TestShadowsocksPluginRejected(t *testing.T) {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))
	mustReject(t, "ss://"+userInfo+"@ss.example.com:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket#p",
		ReasonUnsupportedPlugin)
}

func TestShadowsocksLegacyCipherRejected(t *testing.T) {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-cfb:pw"))
	mustReject(t, "ss://"+userInfo+"@ss.example.com:8388#c", ReasonUnsupportedMethod)
}

func TestShadowsocksIPv6(t *testing.T) {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw"))
	n := mustParse(t, "ss://"+userInfo+"@[2a09:bac1:76c0:fb0::48:6a]:443#v6")
	if n.Server != "2a09:bac1:76c0:fb0::48:6a" || n.Port != 443 {
		t.Errorf("server = %q port = %d", n.Server, n.Port)
	}
}

// В подписках попадаются VLESS-ключи, опубликованные со схемой ss://.
// Разбираем их как vless и чиним схему в Raw, иначе выданная ссылка
// не заведётся у пользователя.
func TestShadowsocksMislabeledVLESS(t *testing.T) {
	n := mustParse(t, "ss://5f81ae57-1b77-45df-9ba1-a774c040bc5e@meg.ns.cloudflare.com:443"+
		"?path=%2Fperform&security=tls&encryption=none&type=ws&sni=key.example.com&host=key.example.com#NL")

	if n.Protocol != model.ProtoVLESS {
		t.Fatalf("protocol = %q, want vless", n.Protocol)
	}
	if n.UUID != "5f81ae57-1b77-45df-9ba1-a774c040bc5e" {
		t.Errorf("uuid = %q", n.UUID)
	}
	if n.Transport != model.TransportWS || n.Path != "/perform" {
		t.Errorf("transport = %q path = %q", n.Transport, n.Path)
	}
	if !strings.HasPrefix(n.Raw, "vless://") {
		t.Errorf("Raw = %.30s…, схема не починена", n.Raw)
	}
	if n.Name != "NL" {
		t.Errorf("name = %q", n.Name)
	}
}

// ...но настоящий Shadowsocks эвристика трогать не должна.
func TestShadowsocksNotMislabeled(t *testing.T) {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw"))
	n := mustParse(t, "ss://"+userInfo+"@ss.example.com:8388?type=ws&path=/x&security=tls&sni=ss.example.com#s")
	if n.Protocol != model.ProtoShadowsocks {
		t.Fatalf("protocol = %q, want ss", n.Protocol)
	}
}

func TestUnsupportedProtocols(t *testing.T) {
	for _, uri := range []string{
		"hysteria2://pw@h.example.com:443?sni=h.example.com#h",
		"hy2://pw@h.example.com:443#h",
		"tuic://uuid:pw@t.example.com:443#t",
		"anytls://pw@a.example.com:443#a",
		"ssr://abcdef",
	} {
		mustReject(t, uri, ReasonUnsupportedProtocol)
	}
}

func TestPrivateAndLoopbackRejected(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "192.168.1.1", "10.0.0.5", "0.0.0.0", "100.64.1.1"} {
		mustReject(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@"+host+":443?type=tcp&security=none#x",
			ReasonBadHost)
	}
}

func TestBadPorts(t *testing.T) {
	mustReject(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:0?type=tcp#x", ReasonBadPort)
	mustReject(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:99999?type=tcp#x", ReasonBadPort)
}

// Ключ, отличающийся только именем, — это один и тот же сервер.
// Дедуп по полной строке (как в старом чекере) множил работу втрое.
func TestFingerprintIgnoresName(t *testing.T) {
	base := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443?type=tcp&security=tls&sni=a.example.com"
	a := mustParse(t, base+"#Server%20A")
	b := mustParse(t, base+"#Server%20B")
	if a.Fingerprint() != b.Fingerprint() {
		t.Errorf("отпечатки различаются: %s vs %s", a.Fingerprint(), b.Fingerprint())
	}

	other := mustParse(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:8443?type=tcp&security=tls&sni=a.example.com#A")
	if a.Fingerprint() == other.Fingerprint() {
		t.Error("разные порты дали одинаковый отпечаток")
	}
}

// Разные подписки на одном сервере — независимые ключи: одну могут
// забанить, вторая продолжит работать. Склеивать их нельзя ни при каких
// условиях, иначе рабочая учётка потеряется вместе с забаненной.
func TestFingerprintSeparatesAccountsOnSameServer(t *testing.T) {
	base := "@same.example.com:443?type=tcp&security=tls&sni=same.example.com#N"

	a := mustParse(t, "vless://11111111-1111-1111-1111-111111111111"+base)
	b := mustParse(t, "vless://22222222-2222-2222-2222-222222222222"+base)
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("два разных uuid на одном сервере склеены в один ключ")
	}

	// То же для пароля: trojan и shadowsocks различаются им, а не uuid.
	t1 := mustParse(t, "trojan://pass-one@same.example.com:443?sni=same.example.com#N")
	t2 := mustParse(t, "trojan://pass-two@same.example.com:443?sni=same.example.com#N")
	if t1.Fingerprint() == t2.Fingerprint() {
		t.Error("два разных пароля на одном сервере склеены в один ключ")
	}

	// И через Batch — дедуп не должен их схлопнуть.
	nodes, stats := Batch([]string{
		"vless://11111111-1111-1111-1111-111111111111" + base,
		"vless://22222222-2222-2222-2222-222222222222" + base,
		"vless://33333333-3333-3333-3333-333333333333" + base,
	})
	if len(nodes) != 3 {
		t.Errorf("из трёх учёток осталось %d", len(nodes))
	}
	if stats.Duplicate != 0 {
		t.Errorf("учётки посчитаны дублями: %d", stats.Duplicate)
	}
}

// Один и тот же вход, но разные порты — это разные точки входа:
// провайдер может закрыть одну и оставить другую.
func TestFingerprintSeparatesPortsAndTransports(t *testing.T) {
	uuid := "vless://11111111-1111-1111-1111-111111111111@srv.example.com:"
	a := mustParse(t, uuid+"443?type=tcp&security=tls&sni=srv.example.com#N")
	b := mustParse(t, uuid+"8443?type=tcp&security=tls&sni=srv.example.com#N")
	c := mustParse(t, uuid+"443?type=ws&security=tls&sni=srv.example.com&path=/x#N")

	seen := map[string]bool{}
	for _, n := range []*model.Node{a, b, c} {
		if seen[n.Fingerprint()] {
			t.Fatal("разные точки входа склеены")
		}
		seen[n.Fingerprint()] = true
	}
}

func TestBatchDedup(t *testing.T) {
	base := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443?type=tcp&security=tls&sni=a.example.com"
	lines := []string{
		base + "#A", base + "#B", base + "#C",
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@b.example.com:443?type=tcp&security=tls&sni=b.example.com#D",
		"# комментарий",
		"",
		"hysteria2://pw@h.example.com:443#h",
	}
	nodes, stats := Batch(lines)

	if len(nodes) != 2 {
		t.Errorf("unique = %d, want 2", len(nodes))
	}
	if stats.Duplicate != 2 {
		t.Errorf("duplicate = %d, want 2", stats.Duplicate)
	}
	if stats.Rejected[ReasonUnsupportedProtocol] != 1 {
		t.Errorf("unsupported = %d, want 1", stats.Rejected[ReasonUnsupportedProtocol])
	}
}

func TestDecodeBase64Variants(t *testing.T) {
	want := "method:pass@host:443"
	for name, enc := range map[string]string{
		"RawURL": base64.RawURLEncoding.EncodeToString([]byte(want)),
		"RawStd": base64.RawStdEncoding.EncodeToString([]byte(want)),
		"URL":    base64.URLEncoding.EncodeToString([]byte(want)),
		"Std":    base64.StdEncoding.EncodeToString([]byte(want)),
	} {
		got, err := decodeBase64(enc)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s: got %q", name, got)
		}
	}
}
