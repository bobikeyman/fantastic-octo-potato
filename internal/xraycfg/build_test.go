package xraycfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bobivpn/checker/internal/parse"
)

func build(t *testing.T, uri string) map[string]any {
	t.Helper()
	n, err := parse.URI(uri)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parse.Validate(n); err != nil {
		t.Fatalf("validate: %v", err)
	}
	raw, err := FullConfig(n, Options{})
	if err != nil {
		t.Fatalf("FullConfig: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json: %v", err)
	}
	// Ядро — единственный авторитетный судья схемы.
	if err := Validate(n, Options{}); err != nil {
		t.Fatalf("ядро не приняло конфиг: %v\n%s", err, raw)
	}
	return out
}

func streamOf(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	obs := cfg["outbounds"].([]any)
	ob := obs[0].(map[string]any)
	ss, ok := ob["streamSettings"].(map[string]any)
	if !ok {
		t.Fatal("нет streamSettings")
	}
	return ss
}

const testPBK = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"

func TestBuildVLESSRealityVision(t *testing.T) {
	cfg := build(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443"+
		"?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome"+
		"&pbk="+testPBK+"&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#r")

	ss := streamOf(t, cfg)
	// type=tcp обязан приехать как "raw": в текущем ядре это канон.
	if ss["network"] != "raw" || ss["security"] != "reality" {
		t.Errorf("network=%v security=%v", ss["network"], ss["security"])
	}
	rs := ss["realitySettings"].(map[string]any)
	if rs["publicKey"] != testPBK || rs["shortId"] != "6ba85179e30d4fc2" {
		t.Errorf("realitySettings = %v", rs)
	}
	if rs["serverName"] != "www.microsoft.com" {
		t.Errorf("serverName = %v", rs["serverName"])
	}

	user := cfg["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if user["flow"] != "xtls-rprx-vision" || user["encryption"] != "none" {
		t.Errorf("user = %v", user)
	}
}

// REALITY без явного fp должен получить chrome: голый Go-хендшейк палится по JA3.
func TestBuildRealityDefaultFingerprint(t *testing.T) {
	cfg := build(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443"+
		"?security=reality&sni=a.example.org&pbk="+testPBK+"&type=raw#r")
	rs := streamOf(t, cfg)["realitySettings"].(map[string]any)
	if rs["fingerprint"] != "chrome" {
		t.Errorf("fingerprint = %v, want chrome", rs["fingerprint"])
	}
}

func TestBuildVLESSWebSocket(t *testing.T) {
	cfg := build(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443"+
		"?type=ws&security=tls&path=%2Fws%2Flink%3Fed%3D2048&host=front.example.com&sni=front.example.com#w")
	ss := streamOf(t, cfg)
	ws := ss["wsSettings"].(map[string]any)
	if ws["path"] != "/ws/link?ed=2048" {
		t.Errorf("path = %v", ws["path"])
	}
	if ws["host"] != "front.example.com" {
		t.Errorf("host = %v", ws["host"])
	}
}

func TestBuildXHTTP(t *testing.T) {
	cfg := build(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@x.example.com:443"+
		"?type=xhttp&security=tls&sni=x.example.com&path=/sh&mode=packet-up#x")
	xh := streamOf(t, cfg)["xhttpSettings"].(map[string]any)
	if xh["path"] != "/sh" || xh["mode"] != "packet-up" {
		t.Errorf("xhttpSettings = %v", xh)
	}
}

func TestBuildGRPCMultiMode(t *testing.T) {
	cfg := build(t, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@g.example.com:443"+
		"?type=grpc&security=tls&sni=g.example.com&serviceName=Tun&mode=multi#g")
	gs := streamOf(t, cfg)["grpcSettings"].(map[string]any)
	if gs["serviceName"] != "Tun" || gs["multiMode"] != true {
		t.Errorf("grpcSettings = %v", gs)
	}
}

func TestBuildTrojanAndShadowsocks(t *testing.T) {
	build(t, "trojan://pass@t.example.com:443?sni=t.example.com#t")
	build(t, "ss://YWVzLTI1Ni1nY206czNjcmV0@ss.example.com:8388#s")
}

// Строгая проверка сертификата по умолчанию — основа защиты от нод-перехватчиков.
// Ключ просит allowInsecure, но без явного разрешения мы его не даём.
func TestAllowInsecureIsOptIn(t *testing.T) {
	uri := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443" +
		"?type=ws&security=tls&sni=a.example.com&allowInsecure=1#a"
	n, err := parse.URI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if !n.AllowInsecure {
		t.Fatal("парсер не увидел allowInsecure=1")
	}

	strict, _ := FullConfig(n, Options{})
	if !strings.Contains(string(strict), `"allowInsecure":false`) {
		t.Errorf("строгий режим не выставил allowInsecure=false:\n%s", strict)
	}

	relaxed, _ := FullConfig(n, Options{AllowInsecure: true})
	if !strings.Contains(string(relaxed), `"allowInsecure":true`) {
		t.Errorf("режим insecure не выставил allowInsecure=true:\n%s", relaxed)
	}
}

// TestCorpusAcceptedByCore — главный тест этапа: ядро обязано принять
// конфиг для каждой ноды, которую пропустил парсер.
func TestCorpusAcceptedByCore(t *testing.T) {
	if testing.Short() {
		t.Skip("долгий тест")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "corpus.txt"))
	if err != nil {
		t.Skipf("корпус недоступен: %v", err)
	}
	nodes, _ := parse.Batch(strings.Split(string(data), "\n"))

	var failed int
	byReason := map[string]int{}
	for _, n := range nodes {
		if err := Validate(n, Options{}); err != nil {
			failed++
			byReason[shortErr(err)]++
			if failed <= 5 {
				t.Errorf("%s %s: %v", n.Protocol, n.Endpoint(), err)
			}
		}
	}
	t.Logf("ядро приняло %d из %d конфигов (Xray %s)", len(nodes)-failed, len(nodes), CoreVersion())
	for r, c := range byReason {
		t.Logf("  отказ %-50s %d", r, c)
	}
	if failed > 0 {
		t.Errorf("ядро отвергло %d конфигов", failed)
	}
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 90 {
		s = s[:90]
	}
	return s
}
