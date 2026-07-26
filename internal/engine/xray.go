package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	// Регистрирует протоколы и транспорты в реестре ядра.
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/bobivpn/checker/internal/model"
	"github.com/bobivpn/checker/internal/xraycfg"
)

// Xray — движок на встроенном xray-core.
//
// Ядро работает как библиотека: ни подпроцессов, ни SOCKS-инбаундов, ни
// портов. Соединение берётся напрямую через core.Dial, поэтому гонок за
// порт между параллельными проверками не существует в принципе, а замер
// времени не включает лишний SOCKS-хоп.
type Xray struct{}

// NewXray создаёт движок.
func NewXray() *Xray { return &Xray{} }

func (*Xray) Name() string { return "xray-core" }

func (*Xray) Version() string { return core.Version() }

// Open поднимает изолированный экземпляр ядра для одной ноды.
func (*Xray) Open(n *model.Node, opts Options) (Session, error) {
	raw, err := xraycfg.FullConfig(n, xraycfg.Options{AllowInsecure: opts.AllowInsecure})
	if err != nil {
		return nil, fmt.Errorf("сборка конфига: %w", err)
	}
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("разбор конфига ядром: %w", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("создание экземпляра: %w", err)
	}
	// Готовность определяется возвратом Start, а не таймером: ждать
	// фиксированные секунды после запуска не нужно и вредно.
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return nil, fmt.Errorf("запуск ядра: %w", err)
	}
	return &xraySession{inst: inst}, nil
}

type xraySession struct {
	inst *core.Instance
}

func (s *xraySession) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dest, err := destination(network, addr)
	if err != nil {
		return nil, err
	}
	return core.Dial(ctx, s.inst, dest)
}

func (s *xraySession) HTTPClient(timeout time.Duration) *http.Client {
	return HTTPClientFor(s.DialContext, timeout)
}

func (s *xraySession) Close() error {
	if s.inst == nil {
		return nil
	}
	err := s.inst.Close()
	s.inst = nil
	return err
}

// destination переводит "host:port" в адрес назначения ядра.
//
// Домен НЕ резолвится локально: он уезжает на ноду как домен. Это и ближе
// к поведению реального клиента, и заодно проверяет DNS самой ноды.
func destination(network, addr string) (xnet.Destination, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("адрес %q: %w", addr, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return xnet.Destination{}, fmt.Errorf("порт %q некорректен", portStr)
	}
	port := xnet.Port(portNum)

	var address xnet.Address
	if ip := net.ParseIP(host); ip != nil {
		address = xnet.IPAddress(ip)
	} else {
		address = xnet.DomainAddress(host)
	}

	switch network {
	case "udp", "udp4", "udp6":
		return xnet.UDPDestination(address, port), nil
	default:
		return xnet.TCPDestination(address, port), nil
	}
}
