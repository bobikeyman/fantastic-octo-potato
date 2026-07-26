// Package engine абстрагирует ядро, через которое идёт проверка.
//
// Абстракция нужна не ради красоты: Xray-core не поддерживает hysteria2,
// tuic и anytls. Когда для них понадобится второй бэкенд, пайплайн проверки
// менять не придётся — достаточно другой реализации Engine.
package engine

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/bobivpn/checker/internal/model"
)

// Options управляет поднятием сессии.
type Options struct {
	// AllowInsecure отключает проверку сертификата ноды внутри туннеля.
	//
	// Обычный проход идёт с false. Ключи, которые на нём отвалились, но
	// просят allowInsecure, перепроверяются вторым проходом с true и уходят
	// в корзину tier=insecure.
	AllowInsecure bool
}

// Engine поднимает изолированные сессии для проверки нод.
type Engine interface {
	// Name — идентификатор движка для отчёта.
	Name() string
	// Version — версия ядра.
	Version() string
	// Open поднимает сессию для одной ноды. Вызывающий обязан её закрыть.
	Open(n *model.Node, opts Options) (Session, error)
}

// Session — поднятое ядро для одной ноды.
type Session interface {
	// DialContext совместим с http.Transport.DialContext.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	// HTTPClient отдаёт клиент, ходящий через эту ноду.
	HTTPClient(timeout time.Duration) *http.Client
	Close() error
}

// HTTPClientFor собирает http.Client поверх произвольного диалера.
//
// Проверка сертификата здесь НЕ отключается ни при каких настройках:
// это сквозная валидация до тестового хоста, и именно она ловит ноды,
// подменяющие трафик. Опция AllowInsecure относится только к TLS внутри
// туннеля — до самой ноды.
func HTTPClientFor(dial func(context.Context, string, string) (net.Conn, error), timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DialContext: dial,
		// Каждая проба — своё соединение: переиспользование смазало бы
		// замеры латентности и скрыло ноды, отваливающиеся после первого запроса.
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Редирект — это не 204. Возвращаем его как есть, чтобы строгая
		// проверка статуса увидела настоящий ответ, а не конец цепочки.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
