package probe

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bobivpn/checker/internal/engine"
	"github.com/bobivpn/checker/internal/model"
)

// fakeEngine заменяет ядро: тесты раннера не должны никуда ходить.
type fakeEngine struct {
	openErr   error
	panicOnce bool
	opened    int64
}

func (f *fakeEngine) Name() string    { return "fake" }
func (f *fakeEngine) Version() string { return "test" }

func (f *fakeEngine) Open(*model.Node, engine.Options) (engine.Session, error) {
	atomic.AddInt64(&f.opened, 1)
	if f.panicOnce {
		panic("кривой конфиг из чужой подписки")
	}
	return nil, f.openErr
}

func nodes(t *testing.T, count int, server string, port int) []*model.Node {
	t.Helper()
	out := make([]*model.Node, count)
	for i := range out {
		out[i] = &model.Node{
			Raw:       "vless://" + strconv.Itoa(i),
			Protocol:  model.ProtoVLESS,
			Server:    server,
			Port:      port,
			UUID:      "b831381d-6324-4d53-ad4f-8cda48b3081" + strconv.Itoa(i%10),
			Security:  model.SecNone,
			Transport: model.TransportRaw,
		}
	}
	return out
}

func TestRunnerPreservesOrderAndCounts(t *testing.T) {
	list := nodes(t, 20, "example.invalid", 443)

	var mu sync.Mutex
	seen := 0
	r := &Runner{
		Engine:      &fakeEngine{openErr: errors.New("ядро недоступно")},
		Config:      Config{SkipL4: true, ProbeTimeout: time.Second},
		Concurrency: 8,
		OnResult: func(_ Result, done, total int) {
			mu.Lock()
			defer mu.Unlock()
			seen++
			if total != len(list) {
				t.Errorf("total = %d, ожидалось %d", total, len(list))
			}
			if done < 1 || done > total {
				t.Errorf("done = %d вне диапазона", done)
			}
		},
	}

	results := r.Run(context.Background(), list)

	if len(results) != len(list) {
		t.Fatalf("результатов %d, нод %d", len(results), len(list))
	}
	if seen != len(list) {
		t.Errorf("OnResult вызван %d раз, ожидалось %d", seen, len(list))
	}
	for i, res := range results {
		if res.Raw != list[i].Raw {
			t.Fatalf("порядок нарушен на позиции %d: %q", i, res.Raw)
		}
		if res.OK {
			t.Errorf("нода %d признана рабочей при мёртвом ядре", i)
		}
		if res.Stage != StageOpen {
			t.Errorf("стадия = %q, ожидалась %q", res.Stage, StageOpen)
		}
	}
}

// Паника внутри ядра не должна ронять прогон: на входе тысячи чужих ссылок.
func TestRunnerRecoversFromPanic(t *testing.T) {
	list := nodes(t, 5, "example.invalid", 443)
	r := &Runner{
		Engine:      &fakeEngine{panicOnce: true},
		Config:      Config{SkipL4: true, ProbeTimeout: time.Second},
		Concurrency: 3,
	}

	results := r.Run(context.Background(), list)

	for i, res := range results {
		if res.OK {
			t.Errorf("нода %d признана рабочей после паники", i)
		}
		if res.Error == "" {
			t.Errorf("нода %d: паника не записана в результат", i)
		}
	}
}

// Один мёртвый эндпоинт не должен передозваниваться столько раз,
// сколько на него ведёт ключей.
func TestL4CacheDialsEndpointOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Считаем через канал, а не счётчиком: горутина Accept просыпается
	// уже после возврата Run, и проверка счётчика была бы гонкой.
	accepted := make(chan struct{}, 64)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
			select {
			case accepted <- struct{}{}:
			default:
			}
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// 30 разных ключей, ведущих на один и тот же сервер.
	list := nodes(t, 30, "127.0.0.1", port)

	eng := &fakeEngine{openErr: errors.New("дальше не идём")}
	r := &Runner{
		Engine:      eng,
		Config:      Config{SkipL4: false, L4Timeout: 2 * time.Second, ProbeTimeout: time.Second},
		Concurrency: 10,
	}
	r.Run(context.Background(), list)

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("не было ни одного дозвона до эндпоинта")
	}
	// Лишние соединения, если бы они были, уже лежали бы в очереди listener'а.
	select {
	case <-accepted:
		t.Error("эндпоинт передозванивался: кэш L4 не сработал")
	case <-time.After(300 * time.Millisecond):
	}
	// Ядро всё равно поднимается на каждую ноду — L4 их не отсеял.
	if got := atomic.LoadInt64(&eng.opened); got != int64(len(list)) {
		t.Errorf("ядро поднято %d раз, ожидалось %d", got, len(list))
	}
}

func TestL4CacheSharesFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // порт мёртв

	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	list := nodes(t, 10, host, port)

	eng := &fakeEngine{}
	r := &Runner{
		Engine:      eng,
		Config:      Config{SkipL4: false, L4Timeout: 500 * time.Millisecond},
		Concurrency: 5,
	}
	results := r.Run(context.Background(), list)

	for i, res := range results {
		if res.Stage != StageL4 {
			t.Errorf("нода %d: стадия %q, ожидалась %q", i, res.Stage, StageL4)
		}
	}
	// Ни одна нода не должна была дойти до поднятия ядра.
	if got := atomic.LoadInt64(&eng.opened); got != 0 {
		t.Errorf("ядро поднималось %d раз при мёртвом эндпоинте", got)
	}
}
