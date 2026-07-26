package probe

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bobivpn/checker/internal/engine"
	"github.com/bobivpn/checker/internal/model"
)

// Runner прогоняет пачку нод через проверку с ограничением параллелизма.
type Runner struct {
	Engine      engine.Engine
	Config      Config
	Concurrency int

	// OnResult вызывается после каждой проверенной ноды. Может быть nil.
	// Вызовы приходят из разных горутин — реализация обязана быть потокобезопасной.
	OnResult func(res Result, done, total int)
}

// Run проверяет ноды и возвращает результаты в исходном порядке.
func (r *Runner) Run(ctx context.Context, nodes []*model.Node) []Result {
	concurrency := r.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	results := make([]Result, len(nodes))
	cache := newL4Cache()
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var done int64

	// L4 внутри Check выключаем: раннер делает его сам через кэш, чтобы
	// один мёртвый эндпоинт не передозванивался столько раз, сколько на него
	// ведёт ключей.
	cfg := r.Config
	cfg.SkipL4 = true

	for i, n := range nodes {
		select {
		case <-ctx.Done():
			return results
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(i int, n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()

			res := r.checkOne(ctx, cache, n, cfg)
			results[i] = res

			d := int(atomic.AddInt64(&done, 1))
			if r.OnResult != nil {
				r.OnResult(res, d, len(nodes))
			}
		}(i, n)
	}

	wg.Wait()
	return results
}

// checkOne изолирует проверку одной ноды.
//
// Паника внутри ядра на кривом конфиге не должна ронять весь прогон:
// на входе тысячи ссылок из чужих подписок, доверия к ним нет.
func (r *Runner) checkOne(ctx context.Context, cache *l4Cache, n *model.Node, cfg Config) (res Result) {
	defer func() {
		if rec := recover(); rec != nil {
			res = Result{
				Fingerprint: n.Fingerprint(),
				Raw:         n.Raw,
				Node:        n,
				Stage:       StageOpen,
				Error:       fmt.Sprintf("паника при проверке: %v", rec),
				CheckedAt:   time.Now().UTC(),
			}
		}
	}()

	if !r.Config.SkipL4 {
		d, err := cache.get(ctx, n.Endpoint(), cfg.L4Timeout)
		if err != nil {
			return Result{
				Fingerprint: n.Fingerprint(),
				Raw:         n.Raw,
				Node:        n,
				Stage:       StageL4,
				Error:       err.Error(),
				CheckedAt:   time.Now().UTC(),
			}
		}
		res = Check(ctx, r.Engine, n, cfg)
		res.L4LatencyMs = int(d.Milliseconds())
		return res
	}
	return Check(ctx, r.Engine, n, cfg)
}

// l4Cache хранит результат TCP-дозвона по адресу эндпоинта.
//
// На один и тот же сервер в подписках нередко ведут десятки ключей,
// различающихся только учётными данными: дозваниваться до него повторно
// бессмысленно.
type l4Cache struct {
	mu sync.Mutex
	m  map[string]*l4Entry
}

type l4Entry struct {
	once sync.Once
	d    time.Duration
	err  error
}

func newL4Cache() *l4Cache {
	return &l4Cache{m: make(map[string]*l4Entry)}
}

func (c *l4Cache) get(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	c.mu.Lock()
	e, ok := c.m[addr]
	if !ok {
		e = &l4Entry{}
		c.m[addr] = e
	}
	c.mu.Unlock()

	e.once.Do(func() {
		// Отвязываемся от отмены конкретного вызывающего: иначе первая же
		// отменённая горутина запишет свою ошибку в кэш для всех остальных.
		e.d, e.err = L4(context.WithoutCancel(ctx), addr, timeout)
	})
	return e.d, e.err
}
