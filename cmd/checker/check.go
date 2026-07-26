package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bobivpn/checker/internal/engine"
	"github.com/bobivpn/checker/internal/model"
	"github.com/bobivpn/checker/internal/probe"
)

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	shardPath := fs.String("shard", "", "файл шарда (shard-N.json)")
	outPath := fs.String("out", "", "куда записать результаты JSON")
	concurrency := fs.Int("concurrency", 150, "параллельных проверок")
	minSpeed := fs.Float64("min-speed", 200, "минимальная скорость, KB/s")
	maxLatency := fs.Duration("max-latency", 2*time.Second, "максимальная задержка (медиана)")
	probeTimeout := fs.Duration("probe-timeout", 8*time.Second, "таймаут одной пробы")
	limit := fs.Int("limit", 0, "проверить только первые N нод (для отладки)")
	quiet := fs.Bool("quiet", false, "печатать только итог")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *shardPath == "" {
		fs.Usage()
		return fmt.Errorf("не указан --shard")
	}

	shard, err := model.ReadShard(*shardPath)
	if err != nil {
		return err
	}
	nodes := shard.Nodes
	if *limit > 0 && *limit < len(nodes) {
		nodes = nodes[:*limit]
	}

	eng := engine.NewXray()
	fmt.Printf("шард %d/%d: %d нод | ядро %s %s | параллельно %d\n",
		shard.Index+1, shard.Total, len(nodes), eng.Name(), eng.Version(), *concurrency)

	// Прерывание должно приводить к записи того, что уже проверено,
	// а не терять весь прогон.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := probe.DefaultConfig()
	cfg.MinSpeedKBps = *minSpeed
	cfg.MaxLatency = *maxLatency
	cfg.ProbeTimeout = *probeTimeout

	// Собственный адрес нужен, чтобы поймать ключи, у которых трафик
	// идёт мимо прокси и возвращается адрес самого раннера.
	ownCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	own, err := probe.OwnIP(ownCtx, cfg.TraceURL, 15*time.Second)
	cancel()
	if err != nil {
		fmt.Printf("предупреждение: собственный адрес не определён (%v) — проверка «трафик мимо прокси» ослаблена\n", err)
	} else {
		fmt.Printf("собственный адрес: %s\n", own)
		cfg.OwnIP = own
	}

	var (
		mu      sync.Mutex
		okCount int
		started = time.Now()
	)

	runner := &probe.Runner{
		Engine:      eng,
		Config:      cfg,
		Concurrency: *concurrency,
		OnResult: func(res probe.Result, done, total int) {
			mu.Lock()
			defer mu.Unlock()
			if res.OK {
				okCount++
			}
			if *quiet {
				// Раз в сотню — чтобы лог CI оставался читаемым.
				if done%100 == 0 || done == total {
					fmt.Printf("[%d/%d] рабочих %d, прошло %v\n",
						done, total, okCount, time.Since(started).Round(time.Second))
				}
				return
			}
			printResult(res, done, total)
		},
	}

	results := runner.Run(ctx, nodes)

	// Отменённые задачи оставляют нулевые записи — они не «нерабочие ключи»,
	// а непроверенные, и в выдачу попадать не должны.
	checked := make([]probe.Result, 0, len(results))
	for _, r := range results {
		if r.Fingerprint != "" {
			checked = append(checked, r)
		}
	}

	printSummary(checked, len(nodes), time.Since(started))

	if *outPath != "" {
		payload := map[string]any{
			"shard":        shard.Index,
			"shards_total": shard.Total,
			"engine":       eng.Name(),
			"core_version": eng.Version(),
			"own_ip":       cfg.OwnIP,
			"checked":      len(checked),
			"planned":      len(nodes),
			"finished_at":  time.Now().UTC().Format(time.RFC3339),
			"results":      checked,
		}
		if err := model.WriteJSON(*outPath, payload); err != nil {
			return fmt.Errorf("запись результатов: %w", err)
		}
		fmt.Printf("результаты записаны в %s\n", *outPath)
	}

	if ctx.Err() != nil {
		return fmt.Errorf("прогон прерван после %d из %d нод", len(checked), len(nodes))
	}
	return nil
}

func printResult(res probe.Result, done, total int) {
	name := res.Node.Name
	if name == "" {
		name = res.Node.Endpoint()
	}
	if len(name) > 34 {
		name = name[:33] + "…"
	}

	if res.OK {
		tier := ""
		if res.Tier == model.TierInsecure {
			tier = " [insecure]"
		}
		fmt.Printf("[%d/%d] ✓ %-34s %s %s | %d ms | %.0f KB/s%s\n",
			done, total, name, res.ExitCountry, res.ExitIP, res.LatencyMs, res.SpeedKBps, tier)
		return
	}
	fmt.Printf("[%d/%d] ✗ %-34s %-13s %s\n", done, total, name, res.Stage, shorten(res.Error, 70))
}

func printSummary(results []probe.Result, planned int, elapsed time.Duration) {
	byStage := map[probe.Stage]int{}
	byCountry := map[string]int{}
	var ok, insecure int

	for _, r := range results {
		byStage[r.Stage]++
		if !r.OK {
			continue
		}
		ok++
		if r.Tier == model.TierInsecure {
			insecure++
		}
		if r.ExitCountry != "" {
			byCountry[r.ExitCountry]++
		}
	}

	fmt.Printf("\n%s\n", divider)
	fmt.Printf("проверено %d из %d за %v\n", len(results), planned, elapsed.Round(time.Second))
	fmt.Printf("рабочих: %d", ok)
	if insecure > 0 {
		fmt.Printf(" (из них %d в корзине insecure)", insecure)
	}
	if len(results) > 0 {
		fmt.Printf(" — %.1f%%", float64(ok)/float64(len(results))*100)
	}
	fmt.Println()

	fmt.Println("\nотсев по стадиям:")
	for _, st := range []probe.Stage{
		probe.StageL4, probe.StageOpen, probe.StageConnectivity,
		probe.StageTrace, probe.StageExitIP, probe.StageLatency, probe.StageSpeed,
	} {
		if n := byStage[st]; n > 0 {
			fmt.Printf("  %-14s %d\n", st, n)
		}
	}

	if len(byCountry) > 0 {
		fmt.Printf("\nстран: %d\n", len(byCountry))
	}
	fmt.Println(divider)
}

const divider = "────────────────────────────────────────────────────────"
