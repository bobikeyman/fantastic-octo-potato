package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/bobivpn/checker/internal/model"
	"github.com/bobivpn/checker/internal/parse"
	"github.com/bobivpn/checker/internal/subs"
)

func cmdCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	file := fs.String("subs", "subscriptions.txt", "файл со ссылками на подписки")
	envVar := fs.String("env", "SUBSCRIPTION_URLS", "переменная окружения с приватными подписками")
	outDir := fs.String("out", "shards", "каталог для шардов")
	shards := fs.Int("shards", 8, "на сколько частей резать работу")
	concurrency := fs.Int("concurrency", 8, "параллельных загрузок")
	timeout := fs.Duration("timeout", 30*time.Second, "таймаут одной загрузки")
	if err := fs.Parse(args); err != nil {
		return err
	}

	urls, err := subs.LoadURLs(*file, *envVar)
	if err != nil {
		return fmt.Errorf("список подписок: %w", err)
	}
	if len(urls) == 0 {
		return fmt.Errorf("не найдено ни одной подписки (файл %s, переменная %s)", *file, *envVar)
	}
	fmt.Printf("подписок: %d\n", len(urls))

	fetcher := subs.NewFetcher()
	fetcher.Timeout = *timeout

	ctx := context.Background()
	results := fetcher.FetchAll(ctx, urls, *concurrency)

	var (
		all      []string
		okCount  int
		errCount int
	)
	for _, r := range results {
		short := shorten(r.URL, 64)
		switch {
		case r.Err != nil:
			errCount++
			fmt.Printf("  ✗ %-64s %v\n", short, r.Err)
			continue
		case r.LooksLikeYAML:
			errCount++
			fmt.Printf("  ⚠ %-64s Clash YAML — формат не поддержан\n", short)
			continue
		case r.Lines == 0:
			errCount++
			fmt.Printf("  ⚠ %-64s пусто\n", short)
			continue
		}
		okCount++
		mark := ""
		if r.Base64 {
			mark = " (base64)"
		}
		fmt.Printf("  ✓ %-64s %5d строк%s за %v\n", short, r.Lines, mark, r.Elapsed.Round(time.Millisecond))
		all = append(all, strings.Split(r.Body, "\n")...)
	}

	fmt.Printf("\nзагружено %d подписок, ошибок %d, строк всего %d\n", okCount, errCount, len(all))
	if len(all) == 0 {
		return fmt.Errorf("ни одна подписка не отдала ключи")
	}

	nodes, stats := parse.Batch(all)
	fmt.Printf("разобрано: %d | уникальных: %d | дублей: %d | отбраковано: %d\n",
		stats.Parsed, stats.Unique, stats.Duplicate, stats.RejectedTotal())
	for _, r := range stats.TopReasons() {
		fmt.Printf("  отбраковка  %-24s %d\n", r.Reason, r.Count)
	}
	if len(nodes) == 0 {
		return fmt.Errorf("после разбора не осталось ни одной ноды")
	}

	parts := model.SplitShards(nodes, *shards)
	if err := model.WriteShards(*outDir, parts); err != nil {
		return fmt.Errorf("запись шардов: %w", err)
	}
	fmt.Printf("\nзаписано %d шардов в %s (по ~%d нод)\n", len(parts), *outDir, len(parts[0].Nodes))

	// Сводка для отчёта публикации: цифры этапа сбора иначе потеряются
	// между джобами CI.
	summary := map[string]any{
		"subscriptions_total":  len(urls),
		"subscriptions_ok":     okCount,
		"subscriptions_failed": errCount,
		"lines":                stats.Lines,
		"parsed":               stats.Parsed,
		"unique":               stats.Unique,
		"duplicate":            stats.Duplicate,
		"rejected":             stats.Rejected,
		"shards":               len(parts),
		"collected_at":         time.Now().UTC().Format(time.RFC3339),
	}
	return model.WriteJSON(*outDir+"/collect-summary.json", summary)
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
