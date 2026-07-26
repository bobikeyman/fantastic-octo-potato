package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bobivpn/checker/internal/geo"
	"github.com/bobivpn/checker/internal/output"
	"github.com/bobivpn/checker/internal/probe"
	"github.com/bobivpn/checker/internal/score"
)

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	resultsDir := fs.String("results", "results", "каталог с результатами шардов")
	outDir := fs.String("out", ".", "каталог для файлов подписок")
	historyPath := fs.String("history", "state/history.jsonl.gz", "файл истории репутации")
	minEWMA := fs.Float64("min-ewma", 0.6, "минимальная репутация для публикации")
	minRuns := fs.Int("min-runs", 2, "сколько прогонов ключ должен быть виден")
	ttlDays := fs.Int("ttl-days", 7, "через сколько дней забывать невидимые ключи")
	// 0 = без ограничения. Совпадение выходного адреса не означает ни одного
	// сервера, ни одной учётки — подробности в докстроке LimitPerExitIP.
	maxPerIP := fs.Int("max-per-ip", 0, "максимум ключей на один выходной адрес (0 — без ограничения)")
	topCount := fs.Int("top", 100, "размер топовой подписки")
	noGeo := fs.Bool("no-geo", false, "не запрашивать провайдеров")
	if err := fs.Parse(args); err != nil {
		return err
	}

	results, coreVersion, err := loadResults(*resultsDir)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return fmt.Errorf("в %s нет результатов", *resultsDir)
	}

	stages := map[string]int{}
	okNow := 0
	for _, r := range results {
		stages[string(r.Stage)]++
		if r.OK {
			okNow++
		}
	}
	fmt.Printf("результатов: %d | рабочих в этом прогоне: %d\n", len(results), okNow)

	// --- История репутации ---
	history, err := score.Load(*historyPath)
	if err != nil {
		return fmt.Errorf("история: %w", err)
	}
	knownBefore := history.Len()

	now := time.Now().UTC()
	for _, r := range results {
		history.Observe(score.Observation{
			Fingerprint: r.Fingerprint,
			OK:          r.OK,
			Country:     r.ExitCountry,
			ExitIP:      r.ExitIP,
			LatencyMs:   r.LatencyMs,
			SpeedKBps:   r.SpeedKBps,
			Source:      "ci",
			At:          now,
		})
	}
	forgotten := history.Prune(now, time.Duration(*ttlDays)*24*time.Hour)
	fmt.Printf("история: было %d, стало %d (забыто %d)\n", knownBefore, history.Len(), forgotten)

	// --- Отбор по репутации ---
	policy := score.Policy{MinEWMA: *minEWMA, MinRuns: *minRuns, RequireCurrentOK: true}
	admitted := make([]probe.Result, 0, okNow)
	var heldBack int
	for _, r := range results {
		if !r.OK {
			continue
		}
		entry, _ := history.Get(r.Fingerprint)
		if !policy.Admits(entry, true) {
			heldBack++
			continue
		}
		admitted = append(admitted, r)
	}
	fmt.Printf("допущено к публикации: %d (отложено до следующего прогона: %d)\n", len(admitted), heldBack)

	if err := history.Save(*historyPath); err != nil {
		return fmt.Errorf("сохранение истории: %w", err)
	}

	// --- Провайдеры ---
	providers := map[string]string{}
	if !*noGeo && len(admitted) > 0 {
		ips := make([]string, 0, len(admitted))
		for _, r := range admitted {
			ips = append(ips, r.ExitIP)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		infos := geo.NewLookup().Resolve(ctx, ips)
		cancel()
		for ip, info := range infos {
			providers[ip] = info.Provider()
		}
		fmt.Printf("провайдеров определено: %d\n", len(providers))
	}

	// --- Формирование выдачи ---
	keys := output.FromResults(admitted, providers)
	for i := range keys {
		if e, ok := history.Get(keys[i].Fingerprint); ok {
			keys[i].Uptime = e.Uptime()
			keys[i].Runs = e.Runs
		}
	}

	output.Sort(keys)
	before := len(keys)
	keys = output.LimitPerExitIP(keys, *maxPerIP)
	if dropped := before - len(keys); dropped > 0 {
		fmt.Printf("убрано дублей по выходному адресу: %d\n", dropped)
	}

	if len(keys) == 0 {
		fmt.Println("предупреждение: ни один ключ не прошёл отбор — файлы не перезаписываются")
		return nil
	}

	if err := writeAll(*outDir, keys, stages, len(results), coreVersion, *topCount, now); err != nil {
		return err
	}
	fmt.Printf("\nопубликовано ключей: %d\n", len(keys))
	return nil
}

func writeAll(dir string, keys []output.Key, stages map[string]int, checked int, coreVersion string, topCount int, now time.Time) error {
	renamed := output.Rename(keys)

	profile := output.DefaultProfile()
	profile.Announce = "🐶 BobiVPN — Быстрый и Надёжный\n" + output.AnnounceLine(now)

	at := func(name string) string { return filepath.Join(dir, name) }

	// Сырые ссылки без переименования — для тех, кому важны исходные имена.
	raw := make([]string, len(keys))
	for i, k := range keys {
		raw[i] = k.Raw
	}

	steps := []struct {
		name string
		fn   func() error
	}{
		{"vpn.txt", func() error { return output.WritePlain(at("vpn.txt"), raw) }},
		{"vpn_base64.txt", func() error { return output.WriteBase64(at("vpn_base64.txt"), raw) }},
		{"vpn_renamed.txt", func() error { return output.WritePlain(at("vpn_renamed.txt"), renamed) }},
		{"vpn_renamed_base64.txt", func() error { return output.WriteBase64(at("vpn_renamed_base64.txt"), renamed) }},
		{"bobi_vpn.txt", func() error { return output.WriteHapp(at("bobi_vpn.txt"), profile, renamed) }},
		{"bobi_vpn_base64.txt", func() error { return output.WriteHappBase64(at("bobi_vpn_base64.txt"), profile, renamed) }},
	}
	for _, s := range steps {
		if err := s.fn(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}

	// Lite — только ближние страны.
	liteCountries := []string{"RU", "DE", "FR", "FI", "EE", "LV", "LT"}
	lite := output.FilterCountries(keys, liteCountries)
	liteProfile := profile
	liteProfile.Title = "🐶BobiVPN Lite🐶"
	liteProfile.Announce = "🐶 BobiVPN Lite — RU DE FR FI Балтика\n" + output.AnnounceLine(now)
	if err := output.WriteHapp(at("bobi_vpn_lite.txt"), liteProfile, output.Rename(lite)); err != nil {
		return fmt.Errorf("bobi_vpn_lite.txt: %w", err)
	}

	// Top — по надёжности, а не по стране.
	top := make([]output.Key, len(keys))
	copy(top, keys)
	output.SortByQuality(top)
	if len(top) > topCount {
		top = top[:topCount]
	}
	topProfile := profile
	topProfile.Title = "🏆BobiVPN Top🏆"
	topProfile.Announce = fmt.Sprintf("🏆 BobiVPN Top-%d\n⭐ Самые стабильные по истории проверок", len(top))
	if err := output.WriteHapp(at("bobi_vpn_top.txt"), topProfile, output.Rename(top)); err != nil {
		return fmt.Errorf("bobi_vpn_top.txt: %w", err)
	}

	files, err := output.WriteCountries(filepath.Join(dir, "countries"), keys, profile)
	if err != nil {
		return fmt.Errorf("countries/: %w", err)
	}

	report := output.BuildReport(keys, renamed, stages, checked, coreVersion, now)
	if err := writeJSONFile(at("vpn_report.json"), report); err != nil {
		return fmt.Errorf("vpn_report.json: %w", err)
	}

	fmt.Println("\nзаписано:")
	fmt.Printf("  bobi_vpn.txt          %d ключей\n", len(renamed))
	fmt.Printf("  bobi_vpn_lite.txt     %d ключей\n", len(lite))
	fmt.Printf("  bobi_vpn_top.txt      %d ключей\n", len(top))
	fmt.Printf("  countries/            %d файлов\n", len(files))
	fmt.Println("\nпо странам:")
	for i, f := range files {
		if i >= 15 {
			fmt.Printf("  … ещё %d стран\n", len(files)-15)
			break
		}
		fmt.Printf("  %s %-18s %3d\n", output.Flag(f.Code), f.Country, f.Count)
	}
	return nil
}

// loadResults собирает результаты всех шардов.
func loadResults(dir string) ([]probe.Result, string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, "", err
	}
	var (
		all         []probe.Result
		coreVersion string
		seen        = map[string]struct{}{}
	)
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, "", err
		}
		var payload struct {
			CoreVersion string         `json:"core_version"`
			Results     []probe.Result `json:"results"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return nil, "", fmt.Errorf("%s: %w", p, err)
		}
		if payload.CoreVersion != "" {
			coreVersion = payload.CoreVersion
		}
		for _, r := range payload.Results {
			// Один ключ может попасть в два шарда только по ошибке, но
			// повторный учёт исказил бы историю репутации.
			if _, dup := seen[r.Fingerprint]; dup {
				continue
			}
			seen[r.Fingerprint] = struct{}{}
			all = append(all, r)
		}
	}
	return all, coreVersion, nil
}

func writeJSONFile(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
