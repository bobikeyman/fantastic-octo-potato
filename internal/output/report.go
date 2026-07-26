package output

import (
	"time"

	"github.com/bobivpn/checker/internal/model"
)

// Report — машиночитаемый отчёт прогона.
type Report struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	GeneratedAt string `json:"generated_at"`
	CoreVersion string `json:"core_version"`

	TotalChecked int `json:"total_checked"`
	WorkingCount int `json:"working_count"`
	PublishedCnt int `json:"published_count"`
	InsecureCnt  int `json:"insecure_count"`

	// StageBreakdown показывает, на какой стадии отсеялись ключи, —
	// без этого нельзя понять, что именно ухудшилось между прогонами.
	StageBreakdown map[string]int `json:"stage_breakdown"`

	Countries map[string]*CountryStat `json:"countries"`
	Keys      []ReportKey             `json:"keys"`
}

// CountryStat — сводка по стране.
type CountryStat struct {
	Name  string `json:"name"`
	Flag  string `json:"flag"`
	Count int    `json:"count"`
}

// ReportKey — запись об опубликованном ключе.
type ReportKey struct {
	Name        string  `json:"name"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Flag        string  `json:"flag"`
	Provider    string  `json:"provider"`
	ExitIP      string  `json:"exit_ip"`
	LatencyMs   int     `json:"latency_ms"`
	JitterMs    int     `json:"jitter_ms"`
	SpeedKBps   float64 `json:"speed_kbps"`
	// Uptime и Runs — то, чего нет у разового чекера: доля успешных
	// прогонов и сколько раз ключ вообще наблюдался.
	Uptime float64 `json:"uptime"`
	Runs   int     `json:"runs"`
	Tier   string  `json:"tier"`
	Key    string  `json:"key"`
}

// BuildReport собирает отчёт по опубликованным ключам.
func BuildReport(keys []Key, renamed []string, stages map[string]int, checked int, coreVersion string, now time.Time) *Report {
	rep := &Report{
		Name:           "🐶 Bobi VPN",
		Description:    "Проверенные ключи с историей репутации",
		GeneratedAt:    now.UTC().Format(time.RFC3339),
		CoreVersion:    coreVersion,
		TotalChecked:   checked,
		WorkingCount:   len(keys),
		PublishedCnt:   len(keys),
		StageBreakdown: stages,
		Countries:      make(map[string]*CountryStat),
		Keys:           make([]ReportKey, 0, len(keys)),
	}

	for i, k := range keys {
		code := k.CountryCode
		if code == "" {
			code = "XX"
		}
		stat, ok := rep.Countries[code]
		if !ok {
			stat = &CountryStat{Name: CountryName(code), Flag: Flag(code)}
			rep.Countries[code] = stat
		}
		stat.Count++

		if k.Insecure {
			rep.InsecureCnt++
		}

		tier := string(model.TierMain)
		if k.Insecure {
			tier = string(model.TierInsecure)
		}

		link := k.Raw
		if i < len(renamed) {
			link = renamed[i]
		}

		rep.Keys = append(rep.Keys, ReportKey{
			Name:        CountryName(code) + " | " + k.Provider,
			Country:     CountryName(code),
			CountryCode: code,
			Flag:        Flag(code),
			Provider:    k.Provider,
			ExitIP:      k.ExitIP,
			LatencyMs:   k.LatencyMs,
			JitterMs:    k.JitterMs,
			SpeedKBps:   round1(k.SpeedKBps),
			Uptime:      round3(k.Uptime),
			Runs:        k.Runs,
			Tier:        tier,
			Key:         link,
		})
	}
	return rep
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }
func round3(v float64) float64 { return float64(int(v*1000+0.5)) / 1000 }
