package parse

import (
	"sort"
	"strings"

	"github.com/bobivpn/checker/internal/model"
)

// Stats — сводка по разбору пачки ключей. Идёт в отчёт и в лог CI.
type Stats struct {
	Lines     int            `json:"lines"`
	Parsed    int            `json:"parsed"`
	Unique    int            `json:"unique"`
	Duplicate int            `json:"duplicate"`
	Rejected  map[Reason]int `json:"rejected"`
}

// RejectedTotal — сколько строк отбраковано суммарно.
func (s *Stats) RejectedTotal() int {
	n := 0
	for _, v := range s.Rejected {
		n += v
	}
	return n
}

// TopReasons возвращает причины отбраковки по убыванию частоты.
func (s *Stats) TopReasons() []struct {
	Reason Reason
	Count  int
} {
	out := make([]struct {
		Reason Reason
		Count  int
	}, 0, len(s.Rejected))
	for r, c := range s.Rejected {
		out = append(out, struct {
			Reason Reason
			Count  int
		}{r, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

// Batch разбирает, валидирует и дедуплицирует пачку строк.
//
// Дедуп идёт по model.Node.Fingerprint() — то есть БЕЗ учёта #имени.
// Старый чекер дедуплицировал по полной строке ссылки, поэтому одна и та же
// нода под десятком разных названий проверялась десять раз.
func Batch(lines []string) ([]*model.Node, *Stats) {
	stats := &Stats{Rejected: map[Reason]int{}}
	seen := make(map[string]struct{}, len(lines))
	out := make([]*model.Node, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		stats.Lines++

		n, err := URI(line)
		if err != nil {
			stats.Rejected[reasonOf(err)]++
			continue
		}
		if err := Validate(n); err != nil {
			stats.Rejected[reasonOf(err)]++
			continue
		}
		stats.Parsed++

		fp := n.Fingerprint()
		if _, dup := seen[fp]; dup {
			stats.Duplicate++
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, n)
	}

	stats.Unique = len(out)
	return out, stats
}

func reasonOf(err error) Reason {
	if e, ok := err.(*Error); ok {
		return e.Reason
	}
	return ReasonMalformed
}
