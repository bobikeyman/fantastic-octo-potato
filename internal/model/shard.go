package model

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Shard — часть работы для одного джоба CI.
type Shard struct {
	Index int     `json:"index"`
	Total int     `json:"total"`
	Nodes []*Node `json:"nodes"`
}

// SplitShards раскладывает ноды по шардам.
//
// Раскладка идёт по остатку от деления, а не отрезками: ключи одного
// источника лежат в списке подряд и часто ведут в одну страну, так что
// нарезка отрезками собрала бы все медленные ноды в один джоб.
func SplitShards(nodes []*Node, total int) []Shard {
	if total < 1 {
		total = 1
	}
	shards := make([]Shard, total)
	for i := range shards {
		shards[i] = Shard{Index: i, Total: total}
	}
	// Порядок фиксируем по отпечатку: раскладка обязана быть одинаковой
	// при одинаковом входе, иначе кэш и история поедут.
	sorted := make([]*Node, len(nodes))
	copy(sorted, nodes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Fingerprint() < sorted[j].Fingerprint()
	})
	for i, n := range sorted {
		idx := i % total
		shards[idx].Nodes = append(shards[idx].Nodes, n)
	}
	return shards
}

// WriteShards записывает шарды в каталог как shard-0.json, shard-1.json, …
func WriteShards(dir string, shards []Shard) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, sh := range shards {
		path := filepath.Join(dir, fmt.Sprintf("shard-%d.json", sh.Index))
		if err := writeJSON(path, sh); err != nil {
			return err
		}
	}
	return nil
}

// ReadShard читает один шард.
func ReadShard(path string) (*Shard, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sh Shard
	if err := json.Unmarshal(data, &sh); err != nil {
		return nil, fmt.Errorf("разбор шарда %s: %w", path, err)
	}
	return &sh, nil
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(v)
}

// WriteJSON — экспорт для команд CLI.
func WriteJSON(path string, v any) error { return writeJSON(path, v) }
