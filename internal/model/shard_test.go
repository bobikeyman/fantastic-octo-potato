package model

import (
	"path/filepath"
	"strconv"
	"testing"
)

func testNodes(count int) []*Node {
	out := make([]*Node, count)
	for i := range out {
		out[i] = &Node{
			Raw:       "vless://node" + strconv.Itoa(i),
			Protocol:  ProtoVLESS,
			Server:    "host" + strconv.Itoa(i) + ".example.com",
			Port:      443,
			UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
			Security:  SecTLS,
			Transport: TransportRaw,
		}
	}
	return out
}

func TestSplitShardsCoversEverything(t *testing.T) {
	nodes := testNodes(101)
	shards := SplitShards(nodes, 8)

	if len(shards) != 8 {
		t.Fatalf("шардов %d", len(shards))
	}

	seen := map[string]int{}
	total := 0
	for i, sh := range shards {
		if sh.Index != i || sh.Total != 8 {
			t.Errorf("шард %d: Index=%d Total=%d", i, sh.Index, sh.Total)
		}
		total += len(sh.Nodes)
		for _, n := range sh.Nodes {
			seen[n.Fingerprint()]++
		}
	}
	if total != len(nodes) {
		t.Errorf("разложено %d нод из %d", total, len(nodes))
	}
	for fp, c := range seen {
		if c != 1 {
			t.Errorf("нода %s попала в %d шардов", fp, c)
		}
	}

	// Раскладка по остатку даёт разброс не больше единицы.
	min, max := len(shards[0].Nodes), len(shards[0].Nodes)
	for _, sh := range shards {
		if len(sh.Nodes) < min {
			min = len(sh.Nodes)
		}
		if len(sh.Nodes) > max {
			max = len(sh.Nodes)
		}
	}
	if max-min > 1 {
		t.Errorf("перекос шардов: от %d до %d", min, max)
	}
}

// Раскладка обязана быть одинаковой при одинаковом входе: иначе история
// репутации и кэш поедут между прогонами.
func TestSplitShardsDeterministic(t *testing.T) {
	nodes := testNodes(50)

	shuffled := make([]*Node, len(nodes))
	for i, n := range nodes {
		shuffled[len(nodes)-1-i] = n
	}

	a := SplitShards(nodes, 4)
	b := SplitShards(shuffled, 4)

	for i := range a {
		if len(a[i].Nodes) != len(b[i].Nodes) {
			t.Fatalf("шард %d: размеры %d и %d", i, len(a[i].Nodes), len(b[i].Nodes))
		}
		for j := range a[i].Nodes {
			if a[i].Nodes[j].Fingerprint() != b[i].Nodes[j].Fingerprint() {
				t.Fatalf("шард %d позиция %d: раскладка зависит от порядка входа", i, j)
			}
		}
	}
}

func TestSplitShardsEdgeCases(t *testing.T) {
	if got := SplitShards(nil, 4); len(got) != 4 {
		t.Errorf("пустой вход дал %d шардов", len(got))
	}
	if got := SplitShards(testNodes(3), 0); len(got) != 1 {
		t.Errorf("shards=0 дал %d шардов, ожидался 1", len(got))
	}
	// Шардов больше, чем нод: лишние остаются пустыми, но существуют.
	got := SplitShards(testNodes(2), 5)
	if len(got) != 5 {
		t.Fatalf("шардов %d", len(got))
	}
	nonEmpty := 0
	for _, sh := range got {
		if len(sh.Nodes) > 0 {
			nonEmpty++
		}
	}
	if nonEmpty != 2 {
		t.Errorf("непустых шардов %d, ожидалось 2", nonEmpty)
	}
}

func TestShardRoundTrip(t *testing.T) {
	dir := t.TempDir()
	shards := SplitShards(testNodes(20), 3)

	if err := WriteShards(dir, shards); err != nil {
		t.Fatal(err)
	}
	for i, want := range shards {
		got, err := ReadShard(filepath.Join(dir, "shard-"+strconv.Itoa(i)+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if got.Index != want.Index || got.Total != want.Total {
			t.Errorf("шард %d: Index=%d Total=%d", i, got.Index, got.Total)
		}
		if len(got.Nodes) != len(want.Nodes) {
			t.Fatalf("шард %d: нод %d, ожидалось %d", i, len(got.Nodes), len(want.Nodes))
		}
		for j := range got.Nodes {
			if got.Nodes[j].Fingerprint() != want.Nodes[j].Fingerprint() {
				t.Errorf("шард %d позиция %d: отпечаток не пережил сериализацию", i, j)
			}
			if got.Nodes[j].Raw != want.Nodes[j].Raw {
				t.Errorf("шард %d позиция %d: Raw потерян", i, j)
			}
		}
	}
}
