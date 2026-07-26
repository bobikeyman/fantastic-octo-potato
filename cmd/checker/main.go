// Command checker — BobiVPN Checker.
//
// Режимы:
//
//	parse    разбор и дедуп ключей из файла (офлайн, сеть не нужна)
//	version  версия сборки
//
// Сетевые режимы (collect, check, publish) появятся по мере реализации
// пайплайна — см. PLAN.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/bobivpn/checker/internal/model"
	"github.com/bobivpn/checker/internal/parse"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "parse":
		if err := cmdParse(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Println("bobi-checker", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "неизвестный режим %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `BobiVPN Checker

Использование:
  checker parse --file <путь> [--stats] [--rejected] [--out <файл.json>]
  checker version

Режим parse работает офлайн: разбирает ключи, валидирует и дедуплицирует
по отпечатку без учёта #имени.
`)
}

func cmdParse(args []string) error {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	file := fs.String("file", "", "файл со ссылками (по одной на строку)")
	showStats := fs.Bool("stats", false, "печатать разбивку по протоколам и транспортам")
	showRejected := fs.Bool("rejected", false, "печатать отбракованные строки с причиной")
	out := fs.String("out", "", "записать разобранные ноды в JSON-файл")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		fs.Usage()
		return fmt.Errorf("не указан --file")
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")

	if *showRejected {
		printRejected(lines)
	}

	nodes, stats := parse.Batch(lines)

	fmt.Printf("строк: %d | разобрано: %d | уникальных: %d | дублей: %d | отбраковано: %d\n",
		stats.Lines, stats.Parsed, stats.Unique, stats.Duplicate, stats.RejectedTotal())

	for _, r := range stats.TopReasons() {
		fmt.Printf("  отбраковка  %-24s %d\n", r.Reason, r.Count)
	}

	if *showStats {
		printBreakdown(nodes)
	}

	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(nodes); err != nil {
			return err
		}
		fmt.Printf("записано %d нод в %s\n", len(nodes), *out)
	}
	return nil
}

func printRejected(lines []string) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n, err := parse.URI(line)
		if err == nil {
			err = parse.Validate(n)
		}
		if err != nil {
			fmt.Printf("  ✗ %-24s %.110s\n", err, line)
		}
	}
}

func printBreakdown(nodes []*model.Node) {
	byProto := map[string]int{}
	bySec := map[string]int{}
	byTrans := map[string]int{}
	vision, insecure := 0, 0

	for _, n := range nodes {
		byProto[string(n.Protocol)]++
		bySec[string(n.Security)]++
		byTrans[string(n.Transport)]++
		if n.Flow != "" {
			vision++
		}
		if n.AllowInsecure {
			insecure++
		}
	}

	fmt.Println("\nпротоколы:")
	printCounts(byProto)
	fmt.Println("security:")
	printCounts(bySec)
	fmt.Println("транспорт:")
	printCounts(byTrans)
	fmt.Printf("\nxtls-vision: %d | allowInsecure: %d\n", vision, insecure)
}

// printCounts печатает по убыванию частоты — вывод должен быть детерминированным,
// иначе его нельзя сравнивать между прогонами.
func printCounts(m map[string]int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		fmt.Printf("  %-16s %d\n", k, m[k])
	}
}
