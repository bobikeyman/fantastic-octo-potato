package xraycfg

import (
	"bytes"
	"fmt"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	// Регистрирует все протоколы и транспорты в реестре ядра.
	// Без этого импорта core.New не найдёт ни vless, ни reality.
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/bobivpn/checker/internal/model"
)

// CoreVersion — версия встроенного ядра Xray. Пишется в отчёт прогона.
func CoreVersion() string { return core.Version() }

// Validate проверяет, что ядро принимает конфиг ноды.
//
// Сеть не используется: core.New только собирает объектный граф — никаких
// соединений, резолвов и хендшейков. Это финальный фильтр стадии 0,
// заменяющий отдельный вызов `xray run -test`.
func Validate(n *model.Node, opts Options) error {
	raw, err := FullConfig(n, opts)
	if err != nil {
		return err
	}
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("конфиг не разобран ядром: %w", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		return fmt.Errorf("ядро отвергло конфиг: %w", err)
	}
	return inst.Close()
}
