// Package keyforgeshield — эталонный Go-SDK для keyforge-shield.
//
// Open-core контракт: библиотека core обязательна и работает самостоятельно
// (честная криптографическая/строковая проверка, без анти-tamper упрочнения).
// Hardening-слой — платный, закрытый, распространяется только как отдельный
// компилированный артефакт (см. docs/adr/0001-open-core-with-paid-hardening-layer.md)
// и подгружается best-effort: если его нет, SDK продолжает работать в
// open-core режиме и явно сообщает об этом, а не притворяется, что защита есть.
package keyforgeshield

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/ebitengine/purego"
)

type verifyStringsFunc func(a, b string) int32
type hardeningProbeFunc func() int32

// Mode сообщает, в каком режиме работает SDK — для логирования и для того,
// чтобы продукт-интегратор мог честно показать пользователю, что он получил.
type Mode int

const (
	ModeOpenCore Mode = iota
	ModeHardened
)

func (m Mode) String() string {
	if m == ModeHardened {
		return "hardened (paid layer active)"
	}
	return "open-core (no hardening layer)"
}

// Verifier — загруженный core (обязательно) + опционально hardening.
type Verifier struct {
	verify  verifyStringsFunc
	probe   hardeningProbeFunc
	mode    Mode
}

func coreLibName() string {
	switch runtime.GOOS {
	case "linux":
		return "libkeyforge_core.so"
	case "darwin":
		return "libkeyforge_core.dylib"
	case "windows":
		return "keyforge_core.dll"
	default:
		panic("unsupported platform: " + runtime.GOOS)
	}
}

func hardeningLibName() string {
	switch runtime.GOOS {
	case "linux":
		return "libkeyforge_hardening_stub.so"
	case "darwin":
		return "libkeyforge_hardening_stub.dylib"
	case "windows":
		return "keyforge_hardening_stub.dll"
	default:
		panic("unsupported platform: " + runtime.GOOS)
	}
}

// New грузит core-библиотеку из libDir (обязательно) и пытается подгрузить
// hardening-слой из того же каталога (best-effort — отсутствие не ошибка).
func New(libDir string) (*Verifier, error) {
	corePath := filepath.Join(libDir, coreLibName())
	coreLib, err := purego.Dlopen(corePath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("core library is required but failed to load from %s: %w", corePath, err)
	}

	v := &Verifier{mode: ModeOpenCore}
	purego.RegisterLibFunc(&v.verify, coreLib, "verify_strings")

	hardeningPath := filepath.Join(libDir, hardeningLibName())
	hardeningLib, err := purego.Dlopen(hardeningPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		// Не ошибка: это ожидаемое состояние open-core издания.
		return v, nil
	}

	var probe hardeningProbeFunc
	purego.RegisterLibFunc(&probe, hardeningLib, "hardening_probe")
	if probe() == 1 {
		v.probe = probe
		v.mode = ModeHardened
	}

	return v, nil
}

// Mode возвращает текущий режим работы SDK.
func (v *Verifier) Mode() Mode {
	return v.mode
}

// Verify — эталонная проверка (в прототипе — сравнение строк, в проде —
// разбор и проверка подписанного токена). Hardening-слой, если активен,
// в реальной реализации будет оборачивать этот вызов своими побочными
// проверками; в прототипе он не влияет на результат.
func (v *Verifier) Verify(a, b string) bool {
	return v.verify(a, b) == 1
}
