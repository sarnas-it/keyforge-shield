package nativelib

import (
	"fmt"
	"os"
	"path/filepath"
)

// Extract распаковывает встроенный core во временный каталог и возвращает
// его путь + функцию очистки. Это и есть libDir, который передаётся в
// keyforgeshield.New().
//
// hardening.so сюда НЕ встраивается и не пишется этой функцией — этот
// репозиторий открытый, платный слой в него не попадает ни в каком виде
// (см. ADR-0001). У платящего клиента в собственном (приватном) билд-шаге
// появляется свой аналог этого файла — симметричный embed_hardening_*.go,
// распаковывающий лицензионную .so в ТОТ ЖЕ самый каталог. New() в
// core/go/verifier.go уже умеет подхватывать hardening best-effort — ему
// достаточно, чтобы файл физически лежал рядом с core на момент вызова,
// никаких изменений в этом примере для этого не требуется.
func Extract() (dir string, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "keyforge-shield-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tmpDir) }

	corePath := filepath.Join(tmpDir, coreFileName)
	// 0o500: только чтение+исполнение, без записи — после распаковки файл
	// не должен быть изменяемым тем же процессом, который его создал.
	if err := os.WriteFile(corePath, coreBytes, 0o500); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("write core library: %w", err)
	}

	return tmpDir, cleanup, nil
}
